"""Shared, thread-safe proxy state: impersonation profiles + an upstream proxy pool.

The mitmproxy addon (running on the proxy's asyncio loop) reads this state per request;
the MCP tools (running on the uvicorn thread) mutate it. All access goes through a lock,
and every operation is non-blocking, so cross-thread sharing is safe without an event
loop handoff.
"""

from __future__ import annotations

import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

# Curated fallback list of curl_cffi impersonation targets. The authoritative list is
# whatever `curl-cffi list` prints for the installed version; list_profiles() prefers
# that and falls back to this.
FALLBACK_PROFILES: tuple[str, ...] = (
    "chrome",
    "chrome99",
    "chrome110",
    "chrome116",
    "chrome119",
    "chrome120",
    "chrome123",
    "chrome124",
    "chrome131",
    "chrome133a",
    "edge99",
    "edge101",
    "safari15_5",
    "safari17_0",
    "safari18_0",
    "safari17_2_ios",
    "safari18_0_ios",
    "firefox133",
)

# URL values that mean "send directly, no upstream proxy".
_DIRECT_SENTINELS = {"", "direct", "none"}
DIRECT_NAME = "direct"

# Selection strategies used to assign a *fresh* host to an upstream (stickiness is always
# on, so an assigned host keeps its upstream until the upstream fails, gets blocked, or is
# rotated).
STRATEGIES = ("round_robin", "random", "weighted", "first")


@dataclass
class EgressRecord:
    """One upstream request the proxy re-originated, for audit + agent feedback."""

    host: str
    method: str
    path: str
    profile: str
    upstream: str
    status: Optional[int]
    error: Optional[str] = None


@dataclass
class ProfileStore:
    default_profile: str = "chrome"
    _per_host: dict[str, str] = field(default_factory=dict)
    _log: deque[EgressRecord] = field(default_factory=lambda: deque(maxlen=1000))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def resolve(self, host: str) -> str:
        """The impersonation profile to use for `host` (per-host override, else default)."""
        with self._lock:
            return self._per_host.get(host.lower(), self.default_profile)

    def set_profile(self, browser: str, host: Optional[str] = None) -> dict:
        with self._lock:
            if host:
                self._per_host[host.lower()] = browser
            else:
                self.default_profile = browser
            return self._snapshot_locked()

    def clear_host(self, host: str) -> dict:
        with self._lock:
            self._per_host.pop(host.lower(), None)
            return self._snapshot_locked()

    def snapshot(self) -> dict:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict:
        return {"default_profile": self.default_profile, "per_host": dict(self._per_host)}

    def record(self, entry: EgressRecord) -> None:
        with self._lock:
            self._log.append(entry)

    def recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            items = list(self._log)[-limit:]
        return [
            {
                "host": r.host,
                "method": r.method,
                "path": r.path,
                "profile": r.profile,
                "upstream": r.upstream,
                "status": r.status,
                "error": r.error,
            }
            for r in reversed(items)
        ]


@dataclass
class Upstream:
    """One upstream proxy in the pool. `url` is an http(s)://... or socks5://... URL, or a
    direct sentinel ("direct"/"none"/"") meaning egress with no upstream."""

    name: str
    url: str
    weight: int = 1
    tags: list[str] = field(default_factory=list)
    # Health, updated by record_result.
    consecutive_failures: int = 0
    unhealthy_until: Optional[float] = None  # monotonic deadline; None = healthy
    # Lifetime counters.
    total_requests: int = 0
    total_failures: int = 0
    total_blocks: int = 0

    def is_direct(self) -> bool:
        return self.url.strip().lower() in _DIRECT_SENTINELS

    def proxies(self) -> Optional[dict]:
        """curl_cffi `proxies=` dict, or None for direct egress."""
        if self.is_direct():
            return None
        return {"http": self.url, "https": self.url}


class UpstreamPool:
    """A pool of upstream proxies with intelligent per-request selection.

    Intelligence:
      - Sticky per host: once a target host is assigned an upstream it keeps it, so a
        session's egress IP stays stable (switching IPs mid-session trips anti-fraud).
      - Health-aware: an upstream that hits `failure_threshold` consecutive connection
        failures is benched for `recovery_seconds`, then automatically re-tried.
      - Block-aware: when a host returns `block_threshold` blocking responses (403/429)
        through one upstream, that upstream is blocked *for that host* and the host is
        rotated to a different one on its next request.
      - Strategy: how a fresh (or rotated) host is assigned — round_robin | random |
        weighted | first.
    A per-request failover loop (in the addon) also asks for the next candidate, excluding
    ones already tried this request.
    """

    def __init__(
        self,
        strategy: str = "round_robin",
        *,
        failure_threshold: int = 3,
        recovery_seconds: float = 120.0,
        block_threshold: int = 3,
    ) -> None:
        self._lock = threading.Lock()
        self._upstreams: dict[str, Upstream] = {}
        self._order: list[str] = []  # insertion order, for round_robin
        self._host_pinned: dict[str, str] = {}
        self._host_sticky: dict[str, str] = {}
        self._host_blocked: dict[str, set[str]] = {}
        self._host_block_counts: dict[tuple[str, str], int] = {}
        self._rr_index = 0
        self._failure_threshold = failure_threshold
        self._recovery_seconds = recovery_seconds
        self._block_threshold = block_threshold
        self.strategy = strategy if strategy in STRATEGIES else "round_robin"

    # ---- pool management -------------------------------------------------------------

    def add(self, url: str, name: Optional[str] = None, weight: int = 1, tags: Optional[list[str]] = None) -> dict:
        with self._lock:
            resolved = name or self._auto_name_locked(url)
            self._upstreams[resolved] = Upstream(name=resolved, url=url, weight=max(1, weight), tags=tags or [])
            if resolved not in self._order:
                self._order.append(resolved)
            return self._snapshot_locked()

    def remove(self, name: str) -> dict:
        with self._lock:
            self._upstreams.pop(name, None)
            if name in self._order:
                self._order.remove(name)
            # Drop any host assignments referencing it so those hosts re-pick.
            for h, n in list(self._host_sticky.items()):
                if n == name:
                    self._host_sticky.pop(h, None)
            for h, n in list(self._host_pinned.items()):
                if n == name:
                    self._host_pinned.pop(h, None)
            return self._snapshot_locked()

    def set_strategy(self, strategy: str) -> dict:
        with self._lock:
            if strategy not in STRATEGIES:
                raise ValueError(f"unknown strategy '{strategy}' (use {', '.join(STRATEGIES)})")
            self.strategy = strategy
            return self._snapshot_locked()

    def pin(self, host: str, name: str) -> dict:
        with self._lock:
            if name not in self._upstreams and name != DIRECT_NAME:
                raise ValueError(f"no upstream named '{name}'")
            self._host_pinned[host.lower()] = name
            return self._snapshot_locked()

    def unpin(self, host: str) -> dict:
        with self._lock:
            self._host_pinned.pop(host.lower(), None)
            return self._snapshot_locked()

    def rotate(self, host: str) -> dict:
        """Force `host` to pick a fresh upstream next request; also clears its block list
        so previously-blocked upstreams get another chance."""
        h = host.lower()
        with self._lock:
            self._host_sticky.pop(h, None)
            self._host_blocked.pop(h, None)
            for key in [k for k in self._host_block_counts if k[0] == h]:
                self._host_block_counts.pop(key, None)
            return self._snapshot_locked()

    def set_health(self, name: str, healthy: bool) -> dict:
        with self._lock:
            u = self._upstreams.get(name)
            if not u:
                raise ValueError(f"no upstream named '{name}'")
            if healthy:
                u.unhealthy_until = None
                u.consecutive_failures = 0
            else:
                u.unhealthy_until = time.monotonic() + self._recovery_seconds
            return self._snapshot_locked()

    # ---- selection -------------------------------------------------------------------

    def select(self, host: str, exclude: Optional[set[str]] = None) -> Optional[Upstream]:
        """Pick the upstream for `host`. Returns None to mean direct egress (empty pool, or
        everything unhealthy/blocked/excluded). `exclude` skips names already tried this
        request (for the addon's failover loop)."""
        exclude = exclude or set()
        h = host.lower()
        now = time.monotonic()
        with self._lock:
            self._recover_locked(now)
            blocked = self._host_blocked.get(h, set())

            def available(u: Upstream) -> bool:
                return u.name not in exclude and u.name not in blocked and u.unhealthy_until is None

            pinned = self._host_pinned.get(h)
            if pinned:
                if pinned == DIRECT_NAME and DIRECT_NAME not in exclude:
                    return None
                u = self._upstreams.get(pinned)
                if u and available(u):
                    return u

            sticky = self._host_sticky.get(h)
            if sticky:
                u = self._upstreams.get(sticky)
                if u and available(u):
                    return u

            candidates = [u for u in self._upstreams.values() if available(u)]
            if not candidates:
                return None  # direct fallback

            chosen = self._pick_locked(candidates)
            self._host_sticky[h] = chosen.name
            return chosen

    def _pick_locked(self, candidates: list[Upstream]) -> Upstream:
        if self.strategy == "random":
            return random.choice(candidates)
        if self.strategy == "weighted":
            return random.choices(candidates, weights=[max(1, u.weight) for u in candidates], k=1)[0]
        if self.strategy == "first":
            # Least-loaded-first: fewest lifetime requests, then insertion order.
            return min(candidates, key=lambda u: (u.total_requests, self._order.index(u.name)))
        # round_robin over the current candidate set, in insertion order.
        ordered = sorted(candidates, key=lambda u: self._order.index(u.name))
        chosen = ordered[self._rr_index % len(ordered)]
        self._rr_index += 1
        return chosen

    # ---- feedback --------------------------------------------------------------------

    def record_result(self, host: str, name: str, *, ok: bool, blocked: bool = False) -> None:
        h = host.lower()
        with self._lock:
            u = self._upstreams.get(name)
            if u is not None:
                u.total_requests += 1
                if ok:
                    u.consecutive_failures = 0
                else:
                    u.total_failures += 1
                    u.consecutive_failures += 1
                    if u.consecutive_failures >= self._failure_threshold:
                        u.unhealthy_until = time.monotonic() + self._recovery_seconds
                        if self._host_sticky.get(h) == name:
                            self._host_sticky.pop(h, None)
            if blocked and name != DIRECT_NAME:
                if u is not None:
                    u.total_blocks += 1
                key = (h, name)
                self._host_block_counts[key] = self._host_block_counts.get(key, 0) + 1
                if self._host_block_counts[key] >= self._block_threshold:
                    self._host_blocked.setdefault(h, set()).add(name)
                    if self._host_sticky.get(h) == name:
                        self._host_sticky.pop(h, None)

    # ---- introspection ---------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict:
        now = time.monotonic()
        return {
            "strategy": self.strategy,
            "upstreams": [
                {
                    "name": u.name,
                    "url": u.url,
                    "weight": u.weight,
                    "tags": list(u.tags),
                    "healthy": u.unhealthy_until is None,
                    "benched_for_s": round(u.unhealthy_until - now, 1) if u.unhealthy_until else 0,
                    "requests": u.total_requests,
                    "failures": u.total_failures,
                    "blocks": u.total_blocks,
                }
                for u in self._upstreams.values()
            ],
            "host_pins": dict(self._host_pinned),
            "host_sticky": dict(self._host_sticky),
            "host_blocked": {h: sorted(s) for h, s in self._host_blocked.items() if s},
        }

    def _recover_locked(self, now: float) -> None:
        for u in self._upstreams.values():
            if u.unhealthy_until is not None and now >= u.unhealthy_until:
                u.unhealthy_until = None
                u.consecutive_failures = 0

    def _auto_name_locked(self, url: str) -> str:
        i = 1
        while f"up{i}" in self._upstreams:
            i += 1
        return f"up{i}"
