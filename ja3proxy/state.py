"""Shared, thread-safe impersonation state.

The mitmproxy addon (running on the proxy's asyncio loop) reads this store per request;
the MCP tools (running on the uvicorn thread) mutate it. All access goes through a lock,
and every operation is non-blocking, so cross-thread sharing is safe without an event
loop handoff.
"""

from __future__ import annotations

import threading
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


@dataclass
class EgressRecord:
    """One upstream request the proxy re-originated, for audit + agent feedback."""

    host: str
    method: str
    path: str
    profile: str
    status: Optional[int]
    error: Optional[str] = None


@dataclass
class ProfileStore:
    default_profile: str = "chrome"
    upstream_chain: Optional[str] = None
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

    def set_upstream_chain(self, url: Optional[str]) -> dict:
        with self._lock:
            self.upstream_chain = url or None
            return self._snapshot_locked()

    def snapshot(self) -> dict:
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict:
        return {
            "default_profile": self.default_profile,
            "per_host": dict(self._per_host),
            "upstream_chain": self.upstream_chain,
        }

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
                "status": r.status,
                "error": r.error,
            }
            for r in reversed(items)
        ]
