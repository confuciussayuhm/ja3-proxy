"""mitmproxy addon: re-originate each request through curl_cffi with a browser fingerprint.

mitmproxy terminates the TLS Burp speaks to us (using its own CA — Burp accepts it because
`enforce_upstream_trust:false` is set) and hands us the decrypted request. We short-circuit
mitmproxy's own vanilla-TLS upstream by performing the real upstream fetch with curl_cffi
(`impersonate=<profile>`), which presents a genuine browser JA3/JA4 + HTTP-2 fingerprint to
the target, then set `flow.response` from the result.

The upstream leg is routed through the UpstreamPool: an upstream proxy is chosen per host
(sticky), with connection-failure failover and block-aware rotation.
"""

from __future__ import annotations

import asyncio
import logging

from curl_cffi import requests as cffi
from mitmproxy import http

from .state import DIRECT_NAME, EgressRecord, ProfileStore, UpstreamPool

# Emits one concise line per re-originated request so the operator can see traffic flowing.
# Routes through the root logger, so mitmproxy's TermLog picks it up as the single console sink.
logger = logging.getLogger("ja3proxy")

# Headers we must not forward verbatim to the upstream client: hop-by-hop, or values
# curl_cffi will recompute. Content-Encoding/Content-Length on the RESPONSE are also
# stripped because curl_cffi returns already-decoded bytes.
_STRIP_REQUEST_HEADERS = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "content-length",
}
_STRIP_RESPONSE_HEADERS = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
}

# Default response codes treated as the target blocking this egress IP (drives block-aware
# rotation). Configurable per run — a 403/429 is often just the app's normal reply, so an
# operator can narrow or disable this with --rotate-on-status.
_DEFAULT_BLOCK_STATUS = {403, 429}

# Hard ceiling on per-request failover attempts, regardless of pool size.
_MAX_FAILOVER = 32


class ImpersonateUpstream:
    """Delegates the upstream leg of every proxied request to curl_cffi, via the pool."""

    def __init__(
        self,
        store: ProfileStore,
        pool: UpstreamPool,
        *,
        verify_upstream: bool = True,
        allow_direct_fallback: bool = False,
        block_statuses: set[int] | None = None,
        connect_timeout: float = 8.0,
        read_timeout: float = 120.0,
    ) -> None:
        self._store = store
        self._pool = pool
        self._verify_upstream = verify_upstream
        self._allow_direct_fallback = allow_direct_fallback
        self._block_statuses = _DEFAULT_BLOCK_STATUS if block_statuses is None else block_statuses
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    async def request(self, flow: http.HTTPFlow) -> None:
        # Skip requests already answered (e.g. by an earlier addon) or CONNECTs.
        if flow.response is not None:
            return

        host = flow.request.pretty_host
        profile = self._store.resolve(host)

        req_headers = [
            (name, value)
            for name, value in flow.request.headers.items(multi=True)
            if name.lower() not in _STRIP_REQUEST_HEADERS
        ]

        try:
            resp, used = await asyncio.to_thread(
                self._fetch_with_pool,
                flow.request.method,
                flow.request.url,
                host,
                req_headers,
                flow.request.raw_content or b"",
                profile,
            )
        except Exception as exc:  # noqa: BLE001 — surface any upstream failure as a 502
            self._store.record(
                EgressRecord(host, flow.request.method, flow.request.path, profile, "-", None, str(exc))
            )
            logger.warning(
                "%s %s -> upstream error [%s]: %s", flow.request.method, host, profile, exc
            )
            flow.response = http.Response.make(
                502,
                f"ja3-proxy upstream error via '{profile}': {exc}".encode(),
                {"content-type": "text/plain", "x-ja3-proxy-error": "1"},
            )
            return

        # mitmproxy's Response.make requires bytes when headers are given as tuples (the
        # tuple form, unlike a dict, preserves duplicate headers such as multiple Set-Cookie).
        resp_headers = [
            (name.encode("latin-1", "replace"), value.encode("latin-1", "replace"))
            for name, value in resp.headers.multi_items()
            if name.lower() not in _STRIP_RESPONSE_HEADERS
        ]
        resp_headers.append((b"x-ja3-proxy-profile", profile.encode("ascii", "replace")))
        resp_headers.append((b"x-ja3-proxy-upstream", used.encode("ascii", "replace")))

        flow.response = http.Response.make(resp.status_code, resp.content, resp_headers)
        self._store.record(
            EgressRecord(host, flow.request.method, flow.request.path, profile, used, resp.status_code)
        )
        logger.info(
            "%s %s%s -> %s via %s [%s]",
            flow.request.method,
            host,
            flow.request.path,
            resp.status_code,
            used,
            profile,
        )

    def _fetch_with_pool(
        self,
        method: str,
        url: str,
        host: str,
        headers: list[tuple[str, str]],
        body: bytes,
        profile: str,
    ) -> tuple[cffi.Response, str]:
        """Blocking curl_cffi call with pool selection + connection-failure failover.

        Runs in a worker thread so the proxy loop stays free. Returns (response, upstream_name).
        A blocking status (see block_statuses) is fed back as a block signal (rotates the host
        next time) but is returned as-is — only connection errors trigger same-request failover.

        Failover tries every healthy upstream first; if all are benched or host-blocked it
        retries them anyway (a proxy, never direct) before giving up, so a transient bench or a
        stale block never turns into a spurious 502. Direct egress happens only on opt-in.
        """
        tried: set[str] = set()
        last_exc: Exception | None = None
        # One attempt per upstream, plus one for the empty-pool/direct case, capped for safety.
        budget = min(_MAX_FAILOVER, self._pool.size() + 1)

        for _ in range(budget):
            # Prefer a healthy, unblocked upstream; if none remain, retry a benched/blocked
            # proxy rather than surfacing a premature failure.
            upstream = self._pool.select(host, exclude=tried)
            if upstream is None:
                upstream = self._pool.select(host, exclude=tried, allow_degraded=True)

            if upstream is None:
                # Nothing left to try. Egress direct ONLY when the operator opted in: an empty
                # pool (direct is intended), or --allow-direct-fallback. With a configured proxy
                # pool, refuse direct so the client's real IP never leaks — surface the error.
                if self._pool.has_proxy_upstreams() and not self._allow_direct_fallback:
                    raise last_exc or RuntimeError(
                        "all upstream proxies failed this request (connection errors); "
                        "refusing direct egress to avoid leaking the real IP — check/add "
                        "upstreams, or pass --allow-direct-fallback to permit direct"
                    )
                name, proxies = DIRECT_NAME, None
            else:
                name, proxies = upstream.name, upstream.proxies()

            try:
                resp = cffi.request(
                    method,
                    url,
                    headers=headers,
                    data=body if body else None,
                    impersonate=profile,
                    allow_redirects=False,
                    verify=self._verify_upstream,
                    proxies=proxies,
                    timeout=(self._connect_timeout, self._read_timeout),
                )
            except Exception as exc:  # noqa: BLE001 — connection error: bench + failover
                last_exc = exc
                self._pool.record_result(host, name, ok=False)
                tried.add(name)
                # Direct has no further fallback, so stop once it fails.
                if name == DIRECT_NAME:
                    break
                continue

            blocked = resp.status_code in self._block_statuses
            self._pool.record_result(host, name, ok=True, blocked=blocked)
            return resp, name

        raise last_exc if last_exc is not None else RuntimeError("no upstream available")
