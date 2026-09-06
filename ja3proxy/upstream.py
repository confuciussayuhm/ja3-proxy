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

import logging

from curl_cffi import requests as cffi
from curl_cffi.requests import AsyncSession
from curl_cffi.requests.exceptions import SSLError
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

# How many upstreams may return a TLS-trust failure before we stop and blame the target.
# One is not enough: a single TLS-intercepting upstream in the pool would look identical to a
# genuinely untrusted target. Two independent upstreams agreeing settles it — see the handler in
# `_fetch_with_pool`.
_MAX_TLS_VERDICTS = 2

# Appended to the error surfaced for a TLS-trust failure. curl verifies against a roots-only
# bundle and, unlike a browser, never chases the AuthorityInformationAccess URL to fetch a missing
# intermediate — so a server that omits its intermediate works in Chrome and Burp but fails here
# with "unable to get local issuer certificate". That asymmetry is confusing enough in the middle
# of a test that the remedy belongs in the error itself rather than in the README.
_TLS_TRUST_HINT = (
    "the target's certificate chain did not verify on the upstream leg. Most often the server "
    "omits its intermediate certificate — browsers hide this by fetching it via AIA, curl does "
    "not — or it is signed by a private/internal CA. Pass --ca-bundle <pem> (certifi's cacert.pem "
    "plus the missing intermediate/root) to keep verification on, or --insecure to skip it"
)


class ImpersonateUpstream:
    """Delegates the upstream leg of every proxied request to curl_cffi, via the pool."""

    def __init__(
        self,
        store: ProfileStore,
        pool: UpstreamPool,
        *,
        # True verifies against curl's default trust store, False disables verification, and a
        # str is a path to a PEM bundle used instead (curl_cffi maps it onto CURLOPT_CAINFO).
        verify_upstream: bool | str = True,
        allow_direct_fallback: bool = False,
        block_statuses: set[int] | None = None,
        connect_timeout: float = 8.0,
        read_timeout: float = 120.0,
        debug_headers: bool = False,
    ) -> None:
        self._store = store
        self._pool = pool
        self._verify_upstream = verify_upstream
        self._allow_direct_fallback = allow_direct_fallback
        self._block_statuses = _DEFAULT_BLOCK_STATUS if block_statuses is None else block_statuses
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        # OFF by default: the x-ja3-proxy-profile / -upstream response headers are debug telemetry,
        # and injecting them into every response POLLUTES the captured traffic — they appear in Burp
        # history as if the server sent them, can skew response-header-based analysis, and leak the
        # proxy's presence to the client. The same profile/upstream verdict is always recorded in the
        # egress log (queryable via the MCP), so nothing is lost by keeping them off the wire.
        self._debug_headers = debug_headers
        # Cookie isolation (CRITICAL): a FRESH curl_cffi AsyncSession is created PER REQUEST (in
        # `request()`), never shared. A shared Session keeps a domain-scoped cookie jar, so the first
        # login cookie seen for a host (e.g. patient_a on www.doctolib.fr) gets silently re-attached to
        # every later request to that host — poisoning multi-principal / IDOR / authz testing (a
        # cookie-less request wrongly returns the banked user's data). The proxy must stay transparent:
        # only the client's own forwarded Cookie header may reach the target. Per-request sessions also
        # avoid a shared mutable jar racing across the concurrent requests the proxy drives. Each session
        # still performs async I/O (no thread-pool ceiling — the point of dropping asyncio.to_thread).

    async def done(self) -> None:
        """Sessions are per-request (see `request()`), so there is nothing global to tear down."""
        return

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

        # Per-request curl_cffi session: a fresh, EMPTY cookie jar for THIS request only (see the
        # cookie-isolation note in __init__). The client's own Cookie header rides in `req_headers`;
        # nothing else is attached, so the proxy stays transparent to sessions. The session stays open
        # across the response-build below so `resp.content` is materialised before it closes.
        async with AsyncSession() as session:
            try:
                resp, used = await self._fetch_with_pool(
                    session,
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
            # Only tag the response with the profile/upstream when explicitly debugging — see __init__.
            if self._debug_headers:
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

    async def _fetch_with_pool(
        self,
        session: AsyncSession,
        method: str,
        url: str,
        host: str,
        headers: list[tuple[str, str]],
        body: bytes,
        profile: str,
    ) -> tuple[cffi.Response, str]:
        """Async curl_cffi call with pool selection + connection-failure failover.

        Uses the caller's PER-REQUEST session (see `request()`), so upstream fetches run concurrently on
        the proxy loop (no thread-pool ceiling) AND carry no cross-request cookie state. Returns
        (response, upstream_name).
        A blocking status (see block_statuses) is fed back as a block signal (rotates the host
        next time) but is returned as-is — only connection errors trigger same-request failover.

        Failover tries every healthy upstream first; if all are benched or host-blocked it
        retries them anyway (a proxy, never direct) before giving up, so a transient bench or a
        stale block never turns into a spurious 502. Direct egress happens only on opt-in.
        """
        tried: set[str] = set()
        last_exc: Exception | None = None
        # TLS-trust failures are tracked apart from connection failures: they neither bench an
        # upstream nor consume the full pool, and they are the more actionable thing to report
        # when a request fails both ways (see the two `except` arms below).
        tls_exc: Exception | None = None
        tls_verdicts = 0
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
                    # A TLS verdict still outranks the generic exhaustion message: the pool can run
                    # out after a single certificate failure (one upstream ruled out, the rest
                    # unreachable), and "all upstreams failed (connection errors)" would then send
                    # the operator hunting a proxy problem that isn't there.
                    if tls_exc is not None:
                        raise RuntimeError(f"{tls_exc} — {_TLS_TRUST_HINT}") from tls_exc
                    raise last_exc or RuntimeError(
                        "all upstream proxies failed this request (connection errors); "
                        "refusing direct egress to avoid leaking the real IP — check/add "
                        "upstreams, or pass --allow-direct-fallback to permit direct"
                    )
                name, proxies = DIRECT_NAME, None
                tls_hop = False
            else:
                name, proxies = upstream.name, upstream.proxies()
                # An https:// hop presents a certificate of its own, so a TLS failure through it
                # is not unambiguously the target's fault (see Upstream.is_tls_proxy).
                tls_hop = upstream.is_tls_proxy()

            try:
                resp = await session.request(
                    method,
                    url,
                    headers=headers,
                    data=body if body else None,
                    impersonate=profile,
                    allow_redirects=False,
                    verify=self._verify_upstream,
                    proxies=proxies,
                    timeout=(self._connect_timeout, self._read_timeout),
                    # Send ONLY the client's own headers. curl_cffi otherwise merges the
                    # impersonation profile's canned *navigation* header set underneath ours, so
                    # every request the client makes picks up headers it never sent — most
                    # damagingly "Sec-Fetch-User: ?1" and "Upgrade-Insecure-Requests: 1" on an
                    # XHR/fetch call. That combination is impossible per the Fetch spec
                    # (Sec-Fetch-User is only emitted for user-activated navigations, where
                    # Sec-Fetch-Mode is "navigate"), and header-coherence checks in a WAF or bot
                    # -detection layer reject it — typically with a 400 that looks like the app
                    # rejecting the request. It also breaks the proxy's transparency contract:
                    # what the target sees must be what the client actually sent.
                    # The TLS (JA3/JA4) and HTTP-2 (Akamai) fingerprints come from curl-impersonate's
                    # socket- and frame-level options, NOT from these headers, so the impersonation
                    # this proxy exists to provide is unaffected.
                    default_headers=False,
                    # Byte-exact URL pass-through. curl_cffi's default runs the URL through
                    # requests-style requote_uri(), which rewrites test payloads in flight:
                    # "%2e%2e%2f" collapses to "..%2f" and "<script>" becomes "%3Cscript%3E",
                    # so the target never receives the payload the operator sent and the finding
                    # is silently lost. A MITM proxy must not normalise the URI.
                    quote=False,
                )
            except SSLError as exc:  # curl 60/35/51…: a verdict about the TARGET, not this hop
                # A TLS-trust failure says the target's certificate was unacceptable. That is not
                # evidence this upstream is unhealthy, so it must NOT count towards the upstream's
                # failure budget: benching a perfectly good proxy because one host serves a broken
                # chain would poison the pool for every OTHER host that proxy serves — and with
                # `unhealthy_until` being a property of the upstream rather than of the (host,
                # upstream) pair, a handful of requests to one misconfigured host can bench the
                # whole pool. The failure is also deterministic: the same chain fails identically
                # through every upstream, so walking the remaining pool only multiplies the latency
                # before the client sees the same error anyway.
                #
                # We still try a SECOND upstream, because a lone TLS-intercepting proxy in the pool
                # is indistinguishable from an untrusted target on one sample. Two independent
                # upstreams returning the same verdict settle it, and we fail fast.
                #
                # The one exception is an https:// upstream, which has a certificate of its own:
                # there a TLS failure may genuinely be the hop's, so it keeps the ordinary
                # bench-and-failover treatment rather than being blamed on the target.
                if tls_hop:
                    last_exc = exc
                    self._pool.record_result(host, name, ok=False)
                    tried.add(name)
                    continue
                tls_exc = exc
                tls_verdicts += 1
                tried.add(name)
                if tls_verdicts >= _MAX_TLS_VERDICTS or name == DIRECT_NAME:
                    break
                continue
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

        # A TLS-trust verdict outranks a connection error when both happened: the unreachable
        # upstreams are a pool-hygiene problem the operator may already know about, whereas the
        # certificate failure is the one that needs a flag change, and reporting whichever error
        # merely came last would hide it behind an unrelated timeout.
        if tls_exc is not None:
            raise RuntimeError(f"{tls_exc} — {_TLS_TRUST_HINT}") from tls_exc
        raise last_exc if last_exc is not None else RuntimeError("no upstream available")
