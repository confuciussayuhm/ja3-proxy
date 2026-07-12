"""mitmproxy addon: re-originate each request through curl_cffi with a browser fingerprint.

mitmproxy terminates the TLS Burp speaks to us (using its own CA — Burp accepts it because
`enforce_upstream_trust:false` is set) and hands us the decrypted request. We short-circuit
mitmproxy's own vanilla-TLS upstream by performing the real upstream fetch with curl_cffi
(`impersonate=<profile>`), which presents a genuine browser JA3/JA4 + HTTP-2 fingerprint to
the target, then set `flow.response` from the result.
"""

from __future__ import annotations

import asyncio

from curl_cffi import requests as cffi
from mitmproxy import http

from .state import EgressRecord, ProfileStore

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


class ImpersonateUpstream:
    """Delegates the upstream leg of every proxied request to curl_cffi."""

    def __init__(self, store: ProfileStore, *, verify_upstream: bool = True) -> None:
        self._store = store
        self._verify_upstream = verify_upstream

    async def request(self, flow: http.HTTPFlow) -> None:
        # Skip requests already answered (e.g. by an earlier addon) or CONNECTs.
        if flow.response is not None:
            return

        host = flow.request.pretty_host
        profile = self._store.resolve(host)
        chain = self._store.snapshot().get("upstream_chain")

        req_headers = [
            (name, value)
            for name, value in flow.request.headers.items(multi=True)
            if name.lower() not in _STRIP_REQUEST_HEADERS
        ]

        try:
            resp = await asyncio.to_thread(
                self._fetch,
                flow.request.method,
                flow.request.url,
                req_headers,
                flow.request.raw_content or b"",
                profile,
                chain,
            )
        except Exception as exc:  # noqa: BLE001 — surface any upstream failure as a 502
            self._store.record(
                EgressRecord(host, flow.request.method, flow.request.path, profile, None, str(exc))
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

        flow.response = http.Response.make(resp.status_code, resp.content, resp_headers)
        self._store.record(
            EgressRecord(host, flow.request.method, flow.request.path, profile, resp.status_code)
        )

    def _fetch(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        profile: str,
        chain: str | None,
    ) -> cffi.Response:
        """Blocking curl_cffi call, run in a worker thread so the proxy loop stays free."""
        proxies = {"http": chain, "https": chain} if chain else None
        return cffi.request(
            method,
            url,
            headers=headers,
            data=body if body else None,
            impersonate=profile,
            allow_redirects=False,
            verify=self._verify_upstream,
            proxies=proxies,
            timeout=120,
        )
