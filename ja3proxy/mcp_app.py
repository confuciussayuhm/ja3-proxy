"""MCP control plane for the JA3 proxy.

Exposes streamable-HTTP MCP tools (served at /mcp, matching the burp-mcp convention) that
let an agent tune the impersonation profile during a run. Runs on a background uvicorn
thread; tools mutate the shared ProfileStore that the mitmproxy addon reads.
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

from .state import FALLBACK_PROFILES, ProfileStore


def available_profiles() -> list[str]:
    """The curl_cffi impersonation targets for the installed version, best-effort.

    Falls back to a curated list if the installed curl_cffi doesn't expose one in a way
    we recognise. The authoritative source is the `curl-cffi list` CLI.
    """
    try:
        from curl_cffi.requests.impersonate import BrowserTypeLiteral  # type: ignore

        args = getattr(BrowserTypeLiteral, "__args__", None)
        if args:
            return sorted({str(a) for a in args})
    except Exception:  # noqa: BLE001
        pass

    try:
        from curl_cffi.requests import BrowserType  # type: ignore

        members = [m.value for m in BrowserType]  # type: ignore[attr-defined]
        if members:
            return sorted({str(m) for m in members})
    except Exception:  # noqa: BLE001
        pass

    return list(FALLBACK_PROFILES)


def build_mcp(store: ProfileStore) -> FastMCP:
    mcp = FastMCP("ja3-proxy")

    @mcp.tool()
    def set_impersonation_profile(browser: str, host: Optional[str] = None) -> dict:
        """Set the browser TLS/JA3 + HTTP-2 fingerprint the proxy presents to targets.

        browser: a curl_cffi impersonation target (e.g. "chrome", "chrome131",
            "safari18_0", "firefox133"). Call list_profiles() for the valid set.
        host: if given, applies only to that target host (e.g. "www.example.com");
            otherwise sets the global default used for all hosts without an override.
        Returns the new profile state.
        """
        valid = available_profiles()
        if valid and browser not in valid:
            return {
                "ok": False,
                "error": f"unknown profile '{browser}'",
                "available": valid,
            }
        state = store.set_profile(browser, host)
        return {"ok": True, "state": state}

    @mcp.tool()
    def clear_host_profile(host: str) -> dict:
        """Remove a per-host override so `host` falls back to the global default profile."""
        return {"ok": True, "state": store.clear_host(host)}

    @mcp.tool()
    def get_impersonation_profile(host: Optional[str] = None) -> dict:
        """Show the current profile state. If `host` is given, also resolve it for that host."""
        result = {"state": store.snapshot()}
        if host:
            result["resolved_for_host"] = store.resolve(host)
        return result

    @mcp.tool()
    def list_profiles() -> dict:
        """List the impersonation targets curl_cffi supports in this environment."""
        return {"profiles": available_profiles()}

    @mcp.tool()
    def set_upstream_chain(url: Optional[str] = None) -> dict:
        """Chain the proxy through a further upstream (e.g. an IP-rotating proxy).

        url: an http(s) proxy URL to route target traffic through after impersonation,
            or null/empty to send directly. Impersonation still applies either way.
        """
        return {"ok": True, "state": store.set_upstream_chain(url)}

    @mcp.tool()
    def get_egress_log(limit: int = 50) -> dict:
        """Recent upstream requests the proxy re-originated, newest first.

        Each entry records the host, method, path, the profile actually presented, and the
        upstream status (or error). Use this to confirm the intended JA3 was used.
        """
        return {"entries": store.recent(limit)}

    return mcp
