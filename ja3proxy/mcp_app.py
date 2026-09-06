"""MCP control plane for the JA3 proxy.

Exposes streamable-HTTP MCP tools (served at /mcp) that let an AI/LLM agent (or any MCP
client) tune the impersonation profile and the upstream proxy pool during a run. Runs on a
background uvicorn thread; tools mutate the shared ProfileStore + UpstreamPool that the
mitmproxy addon reads.
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .state import FALLBACK_PROFILES, SCOPES, STRATEGIES, ProfileStore, UpstreamPool


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


def build_mcp(store: ProfileStore, pool: UpstreamPool) -> FastMCP:
    # The MCP SDK auto-enables DNS-rebinding protection whenever the server binds to a loopback
    # address, and its default allow-list is 127.0.0.1 / localhost / [::1] only. The consumer here
    # is a Docker container reaching the host as `host.docker.internal`, so with the defaults every
    # connection is refused with "Invalid Host header" and the client sees a dead control plane -
    # while the data plane on the proxy port keeps working, which makes it look healthy. Keep the
    # protection on and admit the one hostname Docker uses.
    mcp = FastMCP(
        "ja3-proxy",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", "host.docker.internal:*"],
            allowed_origins=[
                "http://127.0.0.1:*",
                "http://localhost:*",
                "http://[::1]:*",
                "http://host.docker.internal:*",
            ],
        ),
    )

    # ---- impersonation ----------------------------------------------------------------

    @mcp.tool()
    def set_impersonation_profile(browser: str, host: Optional[str] = None) -> dict:
        """Set the browser TLS/JA3 + HTTP-2 fingerprint the proxy presents to targets.

        browser: a curl_cffi impersonation target (e.g. "chrome", "chrome131",
            "safari18_0", "firefox133"). Call list_profiles() for the valid set.
        host: if given, applies only to that target host; otherwise sets the global default.
        """
        valid = available_profiles()
        if valid and browser not in valid:
            return {"ok": False, "error": f"unknown profile '{browser}'", "available": valid}
        return {"ok": True, "state": store.set_profile(browser, host)}

    @mcp.tool()
    def clear_host_profile(host: str) -> dict:
        """Remove a per-host profile override so `host` falls back to the global default."""
        return {"ok": True, "state": store.clear_host(host)}

    @mcp.tool()
    def get_impersonation_profile(host: Optional[str] = None) -> dict:
        """Show the current profile state. If `host` is given, also resolve it for that host."""
        result: dict = {"state": store.snapshot()}
        if host:
            result["resolved_for_host"] = store.resolve(host)
        return result

    @mcp.tool()
    def list_profiles() -> dict:
        """List the impersonation targets curl_cffi supports in this environment."""
        return {"profiles": available_profiles()}

    # ---- upstream proxy pool ----------------------------------------------------------

    @mcp.tool()
    def add_upstream(url: str, name: Optional[str] = None, weight: int = 1, tags: Optional[list[str]] = None) -> dict:
        """Add an upstream proxy to the pool.

        url: an http(s)://[user:pass@]host:port or socks5://host:port URL. The special value
            "direct" (or "none") means "send with no upstream" — add it to let the pool rotate
            to direct egress.
        name: optional label (auto-assigned "upN" if omitted).
        weight: relative weight for the `weighted` strategy (default 1).
        tags: optional labels (e.g. ["residential", "us"]) for your own bookkeeping.
        """
        return {"ok": True, "state": pool.add(url, name=name, weight=weight, tags=tags)}

    @mcp.tool()
    def remove_upstream(name: str) -> dict:
        """Remove an upstream from the pool by name. Hosts using it re-pick on next request."""
        return {"ok": True, "state": pool.remove(name)}

    @mcp.tool()
    def list_upstreams() -> dict:
        """Show the pool: every upstream with health + stats, the strategy, and per-host
        pins / sticky assignments / block lists."""
        return pool.snapshot()

    @mcp.tool()
    def set_upstream_strategy(strategy: str) -> dict:
        """How a fresh (or rotated) host is assigned an upstream. Stickiness is always on —
        an assigned host keeps its upstream until it fails, gets blocked, or is rotated.

        strategy: one of round_robin (spread hosts evenly), random, weighted (by `weight`),
            or first (least-loaded first).
        """
        if strategy not in STRATEGIES:
            return {"ok": False, "error": f"unknown strategy '{strategy}'", "valid": list(STRATEGIES)}
        return {"ok": True, "state": pool.set_strategy(strategy)}

    @mcp.tool()
    def set_upstream_scope(scope: str) -> dict:
        """Set the stickiness scope for upstream selection.

        scope: "host" (default) pins each target host to its own upstream, so many egress IPs
            are in flight at once; "global" uses one active upstream for *all* hosts and rotates
            every host to the next upstream together when the active one is benched, blocked, or
            rotated. Switching scope clears current sticky assignments.
        """
        if scope not in SCOPES:
            return {"ok": False, "error": f"unknown scope '{scope}'", "valid": list(SCOPES)}
        return {"ok": True, "state": pool.set_scope(scope)}

    @mcp.tool()
    def pin_host_upstream(host: str, name: str) -> dict:
        """Force `host` to always egress through upstream `name` (use "direct" for no proxy).
        Overrides sticky selection and block-rotation for that host."""
        try:
            return {"ok": True, "state": pool.pin(host, name)}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def unpin_host_upstream(host: str) -> dict:
        """Remove a host pin so `host` returns to automatic selection."""
        return {"ok": True, "state": pool.unpin(host)}

    @mcp.tool()
    def rotate_host_upstream(host: str) -> dict:
        """Rotate `host` to a fresh upstream on its next request (get a new egress IP), and
        clear that host's block list so previously-blocked upstreams get another chance.
        Use when a target starts blocking the current egress."""
        return {"ok": True, "state": pool.rotate(host)}

    @mcp.tool()
    def set_upstream_health(name: str, healthy: bool) -> dict:
        """Manually mark an upstream healthy or benched (overrides automatic health)."""
        try:
            return {"ok": True, "state": pool.set_health(name, healthy)}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def set_upstream_chain(url: Optional[str] = None) -> dict:
        """Backward-compatible shorthand: replace the whole pool with a single upstream `url`
        (or clear the pool for direct egress when omitted). Prefer add_upstream for a real pool.
        """
        for u in list(pool.snapshot()["upstreams"]):
            pool.remove(u["name"])
        if url:
            pool.add(url, name="chain")
        return {"ok": True, "state": pool.snapshot()}

    # ---- audit ------------------------------------------------------------------------

    @mcp.tool()
    def get_egress_log(limit: int = 50) -> dict:
        """Recent upstream requests the proxy re-originated, newest first — host, method, path,
        the profile + upstream actually used, and the status (or error). Use this to confirm
        which egress + JA3 was presented and whether a host is being blocked."""
        return {"entries": store.recent(limit)}

    return mcp
