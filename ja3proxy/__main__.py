"""Entry point: run the impersonating MITM proxy and the MCP control plane together.

    python -m ja3proxy --proxy-port 8081 --mcp-port 9877 --profile chrome \
        --upstream http://user:pass@1.2.3.4:8000 --upstream socks5://5.6.7.8:1080 \
        --upstream-strategy round_robin

- The MITM proxy listens on 127.0.0.1:<proxy-port>. Point Burp's *upstream proxy* at it.
- The MCP control plane listens on <mcp-host>:<mcp-port>/mcp (127.0.0.1 by default). An MCP
  client (e.g. an AI/LLM agent) connects there. To reach it from another machine, start with
  --mcp-host 0.0.0.0 and connect to this host's address.
- Upstream proxies (optional) form a pool; the proxy chooses one per host (sticky), with
  health-aware failover and block-aware rotation. Manage the pool live over MCP.

Both run in one process sharing thread-safe state: mitmproxy on the main asyncio loop,
uvicorn (MCP) on a daemon thread.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import threading

import uvicorn
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from .mcp_app import build_mcp
from .state import ProfileStore, UpstreamPool
from .upstream import ImpersonateUpstream


def _start_mcp(store: ProfileStore, pool: UpstreamPool, host: str, port: int) -> None:
    app = build_mcp(store, pool).streamable_http_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="ja3-mcp", daemon=True)
    thread.start()
    print(f"[ja3-proxy] MCP control plane on http://{host}:{port}/mcp")


def _quiet_logging() -> None:
    """Tame the console noise from the two logging stacks sharing this process.

    FastMCP's constructor runs logging.basicConfig() with a RichHandler on the root logger.
    mitmproxy logs every event through the root logger too and installs its own TermLog
    handler, so without this each mitmproxy line prints twice — once rich-formatted, once
    plain. Drop the RichHandler so mitmproxy's TermLog is the single console sink, then lift
    the proxy's per-connection logger above INFO so the "client connect"/"client disconnect"
    chatter (one pair per browser connection) stops flooding the terminal. Genuine warnings
    and errors from that module still get through.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        if type(handler).__name__ == "RichHandler":
            root.removeHandler(handler)
    logging.getLogger("mitmproxy.proxy.server").setLevel(logging.WARNING)


def _build_pool(args: argparse.Namespace) -> UpstreamPool:
    pool = UpstreamPool(strategy=args.upstream_strategy)
    seeds: list[str] = list(args.upstream or [])
    if args.upstreams_file:
        with open(args.upstreams_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    seeds.append(line)
    for url in seeds:
        pool.add(url)
    if seeds:
        print(f"[ja3-proxy] upstream pool: {len(seeds)} proxies, strategy={pool.strategy}")
    else:
        print("[ja3-proxy] upstream pool: empty (direct egress) — add proxies via MCP or --upstream")
    return pool


async def _run_proxy(store: ProfileStore, pool: UpstreamPool, args: argparse.Namespace) -> None:
    opts = options.Options(listen_host=args.proxy_host, listen_port=args.proxy_port)
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)

    # connection_strategy is registered by mitmproxy's proxyserver addon, so it can only be
    # set after the master has loaded its addons. lazy: never open an upstream connection
    # before the request hook — we answer every request from curl_cffi, so mitmproxy must not
    # pre-establish (and TLS-fingerprint) the target connection itself.
    updates: dict[str, object] = {"connection_strategy": "lazy"}
    if args.ca_dir:
        updates["confdir"] = args.ca_dir
    if args.ignore_hosts:
        # Blindly tunnel these hosts instead of MITM-ing them. Needed for cert-pinning clients
        # (e.g. Burp Collaborator's polling.oastify.com) that reject the proxy's CA and would
        # otherwise spam "Client TLS handshake failed" on every poll.
        updates["ignore_hosts"] = list(args.ignore_hosts)
    master.options.update(**updates)

    master.addons.add(
        ImpersonateUpstream(
            store,
            pool,
            verify_upstream=not args.insecure,
            allow_direct_fallback=args.allow_direct_fallback,
        )
    )
    print(
        f"[ja3-proxy] MITM proxy on http://{args.proxy_host}:{args.proxy_port} "
        f"(default profile: {store.default_profile}) — set Burp's upstream proxy to this"
    )
    await master.run()


def main() -> None:
    parser = argparse.ArgumentParser(prog="ja3proxy", description=__doc__)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8081, help="Burp points its upstream here")
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=9877, help="MCP control plane port")
    parser.add_argument("--profile", default="chrome", help="default curl_cffi impersonation target")
    parser.add_argument("--ca-dir", default=None, help="mitmproxy confdir (CA storage); default ~/.mitmproxy")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify the real target's TLS cert on the upstream leg",
    )
    parser.add_argument(
        "--upstream",
        action="append",
        metavar="URL",
        help="upstream proxy to add to the pool (repeatable); http(s)://[user:pass@]host:port or socks5://host:port",
    )
    parser.add_argument(
        "--ignore-hosts",
        action="append",
        metavar="REGEX",
        help="host (regex, matched against host[:port]) to tunnel without MITM instead of "
        "intercepting; repeatable. Use for cert-pinning clients such as Burp Collaborator, "
        r'e.g. --ignore-hosts "(.*\.)?oastify\.com"',
    )
    parser.add_argument(
        "--upstreams-file",
        default=None,
        metavar="PATH",
        help="file with one upstream proxy URL per line (# comments / blank lines ignored)",
    )
    parser.add_argument(
        "--allow-direct-fallback",
        action="store_true",
        help="permit direct (no-proxy) egress when the whole pool is exhausted "
        "(unhealthy/blocked). Off by default: with a configured pool, an exhausted request "
        "fails with 502 rather than silently leaking the real IP. An empty pool always egresses direct.",
    )
    parser.add_argument(
        "--upstream-strategy",
        default="round_robin",
        choices=("round_robin", "random", "weighted", "first"),
        help="how a fresh host is assigned an upstream (stickiness is always on)",
    )
    args = parser.parse_args()

    store = ProfileStore(default_profile=args.profile)
    pool = _build_pool(args)
    _start_mcp(store, pool, args.mcp_host, args.mcp_port)
    _quiet_logging()

    try:
        asyncio.run(_run_proxy(store, pool, args))
    except KeyboardInterrupt:
        print("\n[ja3-proxy] shutting down")


if __name__ == "__main__":
    main()
