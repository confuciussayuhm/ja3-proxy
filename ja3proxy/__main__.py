"""Entry point: run the impersonating MITM proxy and the MCP control plane together.

    python -m ja3proxy --proxy-port 8081 --mcp-port 9877 --profile chrome

- The MITM proxy listens on 127.0.0.1:<proxy-port>. Point Burp's *upstream proxy* at it.
- The MCP control plane listens on <mcp-host>:<mcp-port>/mcp (127.0.0.1 by default). An MCP
  client (e.g. an AI/LLM agent) connects there. To reach it from another machine, start with
  --mcp-host 0.0.0.0 and connect to this host's address.

Both run in one process sharing a thread-safe ProfileStore: mitmproxy on the main asyncio
loop, uvicorn (MCP) on a daemon thread.
"""

from __future__ import annotations

import argparse
import asyncio
import threading

import uvicorn
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from .mcp_app import build_mcp
from .state import ProfileStore
from .upstream import ImpersonateUpstream


def _start_mcp(store: ProfileStore, host: str, port: int) -> None:
    app = build_mcp(store).streamable_http_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="ja3-mcp", daemon=True)
    thread.start()
    print(f"[ja3-proxy] MCP control plane on http://{host}:{port}/mcp")


async def _run_proxy(store: ProfileStore, args: argparse.Namespace) -> None:
    opts = options.Options(listen_host=args.proxy_host, listen_port=args.proxy_port)
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)

    # connection_strategy is registered by mitmproxy's proxyserver addon, so it can only be
    # set after the master has loaded its addons. lazy: never open an upstream connection
    # before the request hook — we answer every request from curl_cffi, so mitmproxy must not
    # pre-establish (and TLS-fingerprint) the target connection itself.
    updates: dict[str, object] = {"connection_strategy": "lazy"}
    if args.ca_dir:
        updates["confdir"] = args.ca_dir
    master.options.update(**updates)

    master.addons.add(ImpersonateUpstream(store, verify_upstream=not args.insecure))
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
    args = parser.parse_args()

    store = ProfileStore(default_profile=args.profile)
    _start_mcp(store, args.mcp_host, args.mcp_port)

    try:
        asyncio.run(_run_proxy(store, args))
    except KeyboardInterrupt:
        print("\n[ja3-proxy] shutting down")


if __name__ == "__main__":
    main()
