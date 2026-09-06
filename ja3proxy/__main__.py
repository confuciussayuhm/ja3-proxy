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
import os
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


# TLS teardown messages that mean nothing more than "the peer dropped the TCP connection
# without sending close_notify". Burp (and most HTTP clients) reap idle upstream connections
# this way, so mitmproxy's TLS layer logs one WARNING per closed connection — i.e. one per
# request — even though the request itself completed fine. Genuine TLS failures (handshake
# errors, alerts, cert problems) carry different text and still print.
_BENIGN_TLS_ERRORS = (
    "unexpected eof",
    "eof occurred in violation of protocol",
)


class _DropUncleanTlsEof(logging.Filter):
    """Suppress the per-connection "TLS Error: (-1, 'Unexpected EOF')" warning."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage().lower()
        if not message.startswith("tls error:"):
            return True
        return not any(benign in message for benign in _BENIGN_TLS_ERRORS)


# Winsock codes for "peer reset the connection" / "peer aborted the connection".
_PROACTOR_RESET_CODES = {10053, 10054}


class _DropProactorConnectionReset(logging.Filter):
    """Suppress the Windows proactor teardown traceback mitmproxy reports as a task error.

    On Windows, asyncio's ProactorEventLoop tears a transport down in
    _call_connection_lost(), whose `finally` block calls sock.shutdown(SHUT_RDWR). When the
    peer has *already* reset the connection — routine whenever a client (Burp, Chrome) walks
    away from an idle connection or the target drops one — that shutdown raises
    ConnectionResetError (WinError 10054) out of a callback with no owner. It lands in the
    loop's exception handler, and mitmproxy logs it as "Unhandled error in task." plus a full
    traceback. The request it belonged to has already completed; the error describes the
    socket close itself, so there is nothing to act on (CPython gh-83861).

    The match is deliberately narrow — mitmproxy's exact message, a ConnectionError carrying a
    reset/abort Winsock code, AND a traceback ending inside proactor_events._call_connection_lost.
    Any other unhandled task error, including a genuine reset raised while handling a request,
    still prints in full.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.getMessage() != "Unhandled error in task.":
            return True
        exc = record.exc_info[1] if record.exc_info else None
        if not isinstance(exc, ConnectionError):
            return True
        code = getattr(exc, "winerror", None) or exc.errno
        if code not in _PROACTOR_RESET_CODES:
            return True
        tb = exc.__traceback__
        if tb is None:
            return True
        while tb.tb_next is not None:
            tb = tb.tb_next
        code_obj = tb.tb_frame.f_code
        return not (
            code_obj.co_name == "_call_connection_lost"
            and code_obj.co_filename.replace("\\", "/").endswith("asyncio/proactor_events.py")
        )


def _quiet_logging(*, verbose_tls: bool = False) -> None:
    """Tame the console noise from the two logging stacks sharing this process.

    FastMCP's constructor runs logging.basicConfig() with a RichHandler on the root logger.
    mitmproxy logs every event through the root logger too and installs its own TermLog
    handler, so without this each mitmproxy line prints twice — once rich-formatted, once
    plain. Drop the RichHandler so mitmproxy's TermLog is the single console sink, then lift
    the proxy's per-connection logger above INFO so the "client connect"/"client disconnect"
    chatter (one pair per browser connection) stops flooding the terminal. Genuine warnings
    and errors from that module still get through.

    Unless verbose_tls is set, also drop the unclean-EOF TLS warnings the same logger emits
    once per client connection teardown (see _BENIGN_TLS_ERRORS), and always drop the Windows
    proactor connection-reset traceback (see _DropProactorConnectionReset) — both describe a
    connection closing, not a request failing.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        if type(handler).__name__ == "RichHandler":
            root.removeHandler(handler)
    proxy_logger = logging.getLogger("mitmproxy.proxy.server")
    proxy_logger.setLevel(logging.WARNING)
    if not verbose_tls:
        proxy_logger.addFilter(_DropUncleanTlsEof())
    # mitmproxy's asyncio exception handler logs through mitmproxy.master; it is installed by
    # master.run(), so filtering the record is the only hook that survives (a loop exception
    # handler set here would be replaced).
    logging.getLogger("mitmproxy.master").addFilter(_DropProactorConnectionReset())


def _resolve_verify(args: argparse.Namespace) -> bool | str:
    """Turn --insecure / --ca-bundle into the value curl_cffi's `verify=` expects.

    False disables verification, a str is a CA bundle path (CURLOPT_CAINFO), True keeps curl's
    own default trust store. The path is checked HERE rather than on first use: a typo would
    otherwise surface as a per-request 502 on the upstream leg, which reads exactly like the
    certificate failure the operator reached for --ca-bundle to fix.
    """
    if args.insecure:
        return False
    if args.ca_bundle:
        path = os.path.abspath(os.path.expanduser(args.ca_bundle))
        if not os.path.isfile(path):
            raise SystemExit(f"[ja3-proxy] --ca-bundle: no such file: {path}")
        return path
    return True


def _parse_block_statuses(spec: str) -> set[int]:
    """Parse --rotate-on-status ("403,429", or "" / "none" to disable) into a code set."""
    spec = (spec or "").strip().lower()
    if spec in ("", "none", "off"):
        return set()
    return {int(part) for part in spec.replace(" ", "").split(",") if part}


def _build_pool(args: argparse.Namespace) -> UpstreamPool:
    pool = UpstreamPool(strategy=args.upstream_strategy, scope=args.upstream_scope)
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


async def _run_proxy(
    store: ProfileStore,
    pool: UpstreamPool,
    args: argparse.Namespace,
    verify_upstream: bool | str,
) -> None:
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
            verify_upstream=verify_upstream,
            allow_direct_fallback=args.allow_direct_fallback,
            block_statuses=_parse_block_statuses(args.rotate_on_status),
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
            debug_headers=args.debug_headers,
        )
    )
    print(
        f"[ja3-proxy] MITM proxy on http://{args.proxy_host}:{args.proxy_port} "
        f"(default profile: {store.default_profile}) — set Burp's upstream proxy to this"
    )
    # Upstream TLS verification is the setting most likely to be misremembered between runs
    # (--insecure silently accepts an intercepted chain), so state it once at startup rather
    # than leaving the operator to infer it from whether requests happen to be failing.
    if verify_upstream is False:
        print("[ja3-proxy] upstream TLS verification: OFF (--insecure)")
    elif isinstance(verify_upstream, str):
        print(f"[ja3-proxy] upstream TLS verification: ON, CA bundle {verify_upstream}")
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
        "--ca-bundle",
        default=None,
        metavar="PATH",
        help="PEM bundle to verify the real target's cert against on the upstream leg (curl's "
        "CAINFO). Use it instead of --insecure when a target serves an INCOMPLETE CHAIN (it omits "
        "its intermediate — browsers hide this by fetching the intermediate via AIA, curl does "
        "not) or is signed by a private/internal CA: verification stays on, so a genuine "
        "interception is still caught. The file REPLACES the default trust store, so build it as "
        "certifi's cacert.pem plus the extra cert(s), not the extra cert(s) alone. Ignored when "
        "--insecure is given.",
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
        "--debug-headers",
        action="store_true",
        help="add x-ja3-proxy-profile / x-ja3-proxy-upstream headers to every response for "
        "troubleshooting. OFF by default — injecting them pollutes captured traffic (they show up "
        "in Burp as if the server sent them) and leaks the proxy's presence. The same info is "
        "always in the egress log (MCP get_egress_log).",
    )
    parser.add_argument(
        "--rotate-on-status",
        default="403,429",
        metavar="CODES",
        help="comma-separated HTTP status codes treated as an egress block (drives block-aware "
        "rotation); the response is still returned. Default 403,429. Use \"none\" to disable "
        "(e.g. when the app returns 403 as a normal reply and you don't want it rotating egress).",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=8.0,
        metavar="SECONDS",
        help="per-upstream TCP/proxy connect timeout (default 8). Keeps a dead proxy from "
        "stalling the request for curl's ~21s default before failing over.",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="upstream response timeout after connect (default 120).",
    )
    parser.add_argument(
        "--upstream-strategy",
        default="round_robin",
        choices=("round_robin", "random", "weighted", "first"),
        help="how a fresh host is assigned an upstream (stickiness is always on)",
    )
    parser.add_argument(
        "--upstream-scope",
        default="host",
        choices=("host", "global"),
        help="stickiness scope: 'host' (default) pins each host to its own upstream; 'global' "
        "routes ALL hosts through one active upstream and rotates them together when it is "
        "benched, blocked, or rotated. Change live over MCP with set_upstream_scope.",
    )
    parser.add_argument(
        "--verbose-tls",
        action="store_true",
        help="keep the per-connection \"TLS Error: (-1, 'Unexpected EOF')\" warnings. These are "
        "emitted once per client connection that closes without a TLS close_notify (normal for "
        "Burp and most clients reaping idle connections) and are suppressed by default; genuine "
        "handshake/cert failures always print.",
    )
    args = parser.parse_args()

    # Resolve (and validate) the upstream TLS setting before anything binds a port or starts the
    # MCP daemon thread, so a bad --ca-bundle path exits cleanly instead of half-starting the
    # process and then raising out of the proxy's event loop.
    verify_upstream = _resolve_verify(args)

    store = ProfileStore(default_profile=args.profile)
    pool = _build_pool(args)
    _start_mcp(store, pool, args.mcp_host, args.mcp_port)
    _quiet_logging(verbose_tls=args.verbose_tls)

    try:
        asyncio.run(_run_proxy(store, pool, args, verify_upstream))
    except KeyboardInterrupt:
        print("\n[ja3-proxy] shutting down")


if __name__ == "__main__":
    main()
