# ja3-proxy

A TLS-terminating MITM proxy that presents a **real browser JA3/JA4 + HTTP-2 fingerprint**
to the target, with an **MCP control plane** so an AI/LLM agent (or any MCP client) can pick
the impersonation profile per host at runtime. Built for browser-first, network-layer-aware
web security testing where the agent reasons about the defense in front of the target and
picks the fingerprint to match.

## Why this exists

A plain upstream **HTTP (CONNECT)** or **SOCKS** proxy does *not* change your TLS fingerprint:
both are TCP-level relays, so Burp still performs the TLS handshake end-to-end through the
tunnel and the target sees **Burp's** JA3. The only upstream that controls the JA3 is one that
**terminates TLS and re-originates a fresh handshake** with a browser TLS stack. That's this
proxy: it terminates the connection from Burp and re-issues each request through
[`curl_cffi`](https://github.com/lexiforest/curl_cffi) (utls/curl-impersonate), which produces
a byte-accurate browser ClientHello and h2 fingerprint.

Unlike the *Bypass Bot Detection* Burp extension (which only re-orders Burp's own JVM ciphers),
this reproduces the full extension/curve/ALPN ordering a real browser sends.

## Topology

```
browser / curl_cffi / Burp Repeater
        -> Burp :8080            (capture, history, repeater, replay)
        -> ja3-proxy :8081       (re-originate with a browser JA3, MCP-controlled)
        -> target
```

Burp keeps full HTTP-layer fidelity and history; the target sees a real browser JA3.

## Install & run (Windows host)

```powershell
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m ja3proxy --proxy-port 8081 --mcp-port 9877 --profile chrome
```

Then in Burp: **Settings -> Network -> Connections -> Upstream proxy servers**, add a rule
(destination `*`) pointing at `127.0.0.1:8081`. Burp's `enforce_upstream_trust` should be
off (it is by default in the shipped config) so Burp accepts the proxy's MITM certs. The MCP
control plane is reachable by any MCP client at `http://127.0.0.1:9877/mcp` (start with
`--mcp-host 0.0.0.0` to reach it from another machine).

## MCP tools

**Impersonation**

| Tool | Purpose |
|---|---|
| `set_impersonation_profile(browser, host?)` | Set the global (or per-host) JA3/h2 profile |
| `clear_host_profile(host)` | Drop a per-host override |
| `get_impersonation_profile(host?)` | Show current state; resolve for a host |
| `list_profiles()` | curl_cffi impersonation targets available here |

**Upstream proxy pool** (see [Upstream proxy pool](#upstream-proxy-pool))

| Tool | Purpose |
|---|---|
| `add_upstream(url, name?, weight?, tags?)` | Add a proxy to the pool (`socks5://…`, `http://user:pass@…`, or `direct`) |
| `remove_upstream(name)` | Remove a proxy from the pool |
| `list_upstreams()` | Pool + per-upstream health/stats + per-host pins/sticky/blocks |
| `set_upstream_strategy(strategy)` | Assignment strategy: `round_robin` \| `random` \| `weighted` \| `first` |
| `pin_host_upstream(host, name)` | Force a host to a specific upstream (or `direct`) |
| `unpin_host_upstream(host)` | Remove a host pin |
| `rotate_host_upstream(host)` | Give a host a fresh egress IP + clear its block list |
| `set_upstream_health(name, healthy)` | Manually bench / un-bench an upstream |
| `set_upstream_chain(url?)` | Back-compat shorthand: replace the pool with a single upstream |

**Audit**

| Tool | Purpose |
|---|---|
| `get_egress_log(limit?)` | Recent requests + the profile **and upstream** actually used, and status |

## Upstream proxy pool

You can give the proxy a **pool of upstream proxies** and it will choose one per request
intelligently, rather than pinning everything to a single egress. curl (and therefore
curl_cffi) can only route through one proxy per request, so this is smart *selection* across
a pool — not literal multi-hop chaining.

Seed the pool at startup, or manage it live over MCP:

```powershell
python -m ja3proxy --proxy-port 8081 --mcp-port 9877 --profile chrome `
  --upstream socks5://5.6.7.8:1080 `
  --upstream http://user:pass@1.2.3.4:8000 `
  --upstream-strategy round_robin
# or: --upstreams-file proxies.txt   (one URL per line, # comments allowed)
```

How it chooses ("intelligently"):

- **Sticky per host.** Once a target host is assigned an upstream it keeps it, so a session's
  egress IP stays stable — switching IPs mid-session is a classic anti-fraud trip.
- **Health-aware failover.** An upstream that hits a few consecutive connection failures is
  benched and automatically retried later; within a single request the proxy fails over to the
  next healthy upstream (and finally to direct) so a dead proxy never drops the request.
- **Block-aware rotation.** When a host starts returning `403`/`429` through one upstream, that
  upstream is blocked *for that host* and the host rotates to a different egress on its next
  request. Call `rotate_host_upstream(host)` to force a fresh IP immediately.
- **Assignment strategy** for fresh/rotated hosts: `round_robin` (spread evenly, default),
  `random`, `weighted` (by `weight`), or `first` (least-loaded first).
- **Pin / direct.** `pin_host_upstream(host, name)` forces a host to one upstream; add an entry
  with url `direct` to let rotation include no-proxy egress; an empty pool = always direct.

`list_upstreams()` shows health + stats + per-host assignments; `get_egress_log()` records the
upstream actually used per request, so an agent can see what egress a target is blocking.

## Verify the fingerprint

Browse a TLS-fingerprint reflector (e.g. a ja3/ja4 echo service) through Burp and confirm the
reported JA3 matches the selected browser. Flip the profile with `set_impersonation_profile`
and confirm it changes live. `get_egress_log` shows what was actually presented.

## Notes / limitations

- The upstream fetch uses `curl_cffi` synchronously inside a worker thread, and the response
  is buffered (not streamed). Fine for pentest traffic; very large downloads are buffered in
  memory.
- `connection_strategy=lazy` is required so mitmproxy never pre-establishes (and TLS-
  fingerprints) the target connection itself before we answer from curl_cffi.
- Header order from Burp is forwarded as-is; `curl_cffi` supplies the browser's TLS/h2
  fingerprint. Hop-by-hop and length/encoding headers are recomputed.
