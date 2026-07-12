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

| Tool | Purpose |
|---|---|
| `set_impersonation_profile(browser, host?)` | Set the global (or per-host) JA3/h2 profile |
| `clear_host_profile(host)` | Drop a per-host override |
| `get_impersonation_profile(host?)` | Show current state; resolve for a host |
| `list_profiles()` | curl_cffi impersonation targets available here |
| `set_upstream_chain(url?)` | Chain through a further upstream (IP rotation) |
| `get_egress_log(limit?)` | Recent re-originated requests + the JA3 actually presented |

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
