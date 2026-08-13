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
python -m ja3proxy --proxy-port 8081 --mcp-port 9877 --profile chrome `
  --ignore-hosts "(.*\.)?oastify\.com"
```

`--ignore-hosts "(.*\.)?oastify\.com"` tunnels Burp Collaborator's polling straight through
rather than MITM-ing it — Collaborator pins its own cert and would otherwise log a
`Client TLS handshake failed` every poll. Drop it if you don't use Collaborator.

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
| `set_upstream_scope(scope)` | Stickiness scope: `host` (one IP per host) \| `global` (one active IP for all hosts) |
| `pin_host_upstream(host, name)` | Force a host to a specific upstream (or `direct`) |
| `unpin_host_upstream(host)` | Remove a host pin |
| `rotate_host_upstream(host)` | Give a host a fresh egress IP + clear its block list |
| `set_upstream_health(name, healthy)` | Manually bench / un-bench an upstream |
| `set_upstream_chain(url?)` | Back-compat shorthand: replace the pool with a single upstream |

**Audit**

| Tool | Purpose |
|---|---|
| `get_egress_log(limit?)` | Recent requests + the profile **and upstream** actually used, and status |

## Impersonation profiles

A profile is a [`curl_cffi`](https://github.com/lexiforest/curl_cffi) impersonation target —
the browser whose TLS/JA3/JA4 ClientHello and HTTP-2 fingerprint the proxy reproduces on the
upstream leg. Set the process default with `--profile <name>`, override it live (globally or
per host) with `set_impersonation_profile(browser, host?)`, drop a per-host override with
`clear_host_profile(host)`, and inspect the current mapping with
`get_impersonation_profile(host?)`.

The exact set depends on the installed `curl_cffi` build — call `list_profiles()` (or the
`curl-cffi list` CLI) for the authoritative list in your environment. The build shipped here
exposes 53 targets across these families:

| Family | Example values | Notes |
|---|---|---|
| Chrome (desktop) | `chrome`, `chrome110`, `chrome131`, `chrome136`, `chrome146` | Chromium TLS stack; the most common bucket |
| Chrome (Android) | `chrome_android`, `chrome99_android`, `chrome131_android` | mobile Chrome ClientHello |
| Edge | `edge`, `edge99`, `edge101` | Chromium-based Edge |
| Firefox | `firefox`, `firefox133`, `firefox144`, `firefox147` | NSS TLS stack — a distinct JA3 bucket from Chromium |
| Safari (macOS) | `safari`, `safari17_0`, `safari18_0`, `safari260` | Apple SecureTransport fingerprint |
| Safari (iOS) | `safari_ios`, `safari17_2_ios`, `safari18_4_ios`, `safari260_ios` | mobile Safari |
| Tor | `tor145` | Tor Browser's Firefox-derived fingerprint |

Choosing a profile:

- **Bare names alias the latest.** `chrome`, `edge`, `firefox`, `safari`, and `safari_ios`
  resolve to the newest build of that family in the installed `curl_cffi`. Pinning a version
  (e.g. `chrome131`) is more reproducible across `curl_cffi` upgrades.
- **Match the family to the defense, the version to the story.** Firefox vs Chromium vs Safari
  are the coarse JA3 buckets a fingerprint-based WAF keys on; the version digits move finer
  details (extension ordering, GREASE, ALPN). Pick a version consistent with the User-Agent
  Burp forwards so the UA and JA3 don't contradict each other.
- **Unknown names are rejected.** `set_impersonation_profile` validates against
  `list_profiles()` and returns the available set on a miss; `--profile` is handed to
  `curl_cffi` as-is at startup.
- If a `curl_cffi` build doesn't expose an enumerable list, `list_profiles()` falls back to a
  curated subset (`chrome`, `chrome131`, `firefox133`, `safari18_0`, `edge101`, …).

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
  --upstream-strategy round_robin `
  --ignore-hosts "(.*\.)?oastify\.com"
# or: --upstreams-file proxies.txt   (one URL per line, # comments allowed)
```

How it chooses ("intelligently"):

- **Sticky per host.** Once a target host is assigned an upstream it keeps it, so a session's
  egress IP stays stable — switching IPs mid-session is a classic anti-fraud trip.
- **Health-aware failover.** An upstream that hits a few consecutive connection failures is
  benched and auto-retried later; within a single request the proxy fails over to the next
  healthy upstream so a dead proxy never drops the request. A dead proxy fails after
  `--connect-timeout` (default 8s) instead of curl's ~21s default, so failover is snappy.
- **Degraded last resort, not a premature 502.** If every upstream is benched or blocked, the
  proxy retries the least-bad one anyway (a proxy — **never** direct) before giving up. A
  transient bench or a stale block therefore can't turn into a spurious failure while working
  egress still exists; only a request where *every* proxy genuinely fails to connect errors out.
- **No silent real-IP leak.** With a configured pool, a request where all proxies fail returns
  a `502` rather than quietly egressing from your real IP. Direct egress happens only when you
  opt in: an empty pool, an explicit `direct` pool entry, or `--allow-direct-fallback`.
- **Block-aware rotation (self-healing).** When a host returns a blocking status through one
  upstream, that upstream is blocked *for that host* and the host rotates to a different egress.
  Blocks **auto-expire** (default 120s) so the pool recovers on its own — no manual rotate
  needed. Which codes count is configurable with `--rotate-on-status` (default `403,429`); set
  it to `none` when the app returns `403`/`429` as a normal reply and you don't want those
  rotating egress. `rotate_host_upstream(host)` still forces a fresh IP immediately.
- **Assignment strategy** decides which upstream a *fresh or rotated* host gets (see
  [Assignment strategies](#assignment-strategies) below); stickiness then keeps it there.
- **Pin / direct.** `pin_host_upstream(host, name)` forces a host to one upstream; add an entry
  with url `direct` to let rotation include no-proxy egress; an empty pool = always direct. See
  the leak note above for when direct is (and isn't) used automatically.

Health/block defaults: an upstream is benched after **3** consecutive connection failures and
auto-retried after **120s**; a host **blocks** an upstream after **3** blocking responses
(`403`/`429` by default) through it, and that block auto-expires after **120s**.

### Assignment strategies

Set at startup with `--upstream-strategy <name>` or live with `set_upstream_strategy(name)`.
The strategy only picks the upstream for a host's **first** request (or its first request
after a rotation or block); stickiness then keeps that host on the chosen upstream. Selection
is always over the *currently eligible* set — healthy, not blocked for this host, and not
already tried this request.

| Strategy | Behaviour | Use when |
|---|---|---|
| `round_robin` *(default)* | Cycles through the eligible upstreams in the order they were added, so hosts spread evenly across the pool. | You want balanced, even distribution across interchangeable proxies. |
| `random` | Picks an eligible upstream uniformly at random. | You want unpredictable assignment with no ordering bias. |
| `weighted` | Random pick weighted by each upstream's `weight` (set via `add_upstream(..., weight=N)`; minimum 1). | Some proxies are faster or higher-quota and should carry proportionally more hosts. |
| `first` | Least-loaded first: the eligible upstream with the fewest lifetime requests, ties broken by add order. | You want to warm/fill proxies in order, or keep load on the earliest-listed. |

### Stickiness scope

The strategy decides *which* upstream a new assignment gets; the **scope** decides *how many*
assignments exist at once. Set at startup with `--upstream-scope <host|global>` or live with
`set_upstream_scope(scope)`.

| Scope | Behaviour | Use when |
|---|---|---|
| `host` *(default)* | Each target host is assigned its own upstream independently and sticks to it, so several egress IPs are in flight simultaneously (one per host). | You're hitting many hosts and want them spread across the pool, each with a stable per-session IP. |
| `global` | **One** active upstream carries *all* hosts. When it's benched, blocked, or you `rotate_host_upstream(...)`, every host advances to the next upstream together. | You want a single predictable egress IP at a time for the whole run, rotating the entire session to a fresh proxy on demand or on failure. |

In `global` scope `list_upstreams()` reports the current active upstream as `global_sticky`.
Switching scope clears existing sticky assignments so the new scope takes effect immediately.

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
- Headers from Burp are forwarded as-is, in order, and **nothing else is added**: the request
  is sent with `default_headers=False`, so `curl_cffi` contributes only the TLS/h2 fingerprint,
  never its impersonation profile's canned header set. (With the default on, every request
  picks up the profile's *navigation* headers — including `Sec-Fetch-User: ?1` and
  `Upgrade-Insecure-Requests: 1` on XHR/fetch calls, a combination no browser emits and that
  header-coherence checks in a WAF reject.) Hop-by-hop and length/encoding headers are recomputed.
- The URL is passed through byte-exact (`quote=False`). `curl_cffi` would otherwise re-quote it
  and rewrite payloads in flight — `%2e%2e%2f` collapses to `..%2f`, `<script>` becomes
  `%3Cscript%3E` — so the target would never receive what you sent.
- **Cert-pinning clients can't be MITM'd.** Burp Collaborator's polling (`polling.oastify.com`,
  every ~10 min) pins its own certificate and will reject the proxy's CA — you'll see repeated
  `Client TLS handshake failed … does not trust the proxy's certificate`. That's the pinned
  client refusing interception, not a problem with your target traffic. Tunnel such hosts
  straight through with `--ignore-hosts` (repeatable regex, matched against `host[:port]`):

  ```powershell
  python -m ja3proxy ... --ignore-hosts "(.*\.)?oastify\.com"
  ```

- Each re-originated request logs one line — `GET example.com/path -> 200 via up2 [chrome]` —
  so you can watch traffic flow and see the profile + upstream actually used; upstream failures
  log a warning. `get_egress_log()` has the same data structured, over MCP.
