"""JA3-impersonating upstream proxy.

A TLS-terminating MITM proxy that sits upstream of Burp. Burp forwards each request
to this proxy, which re-originates the connection to the real target using a browser
TLS/JA3/JA4 + HTTP-2 fingerprint (via curl_cffi). An MCP control plane lets an AI/LLM
agent (or any MCP client) select the impersonation profile per host at runtime.

Topology:  browser / curl_cffi / Repeater -> Burp (capture) -> THIS PROXY -> target
"""

__version__ = "0.1.0"
