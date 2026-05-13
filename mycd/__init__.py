"""mycd — the Mycelio reference daemon.

Listens for Mycelio frames on raw TLS-TCP (and optionally WebSocket-binary),
dispatches verbs to handlers, translates ROUTE calls to vendor backends
(HTTP / MCP / SSE), and signs response chains with the directory root key.

This is the reference implementation; alternative daemons in other
languages can conform to the same wire format.
"""

__version__ = "0.0.1"
