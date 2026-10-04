"""Anti-abuse limits for the public mycd listener (myc://…:4242).

The daemon is a public, anonymous endpoint, so it enforces its own limits
instead of relying on a proxy in front of it:

* concurrent connections per client IP, and in total;
* frame rate per client IP (token bucket shared by all of its connections);
* FETCH rate per client IP (FETCH makes outbound requests on the caller's
  behalf, so it gets a tighter budget than PING/DISCOVER);
* idle timeout between reads, and a maximum session length;
* maximum frame payload, checked from the header before the body is buffered.

Peers in ``MYCD_TRUSTED_PEERS`` (default loopback + RFC1918, i.e. the HTTP
shim on the docker network, which rate-limits its own clients) skip the
per-IP limits but still count toward the global connection cap. Docker's
published port preserves the real source address (iptables DNAT), so public
clients never show up as private addresses.

Everything is configurable via env (see ``AbuseLimits.from_env``).
"""
from __future__ import annotations

import ipaddress
import os
import time
from collections import deque
from dataclasses import dataclass


def _env(name: str, default, cast=int):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return cast(raw)
    except ValueError:
        return default


@dataclass
class AbuseLimits:
    max_conns_per_ip: int = 8
    max_conns_total: int = 512
    frames_per_sec: float = 5.0  # sustained, per IP
    frame_burst: int = 40  # bucket size, per IP
    fetch_per_min: int = 20  # per IP
    idle_timeout: float = 60.0  # seconds without a byte from the client
    session_max: float = 1800.0  # absolute cap on one connection
    max_frame: int = 256 * 1024  # payload bytes
    trusted: tuple = ()

    @classmethod
    def from_env(cls) -> "AbuseLimits":
        trusted_raw = os.environ.get(
            "MYCD_TRUSTED_PEERS",
            "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        )
        return cls(
            max_conns_per_ip=_env("MYCD_MAX_CONNS_PER_IP", cls.max_conns_per_ip),
            max_conns_total=_env("MYCD_MAX_CONNS_TOTAL", cls.max_conns_total),
            frames_per_sec=_env("MYCD_FRAMES_PER_SEC", cls.frames_per_sec, float),
            frame_burst=_env("MYCD_FRAME_BURST", cls.frame_burst),
            fetch_per_min=_env("MYCD_FETCH_PER_MIN", cls.fetch_per_min),
            idle_timeout=_env("MYCD_IDLE_TIMEOUT", cls.idle_timeout, float),
            session_max=_env("MYCD_SESSION_MAX", cls.session_max, float),
            max_frame=_env("MYCD_MAX_FRAME", cls.max_frame),
            trusted=tuple(
                ipaddress.ip_network(c.strip(), strict=False)
                for c in trusted_raw.split(",")
                if c.strip()
            ),
        )


class AbuseGuard:
    MAX_KEYS = 50_000

    def __init__(self, limits: AbuseLimits | None = None) -> None:
        self.limits = limits or AbuseLimits()
        self._conns: dict[str, int] = {}
        self._total = 0
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, ts)
        self._fetches: dict[str, deque] = {}
        self._last_sweep = 0.0

    def is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.limits.trusted)

    # -- connections -------------------------------------------------------

    def open(self, ip: str) -> str | None:
        """Register a connection. Returns a rejection reason, or None if OK."""
        if self._total >= self.limits.max_conns_total:
            return "server busy: too many connections"
        if not self.is_trusted(ip) and self._conns.get(ip, 0) >= self.limits.max_conns_per_ip:
            return f"too many concurrent connections from your address (max {self.limits.max_conns_per_ip})"
        self._conns[ip] = self._conns.get(ip, 0) + 1
        self._total += 1
        return None

    def close(self, ip: str) -> None:
        n = self._conns.get(ip, 0) - 1
        if n <= 0:
            self._conns.pop(ip, None)
        else:
            self._conns[ip] = n
        self._total = max(0, self._total - 1)

    # -- rates -------------------------------------------------------------

    def allow_frame(self, ip: str, now: float | None = None) -> bool:
        if self.is_trusted(ip):
            return True
        now = time.monotonic() if now is None else now
        self._sweep(now)
        tokens, ts = self._buckets.get(ip, (float(self.limits.frame_burst), now))
        tokens = min(self.limits.frame_burst, tokens + (now - ts) * self.limits.frames_per_sec)
        if tokens < 1:
            self._buckets[ip] = (tokens, now)
            return False
        self._buckets[ip] = (tokens - 1, now)
        return True

    def allow_fetch(self, ip: str, now: float | None = None) -> int:
        """0 if allowed, else seconds until the next FETCH is allowed."""
        if self.is_trusted(ip):
            return 0
        now = time.monotonic() if now is None else now
        q = self._fetches.setdefault(ip, deque())
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= self.limits.fetch_per_min:
            return max(1, int(q[0] + 60 - now) + 1)
        q.append(now)
        return 0

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < 60 and len(self._buckets) < self.MAX_KEYS:
            return
        self._last_sweep = now
        full = self.limits.frame_burst / max(self.limits.frames_per_sec, 0.001)
        for ip in [ip for ip, (_, ts) in self._buckets.items() if now - ts > full]:
            del self._buckets[ip]
        for ip in [ip for ip, q in self._fetches.items() if not q or q[-1] <= now - 60]:
            del self._fetches[ip]
        if len(self._buckets) >= self.MAX_KEYS:
            self._buckets.clear()
