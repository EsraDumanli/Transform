"""Find listening TCP services with a connect scan.

Every setting is required: the scan only touches the ranges and ports you
list. It opens and closes a TCP connection, sends no payload and tries no
credentials. Only scan networks you own or are explicitly authorized to scan.

An IP:port is the weakest possible selector: anything that takes over that
address inherits it. Treat these as candidates for review, not attested
workloads.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .base import KIND_NETWORK_SERVICE, ConfigError, Workload


class Network:
    name = "network"

    def __init__(self, cfg: dict, connect=None):
        self.cidrs = cfg.get("cidrs") or []
        self.ports = cfg.get("ports") or []
        self.timeout_ms = cfg.get("timeout_ms")
        self.max_hosts = cfg.get("max_hosts")
        self.concurrency = cfg.get("concurrency")
        self._connect = connect or self._tcp_connect
        if not self.cidrs:
            raise ConfigError("network: cidrs is required")
        if not self.ports:
            raise ConfigError("network: ports is required")
        for v, n in ((self.timeout_ms, "timeout_ms"), (self.max_hosts, "max_hosts"), (self.concurrency, "concurrency")):
            if not (isinstance(v, int) and v > 0):
                raise ConfigError(f"network: {n} must be a positive integer")
        for p in self.ports:
            if not (isinstance(p, int) and 1 <= p <= 65535):
                raise ConfigError(f"network: invalid port {p!r}")
        self.hosts = expand(self.cidrs, self.max_hosts)

    def _tcp_connect(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=self.timeout_ms / 1000):
                return True
        except OSError:
            return False

    def discover(self) -> tuple[list[Workload], list[str]]:
        targets = [(h, p) for h in self.hosts for p in self.ports]
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            results = list(pool.map(lambda t: self._connect(*t), targets))
        out = []
        for (h, p), is_open in zip(targets, results):
            if is_open:
                hp = f"[{h}]:{p}" if ":" in h else f"{h}:{p}"
                out.append(Workload(
                    source="network", kind=KIND_NETWORK_SERVICE, name=hp,
                    attributes={"ip": h, "port": str(p)}, selectors=[f"net:addr:{hp}"],
                ))
        return out, []


def expand(cidrs: list[str], max_hosts: int) -> list[str]:
    """Expand CIDRs to host addresses, refusing more than ``max_hosts`` in total."""
    hosts: list[str] = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError as e:
            raise ConfigError(f"network: {c!r}: {e}") from e
        if len(hosts) + net.num_addresses > max_hosts:
            raise ConfigError(f"network: {c} would exceed max_hosts ({max_hosts})")
        hosts += [str(a) for a in (net.hosts() if net.num_addresses > 2 else net)]
    return hosts
