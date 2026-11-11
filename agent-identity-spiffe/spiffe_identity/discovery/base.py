"""Shared types for discovery sources.

Each source returns facts it observed directly. A source never fills a gap
with a guess: if it cannot read something (no permission, unsupported OS,
unreachable API) it reports that as an error or a warning.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Protocol

KIND_AI_AGENT = "ai-agent"
KIND_MCP_SERVER = "mcp-server"
KIND_K8S_POD = "k8s-pod"
KIND_PROCESS = "process"
KIND_CONTAINER = "container"
KIND_NETWORK_SERVICE = "network-service"


class ConfigError(ValueError):
    """A discovery source is missing a required setting."""


@dataclass
class Workload:
    source: str                       # discoverer name, e.g. "kubernetes"
    kind: str                         # one of the KIND_* constants
    name: str                         # human-readable name, as observed
    attributes: dict[str, str] = field(default_factory=dict)  # raw observed facts
    # Stable facts a registration entry binds to, "type:key:value",
    # e.g. "k8s:ns:payments", "docker:image_id:sha256:...".
    selectors: list[str] = field(default_factory=list)

    def key(self) -> str:
        return f"{self.source}|{self.kind}|{','.join(sorted(self.selectors))}"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Result:
    source: str
    workloads: list[Workload] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""


class Discoverer(Protocol):
    name: str

    def discover(self) -> tuple[list[Workload], list[str]]:
        """Return (workloads, warnings). Raise on total failure."""
        ...


def run(discoverers: list[Discoverer]) -> list[Result]:
    """Run every source. One failing source does not stop the others."""
    out = []
    for d in discoverers:
        try:
            ws, warns = d.discover()
            out.append(Result(d.name, ws, warns))
        except Exception as e:  # noqa: BLE001 - reported to the user, not swallowed
            out.append(Result(d.name, error=f"{type(e).__name__}: {e}"))
    return out
