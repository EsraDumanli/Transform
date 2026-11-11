"""Discovery sources. Each is opt-in and configured explicitly."""

from .base import ConfigError, Discoverer, Result, Workload, run
from .ai_agents import AIAgents
from .docker import Docker
from .kubernetes import Kubernetes
from .network import Network
from .processes import Processes

SOURCES = {
    "ai_agents": AIAgents,
    "kubernetes": Kubernetes,
    "processes": Processes,
    "docker": Docker,
    "network": Network,
}


# Settings that hold file paths, resolved relative to the config file.
_PATH_KEYS = {"ai_agents": ("manifest_dirs",), "kubernetes": ("token_file", "ca_file")}


def build(cfg: dict, resolve=lambda p: p) -> list[Discoverer]:
    """Build the sources listed under ``discovery`` in the config.

    Unknown keys are an error rather than silently ignored, so a typo does not
    quietly turn a source off. ``resolve`` maps relative paths (normally
    against the config file's directory).
    """
    unknown = set(cfg) - set(SOURCES)
    if unknown:
        raise ConfigError(f"unknown discovery source(s): {sorted(unknown)}; known: {sorted(SOURCES)}")
    out = []
    for name, c in cfg.items():
        if c is None:
            continue
        c = dict(c)
        for key in _PATH_KEYS.get(name, ()):
            if isinstance(c.get(key), list):
                c[key] = [resolve(v) for v in c[key]]
            elif c.get(key):
                c[key] = resolve(c[key])
        out.append(SOURCES[name](c))
    return out


__all__ = ["AIAgents", "ConfigError", "Discoverer", "Docker", "Kubernetes", "Network", "Processes", "Result", "Workload", "build", "run", "SOURCES"]
