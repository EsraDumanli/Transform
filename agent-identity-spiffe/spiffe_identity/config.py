"""Load and validate the JSON config.

Nothing here has a silent default for a value that matters (trust domain,
what to scan, where the server is). A missing required value is an error
that names the key, so you always know what the tools are acting on.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import spiffeid


class ConfigError(ValueError):
    pass


def load(path: str | Path) -> dict:
    p = Path(path)
    try:
        cfg = json.loads(p.read_text())
    except FileNotFoundError as e:
        raise ConfigError(f"config file {p} not found") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"{p}: invalid JSON: {e}") from e
    if not isinstance(cfg, dict):
        raise ConfigError(f"{p}: top level must be an object")
    td = cfg.get("trust_domain")
    if not td:
        raise ConfigError("trust_domain is required (e.g. \"lab.example\"); there is no default")
    try:
        spiffeid.validate_trust_domain(td)
    except spiffeid.SpiffeIDError as e:
        raise ConfigError(f"trust_domain: {e}") from e
    cfg["_base_dir"] = str(p.resolve().parent)
    return cfg


def section(cfg: dict, name: str) -> dict:
    s = cfg.get(name)
    if not isinstance(s, dict):
        raise ConfigError(f"config section {name!r} is required for this command")
    return s


def require(sec: dict, key: str, typ: type | tuple, where: str):
    """Return sec[key], or raise naming the missing/invalid key. Numbers must be > 0."""
    v = sec.get(key)
    if v is None or v == "" or v == []:
        raise ConfigError(f"{where}.{key} is required")
    if isinstance(v, bool) or not isinstance(v, typ):
        raise ConfigError(f"{where}.{key} has the wrong type")
    if isinstance(v, (int, float)) and v <= 0:
        raise ConfigError(f"{where}.{key} must be > 0")
    return v


def resolve_path(cfg: dict, p: str) -> str:
    """Resolve a path relative to the config file's directory."""
    path = Path(p).expanduser()
    return str(path if path.is_absolute() else Path(cfg["_base_dir"]) / path)
