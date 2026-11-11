"""Discover AI/LLM agents and MCP servers.

Two methods, both opt-in:

* Walk ``manifest_dirs`` for agent manifests:
    - A2A Agent Cards (``agent-card.json``, ``agent.json``) that carry a
      ``name`` and either ``url`` or ``skills``.
    - MCP server configs (``.mcp.json``, ``mcp.json``,
      ``claude_desktop_config.json``) with an ``mcpServers`` object; each
      server becomes one workload.
* Probe ``a2a_urls`` for ``/.well-known/agent-card.json`` (and the older
  ``/.well-known/agent.json``).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from .base import KIND_AI_AGENT, KIND_MCP_SERVER, ConfigError, Workload

A2A_NAMES = {"agent-card.json", "agent.json"}
MCP_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
WELL_KNOWN = ("/.well-known/agent-card.json", "/.well-known/agent.json")


class AIAgents:
    name = "ai-agents"

    def __init__(self, cfg: dict, opener=urllib.request.urlopen):
        self.dirs = cfg.get("manifest_dirs") or []
        self.max_depth = cfg.get("max_depth")
        self.urls = cfg.get("a2a_urls") or []
        self.timeout = cfg.get("timeout_seconds")
        self._open = opener
        if not self.dirs and not self.urls:
            raise ConfigError("ai-agents: set manifest_dirs and/or a2a_urls; nothing is scanned by default")
        if self.dirs and not (isinstance(self.max_depth, int) and self.max_depth > 0):
            raise ConfigError("ai-agents: max_depth must be a positive integer when manifest_dirs is set")
        if self.urls and not (isinstance(self.timeout, (int, float)) and self.timeout > 0):
            raise ConfigError("ai-agents: timeout_seconds must be > 0 when a2a_urls is set")

    def discover(self) -> tuple[list[Workload], list[str]]:
        out: list[Workload] = []
        warns: list[str] = []
        for d in self.dirs:
            ws, w = self._walk(Path(d).expanduser())
            out += ws
            warns += w
        for u in self.urls:
            try:
                out.append(self._probe(u))
            except Exception as e:  # noqa: BLE001
                warns.append(f"ai-agents: no agent card at {u}: {e}")
        return out, warns

    # ---- manifests ------------------------------------------------------------

    def _walk(self, root: Path) -> tuple[list[Workload], list[str]]:
        out, warns = [], []
        if not root.is_dir():
            return out, [f"ai-agents: {root} is not a directory"]
        base_depth = len(root.resolve().parts)

        def onerror(err: OSError):
            warns.append(f"ai-agents: cannot read {err.filename}: {err.strerror}")

        for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
            depth = len(Path(dirpath).resolve().parts) - base_depth
            dirnames[:] = [] if depth >= self.max_depth - 1 else [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    if fn in A2A_NAMES:
                        w = parse_a2a_file(p)
                        if w:
                            out.append(w)
                    elif fn in MCP_NAMES:
                        out += parse_mcp_file(p)
                except (OSError, ValueError) as e:
                    warns.append(f"ai-agents: {p}: {e}")
        return out, warns

    # ---- A2A probe ------------------------------------------------------------

    def _probe(self, base: str) -> Workload:
        base = base.rstrip("/")
        last = "no response"
        for path in WELL_KNOWN:
            url = base + path
            try:
                with self._open(url, timeout=self.timeout) as resp:
                    body = resp.read(1 << 20)
            except (urllib.error.URLError, OSError) as e:
                last = str(e)
                continue
            try:
                card = json.loads(body)
            except json.JSONDecodeError:
                last = f"{url} did not return JSON"
                continue
            if _looks_like_card(card):
                return _card_workload(card, url)
            last = f"{url} did not return an A2A agent card"
        raise LookupError(last)


def _looks_like_card(c) -> bool:
    return isinstance(c, dict) and bool(c.get("name")) and (bool(c.get("url")) or bool(c.get("skills")))


def _card_workload(c: dict, origin: str) -> Workload:
    attrs = {"protocol": "a2a", "origin": origin, "agent_name": str(c["name"])}
    for src, dst in (("url", "url"), ("version", "version"), ("protocolVersion", "protocol_version"), ("description", "description")):
        if c.get(src):
            attrs[dst] = str(c[src])
    provider = c.get("provider")
    if isinstance(provider, dict) and provider.get("organization"):
        attrs["provider"] = str(provider["organization"])
    skills = sorted(str(s["id"]) for s in c.get("skills") or [] if isinstance(s, dict) and s.get("id"))
    if skills:
        attrs["skills"] = ",".join(skills)
    return Workload(
        source="ai-agents", kind=KIND_AI_AGENT, name=str(c["name"]), attributes=attrs,
        selectors=[f"ai:a2a-card:{origin}", f"ai:agent-name:{c['name']}"],
    )


def parse_a2a_file(path: Path) -> Workload | None:
    try:
        card = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None  # "agent.json" is a common name; a non-A2A file is not an error
    if not _looks_like_card(card):
        return None
    return _card_workload(card, str(path.resolve()))


def parse_mcp_file(path: Path) -> list[Workload]:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"not valid JSON: {e}") from e
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    origin = str(path.resolve())
    out = []
    for name in sorted(servers):
        s = servers[name] if isinstance(servers[name], dict) else {}
        attrs = {"protocol": "mcp", "origin": origin, "server_name": name}
        transport = s.get("type") or ("http" if s.get("url") else "stdio" if s.get("command") else "")
        if transport:
            attrs["transport"] = transport
        if s.get("command"):
            attrs["command"] = str(s["command"])
        if s.get("url"):
            attrs["url"] = str(s["url"])
        # args and env often hold secrets (tokens on the command line), so they
        # are counted, never copied.
        if s.get("args"):
            attrs["arg_count"] = str(len(s["args"]))
        if s.get("env"):
            attrs["env_count"] = str(len(s["env"]))
        out.append(Workload(
            source="ai-agents", kind=KIND_MCP_SERVER, name=name, attributes=attrs,
            selectors=[f"ai:mcp-config:{origin}", f"ai:mcp-server:{name}"],
        ))
    return out
