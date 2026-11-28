"""Discover AI/LLM agents and MCP servers.

Two methods, both opt-in:

* Walk ``manifest_dirs`` for agent manifests:
    - A2A Agent Cards (``agent-card.json``, ``agent.json``) that carry a
      ``name`` and either ``url`` or ``skills``.
    - MCP server configs (``.mcp.json``, ``mcp.json``,
      ``claude_desktop_config.json``) with an ``mcpServers`` object; each
      server becomes one workload.
* Read ``manifest_files``: specific files, e.g. Claude Code's ``~/.claude.json``
  (user-scoped ``mcpServers`` plus per-project ``projects.<path>.mcpServers``).
  Only the MCP server entries are read; nothing else in the file is kept.
* Probe ``a2a_urls`` for ``/.well-known/agent-card.json`` (and the older
  ``/.well-known/agent.json``).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from ..toolpolicy import ToolDenied
from .base import KIND_AI_AGENT, KIND_MCP_SERVER, ConfigError, Workload

A2A_NAMES = {"agent-card.json", "agent.json"}
MCP_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
WELL_KNOWN = ("/.well-known/agent-card.json", "/.well-known/agent.json")


class AIAgents:
    name = "ai-agents"

    def __init__(self, cfg: dict, gate, opener=None):
        self.dirs = cfg.get("manifest_dirs") or []
        self.files = cfg.get("manifest_files") or []
        self.max_depth = cfg.get("max_depth")
        self.urls = cfg.get("a2a_urls") or []
        self.timeout = cfg.get("timeout_seconds")
        self.gate = gate
        self._open = opener or _gated_opener(gate).open
        if not self.dirs and not self.files and not self.urls:
            raise ConfigError("ai-agents: set manifest_dirs, manifest_files and/or a2a_urls; nothing is scanned by default")
        if self.dirs and not (isinstance(self.max_depth, int) and self.max_depth > 0):
            raise ConfigError("ai-agents: max_depth must be a positive integer when manifest_dirs is set")
        if self.urls and not (isinstance(self.timeout, (int, float)) and self.timeout > 0):
            raise ConfigError("ai-agents: timeout_seconds must be > 0 when a2a_urls is set")

    def discover(self) -> tuple[list[Workload], list[str]]:
        out: list[Workload] = []
        warns: list[str] = []
        for d in self.dirs:
            root = Path(d).expanduser()
            try:
                with self.gate.action("discovery.ai_agents.read_manifests", path=str(root)) as summary:
                    ws, w = self._walk(root)
                    summary["workloads"] = len(ws)
            except ToolDenied as e:
                warns.append(f"ai-agents: {e}")
                continue
            out += ws
            warns += w
        for f in self.files:
            path = Path(f).expanduser()
            if not path.is_file():
                warns.append(f"ai-agents: {path} not found (skipped)")
                continue
            try:
                with self.gate.action("discovery.ai_agents.read_manifests", path=str(path)) as summary:
                    ws = parse_mcp_file(path)
                    summary["workloads"] = len(ws)
            except ToolDenied as e:
                warns.append(f"ai-agents: {e}")
                continue
            except (OSError, ValueError) as e:
                warns.append(f"ai-agents: {path}: {e}")
                continue
            out += ws
        for u in self.urls:
            try:
                out.append(self._probe(u))
            except ToolDenied as e:
                warns.append(f"ai-agents: {e}")
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
                if fn not in A2A_NAMES and fn not in MCP_NAMES:
                    continue
                try:
                    # Every manifest read is checked: a symlink can't reach outside the allowed paths.
                    self.gate.check("discovery.ai_agents.read_manifests", path=str(p))
                except ToolDenied as e:
                    warns.append(f"ai-agents: {e}")
                    continue
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
                with self.gate.action("discovery.ai_agents.probe_a2a", url=url) as summary:
                    with self._open(url, timeout=self.timeout) as resp:
                        body = resp.read(1 << 20)
                    summary["bytes"] = len(body)
            except ToolDenied:
                raise
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


class _GatedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only if the tool policy allows the new URL too."""

    def __init__(self, gate):
        self.gate = gate

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.gate.check("discovery.ai_agents.probe_a2a", url=newurl, redirected_from=req.full_url)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _gated_opener(gate):
    return urllib.request.build_opener(_GatedRedirect(gate))


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


def _safe_url(url: str) -> str:
    """Keep scheme, host and path only: query strings and user:password@ often carry tokens."""
    from urllib.parse import urlsplit, urlunsplit
    try:
        u = urlsplit(url)
    except ValueError:
        return "(unparseable URL)"
    host = u.hostname or ""
    if u.port:
        host = f"{host}:{u.port}"
    return urlunsplit((u.scheme, host, u.path, "", ""))


def parse_mcp_file(path: Path) -> list[Workload]:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"not valid JSON: {e}") from e
    if not isinstance(data, dict):
        return []
    origin = str(path.resolve())
    out = _mcp_servers(data.get("mcpServers"), origin, scope="user" if path.name == ".claude.json" else "")
    # Claude Code keeps project-scoped servers under projects.<project path>.mcpServers
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj in sorted(projects):
            entry = projects[proj]
            if isinstance(entry, dict):
                out += _mcp_servers(entry.get("mcpServers"), origin, scope="project", project=str(proj))
    return out


def _mcp_servers(servers, origin: str, scope: str = "", project: str = "") -> list[Workload]:
    if not isinstance(servers, dict):
        return []
    out = []
    for name in sorted(servers):
        s = servers[name] if isinstance(servers[name], dict) else {}
        attrs = {"protocol": "mcp", "origin": origin, "server_name": name}
        if scope:
            attrs["scope"] = scope
        if project:
            attrs["project"] = project
        transport = s.get("type") or ("http" if s.get("url") else "stdio" if s.get("command") else "")
        if transport:
            attrs["transport"] = transport
        if s.get("command"):
            attrs["command"] = str(s["command"])
        if s.get("url"):
            attrs["url"] = _safe_url(str(s["url"]))
        # args and env often hold secrets (tokens on the command line), so they
        # are counted, never copied.
        if s.get("args"):
            attrs["arg_count"] = str(len(s["args"]))
        if s.get("env"):
            attrs["env_count"] = str(len(s["env"]))
        selectors = [f"ai:mcp-config:{origin}", f"ai:mcp-server:{name}"]
        if project:
            selectors.append(f"ai:mcp-project:{project}")
        out.append(Workload(
            source="ai-agents", kind=KIND_MCP_SERVER, name=name, attributes=attrs, selectors=selectors,
        ))
    return out
