"""Deny-by-default tool policy, enforced at every action, with every decision traced.

The policy lives in its own file (``tool_policy_file`` in the config), so it
can be reviewed and locked down separately from the config that says what a
run should do. The config asks; the policy decides.

Rules
-----
* Fail closed: a missing, unreadable, world-writable or invalid policy file
  stops the program. Nothing runs without a valid policy.
* ``"default"`` must be ``"deny"``: there is no allow-all mode.
* A tool that is not listed is denied.
* Every listed tool must state its limits (folders, hosts, networks, models,
  SPIFFE ID prefixes...). A tool listed without its required limits, an
  unknown tool name, or an unknown limit is a startup error, so a typo can't
  silently widen or narrow access.
* Every action, allowed or denied, is written to the trace file (see
  ``trace.py``). If the trace can't be written, the action is refused.

Example::

    {
      "version": 1,
      "default": "deny",
      "trace": {"file": "../.data/demo/trace.jsonl"},
      "tools": {
        "discovery.ai_agents.read_manifests": {"paths": ["manifests"]},
        "server.connect": {"urls": ["https://127.0.0.1:8443"]},
        "server.entries.list": {},
        "server.entries.create": {"spiffe_id_prefixes": ["spiffe://demo.local/ai-agent/"]}
      }
    }
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import trace as trace_mod

log = logging.getLogger("toolpolicy")


class ToolPolicyError(ValueError):
    """The policy file is missing or invalid. Nothing may run."""


class ToolDenied(PermissionError):
    """An action was blocked by the tool policy."""

    def __init__(self, tool: str, reason: str):
        super().__init__(f"blocked by tool policy: {tool}: {reason}")
        self.tool = tool
        self.reason = reason


# ---- helpers -------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443}


def origin(url: str) -> str:
    """Normalise a URL to scheme://host:port so policy comparisons are exact."""
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        raise ValueError(f"not an http(s) URL with a host: {url!r}")
    port = parts.port or _DEFAULT_PORTS[scheme]
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def _within(path: str, roots: list[str]) -> bool:
    p = _real(path)
    for root in roots:
        r = _real(root)
        try:
            if os.path.commonpath([p, r]) == r:
                return True
        except ValueError:  # different drives (Windows) etc.
            continue
    return False


def _spiffe_prefix_ok(spiffe_id: str, prefixes: list[str]) -> bool:
    for pre in prefixes:
        base = pre.rstrip("/")
        if spiffe_id == base or spiffe_id.startswith(base + "/"):
            return True
    return False


# ---- tool catalogue ------------------------------------------------------------
# Each tool: required limits (name -> validator) and optional limits.

def _str_list(v, key):
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
        raise ToolPolicyError(f"{key} must be a non-empty list of strings")
    return v


def _origin_list(v, key):
    _str_list(v, key)
    try:
        return [origin(x) for x in v]
    except ValueError as e:
        raise ToolPolicyError(f"{key}: {e}") from e


def _pos_int(v, key):
    if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
        raise ToolPolicyError(f"{key} must be a positive integer")
    return v


def _ports(v, key):
    if not isinstance(v, list) or not v or not all(isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in v):
        raise ToolPolicyError(f"{key} must be a non-empty list of ports (1-65535)")
    return v


def _cidrs(v, key):
    _str_list(v, key)
    try:
        return [ipaddress.ip_network(c, strict=False) for c in v]
    except ValueError as e:
        raise ToolPolicyError(f"{key}: {e}") from e


def _methods(v, key):
    _str_list(v, key)
    bad = set(v) - {"ps", "procfs"}
    if bad:
        raise ToolPolicyError(f"{key}: unknown method(s) {sorted(bad)}; allowed: ps, procfs")
    return v


def _spiffe_prefixes(v, key):
    _str_list(v, key)
    from . import spiffeid
    for p in v:
        try:
            spiffeid.parse(p.rstrip("/"))
        except spiffeid.SpiffeIDError as e:
            raise ToolPolicyError(f"{key}: {p!r}: {e}") from e
    return v


def _bool(v, key):
    if not isinstance(v, bool):
        raise ToolPolicyError(f"{key} must be true or false")
    return v


def _reasons(v, key):
    from .lifecycle import REASONS
    _str_list(v, key)
    bad = [r for r in v if r not in REASONS]
    if bad:
        raise ToolPolicyError(f"{key}: unknown reason(s) {bad}; known: {sorted(REASONS)}")
    return v


def _scope_types(v, key):
    from .lifecycle import SCOPE_PATTERNS
    _str_list(v, key)
    bad = [t for t in v if t not in SCOPE_PATTERNS]
    if bad:
        raise ToolPolicyError(f"{key}: unknown scope type(s) {bad}; known: {sorted(SCOPE_PATTERNS)}")
    return v


def _attr_list(v, key):
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ToolPolicyError(f"{key} must be a list of attribute names (it may be empty)")
    return v


TOOLS: dict[str, dict] = {
    "discovery.ai_agents.read_manifests": {"required": {"paths": _str_list}},
    "discovery.ai_agents.probe_a2a": {"required": {"origins": _origin_list}},
    "discovery.kubernetes.list_pods": {"required": {"api_servers": _origin_list, "namespaces": _str_list}},
    "discovery.docker.list_containers": {"required": {"sockets": _str_list}},
    "discovery.processes.read": {"required": {"methods": _methods}, "optional": {"proc_roots": _str_list}},
    "discovery.network.tcp_connect": {"required": {"cidrs": _cidrs, "ports": _ports, "max_hosts": _pos_int}},
    "llm.propose_ids": {"required": {"models": _str_list, "api_origins": _origin_list,
                                     "max_calls_per_run": _pos_int, "send_attributes": _attr_list}},
    "server.connect": {"required": {"urls": _origin_list}},
    "server.entries.list": {},
    "server.entries.create": {"required": {"spiffe_id_prefixes": _spiffe_prefixes}},
    "server.entries.delete": {},
    "server.svid.x509": {"required": {"spiffe_id_prefixes": _spiffe_prefixes}},
    "server.svid.jwt": {"required": {"spiffe_id_prefixes": _spiffe_prefixes, "audiences": _str_list}},
    "server.nodes.enroll": {"required": {"max_pending": _pos_int}},
    "server.nodes.list": {},
    "server.nodes.manage": {},
    "server.nodes.challenge": {},
    "server.svid.attested": {"required": {"spiffe_id_prefixes": _spiffe_prefixes, "max_ttl_minutes": _pos_int,
                                          "require_hardened_runtime": _bool}},
    "portal.scan": {},
    "portal.approve": {},
    "portal.revoke": {},
    "portal.devices": {},
    "portal.builds": {},
    "server.svid.list_issued": {},
    "server.svid.revoke": {"required": {"reasons": _reasons}},
    "portal.revoke_identity": {},
    "server.grants.create": {"required": {"max_grant_minutes": _pos_int, "allowed_scope_types": _scope_types}},
    "server.grants.list": {},
    "server.grants.withdraw": {},
    "portal.grants": {},
}


# ---- the policy ----------------------------------------------------------------

@dataclass
class ToolPolicy:
    path: str
    sha256: str
    trace_file: str
    tools: dict[str, dict]      # tool -> validated limits
    rubric: dict[str, str] = None   # attestation method -> high|medium|low (unlisted = low)

    @classmethod
    def load(cls, path: str | os.PathLike) -> "ToolPolicy":
        p = Path(path)
        if not p.exists():
            raise ToolPolicyError(f"tool policy {p} not found: deny-by-default, nothing can run without it")
        mode = p.stat().st_mode
        if mode & stat.S_IWOTH:
            raise ToolPolicyError(f"tool policy {p} is writable by every user on this machine; run: chmod o-w '{p}'")
        raw = p.read_bytes()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ToolPolicyError(f"{p}: invalid JSON: {e}") from e
        return cls.from_dict(data, str(p.resolve()), hashlib.sha256(raw).hexdigest())

    @classmethod
    def from_dict(cls, data: dict, path: str = "<memory>", sha256: str = "") -> "ToolPolicy":
        if not isinstance(data, dict):
            raise ToolPolicyError("tool policy must be a JSON object")
        unknown = set(data) - {"version", "default", "trace", "tools", "attestation_rubric", "_comment"}
        if unknown:
            raise ToolPolicyError(f"unknown top-level key(s) in tool policy: {sorted(unknown)}")
        if data.get("version") != 1:
            raise ToolPolicyError('tool policy "version" must be 1')
        if data.get("default") != "deny":
            raise ToolPolicyError('tool policy "default" must be "deny" (there is no allow-all mode)')
        tr = data.get("trace")
        if not isinstance(tr, dict) or not isinstance(tr.get("file"), str) or not tr["file"]:
            raise ToolPolicyError('tool policy needs "trace": {"file": "<path to trace.jsonl>"}; every action is traced')
        base = Path(path).parent if path != "<memory>" else Path.cwd()
        trace_file = Path(tr["file"]).expanduser()
        trace_file = trace_file if trace_file.is_absolute() else base / trace_file
        tools_raw = data.get("tools")
        if not isinstance(tools_raw, dict):
            raise ToolPolicyError('tool policy needs a "tools" object (it may be empty, which denies everything)')
        tools: dict[str, dict] = {}
        for name, limits in tools_raw.items():
            spec = TOOLS.get(name)
            if spec is None:
                raise ToolPolicyError(f"unknown tool {name!r}; known tools: {sorted(TOOLS)}")
            if not isinstance(limits, dict):
                raise ToolPolicyError(f"{name}: limits must be an object ({{}} for tools without limits)")
            required, optional = spec.get("required", {}), spec.get("optional", {})
            extra = set(limits) - set(required) - set(optional)
            if extra:
                raise ToolPolicyError(f"{name}: unknown limit(s) {sorted(extra)}; allowed: {sorted({*required, *optional})}")
            checked = {}
            for key, validate in required.items():
                if key not in limits:
                    raise ToolPolicyError(f"{name}: required limit {key!r} is missing")
                checked[key] = validate(limits[key], f"{name}.{key}")
            for key, validate in optional.items():
                if key in limits:
                    checked[key] = validate(limits[key], f"{name}.{key}")
            if name == "discovery.processes.read" and "procfs" in checked["methods"] and "proc_roots" not in checked:
                raise ToolPolicyError(f"{name}: proc_roots is required when methods includes procfs")
            if name in ("discovery.ai_agents.read_manifests", "discovery.docker.list_containers"):
                key = "paths" if "paths" in checked else "sockets"
                checked[key] = [str(Path(x).expanduser() if Path(x).expanduser().is_absolute() else base / x) for x in checked[key]]
            if name == "discovery.processes.read" and "proc_roots" in checked:
                checked["proc_roots"] = [str(Path(x).expanduser() if Path(x).expanduser().is_absolute() else base / x) for x in checked["proc_roots"]]
            tools[name] = checked
        rubric = _rubric(data.get("attestation_rubric", {}))
        return cls(path=path, sha256=sha256, trace_file=str(trace_file), tools=tools, rubric=rubric)

    # ---- decisions --------------------------------------------------------------

    def decide(self, tool: str, args: dict, calls_so_far: int = 0) -> str | None:
        """Return None if allowed, else the reason it's denied."""
        if tool not in TOOLS:
            return "unknown tool"
        if tool not in self.tools:
            return "not listed in the tool policy"
        lim = self.tools[tool]
        try:
            return _CHECKS.get(tool, _no_limits)(lim, args, calls_so_far)
        except (KeyError, ValueError, TypeError) as e:
            return f"could not check the request against the policy ({type(e).__name__}: {e})"


def _rubric(raw) -> dict[str, str]:
    from .nodes import CONFIDENCE_LEVELS, METHODS
    if not isinstance(raw, dict):
        raise ToolPolicyError("attestation_rubric must be an object of method -> high|medium|low")
    out = {}
    for method, level in raw.items():
        if method == "_comment":
            continue
        if method not in METHODS:
            raise ToolPolicyError(f"attestation_rubric: unknown method {method!r}; known: {list(METHODS)}")
        if level not in CONFIDENCE_LEVELS:
            raise ToolPolicyError(f"attestation_rubric.{method} must be one of {list(CONFIDENCE_LEVELS)}")
        out[method] = level
    return out


def _no_limits(lim, args, n):
    return None


def _check_paths(lim, a, n):
    return None if _within(a["path"], lim["paths"]) else f"{a['path']} is outside the allowed paths"


def _check_probe(lim, a, n):
    o = origin(a["url"])
    return None if o in lim["origins"] else f"{o} is not an allowed origin"


def _check_k8s(lim, a, n):
    o = origin(a["api_server"])
    if o not in lim["api_servers"]:
        return f"API server {o} is not allowed"
    ns = a["namespace"]
    return None if ns in lim["namespaces"] else f"namespace {ns!r} is not allowed"


def _check_docker(lim, a, n):
    s = _real(a["socket"])
    return None if s in {_real(x) for x in lim["sockets"]} else f"socket {a['socket']} is not allowed"


def _check_processes(lim, a, n):
    if a["method"] not in lim["methods"]:
        return f"method {a['method']!r} is not allowed"
    if a["method"] == "procfs" and not _within(a["proc_root"], lim.get("proc_roots", [])):
        return f"proc_root {a['proc_root']} is not allowed"
    return None


def _check_network(lim, a, n):
    if a["max_hosts"] > lim["max_hosts"]:
        return f"max_hosts {a['max_hosts']} exceeds the policy's {lim['max_hosts']}"
    for c in a["cidrs"]:
        net = ipaddress.ip_network(c, strict=False)
        if not any(net.version == ok.version and net.subnet_of(ok) for ok in lim["cidrs"]):
            return f"range {c} is not inside an allowed range"
    bad = [p for p in a["ports"] if p not in lim["ports"]]
    return f"port(s) {bad} are not allowed" if bad else None


def _check_llm(lim, a, n):
    if a["model"] not in lim["models"]:
        return f"model {a['model']!r} is not allowed"
    o = origin(a["api_url"])
    if o not in lim["api_origins"]:
        return f"API origin {o} is not allowed"
    extra = [x for x in a["send_attributes"] if x not in lim["send_attributes"]]
    if extra:
        return f"sending attribute(s) {extra} is not allowed"
    if n >= lim["max_calls_per_run"]:
        return f"max_calls_per_run ({lim['max_calls_per_run']}) reached"
    return None


def _check_connect(lim, a, n):
    o = origin(a["url"])
    return None if o in lim["urls"] else f"server {o} is not allowed"


def _check_spiffe(lim, a, n):
    return None if _spiffe_prefix_ok(a["spiffe_id"], lim["spiffe_id_prefixes"]) else f"{a['spiffe_id']} is outside the allowed SPIFFE ID prefixes"


def _check_jwt(lim, a, n):
    r = _check_spiffe(lim, a, n)
    if r:
        return r
    bad = [x for x in a["audience"] if x not in lim["audiences"]]
    return f"audience(s) {bad} are not allowed" if bad else None


def _check_attested(lim, a, n):
    r = _check_spiffe(lim, a, n)
    if r:
        return r
    if a["ttl_minutes"] > lim["max_ttl_minutes"]:
        return f"ttl {a['ttl_minutes']} min exceeds the policy's {lim['max_ttl_minutes']}"
    if lim["require_hardened_runtime"] and not a["hardened_runtime"]:
        return "the workload doesn't run with Hardened Runtime, which the policy requires"
    return None


def _check_enroll(lim, a, n):
    if a["pending"] >= lim["max_pending"]:
        return f"max_pending ({lim['max_pending']}) enrollments already waiting"
    return None


def _check_revoke(lim, a, n):
    return None if a["reason"] in lim["reasons"] else f"reason {a['reason']!r} isn't allowed by the policy"


def _check_grant(lim, a, n):
    if a["minutes"] > lim["max_grant_minutes"]:
        return f"grant of {a['minutes']} min exceeds the policy's {lim['max_grant_minutes']}"
    bad = [t for t in a["scope_types"] if t not in lim["allowed_scope_types"]]
    return f"scope type(s) {bad} aren't allowed" if bad else None


_CHECKS = {
    "server.svid.revoke": _check_revoke,
    "server.grants.create": _check_grant,
    "server.svid.attested": _check_attested,
    "server.nodes.enroll": _check_enroll,
    "discovery.ai_agents.read_manifests": _check_paths,
    "discovery.ai_agents.probe_a2a": _check_probe,
    "discovery.kubernetes.list_pods": _check_k8s,
    "discovery.docker.list_containers": _check_docker,
    "discovery.processes.read": _check_processes,
    "discovery.network.tcp_connect": _check_network,
    "llm.propose_ids": _check_llm,
    "server.connect": _check_connect,
    "server.entries.create": _check_spiffe,
    "server.svid.x509": _check_spiffe,
    "server.svid.jwt": _check_jwt,
}


# ---- the gate ------------------------------------------------------------------

class ToolGate:
    """The single choke point: every action calls ``check`` or ``action``."""

    def __init__(self, policy: ToolPolicy, writer: trace_mod.TraceWriter, actor: str = ""):
        self.policy = policy
        self.writer = writer
        self.actor = actor
        self._lock = threading.Lock()
        self._calls: dict[str, int] = {}

    def new_run(self) -> None:
        """Reset per-run counters (e.g. llm max_calls_per_run)."""
        with self._lock:
            self._calls.clear()

    def check(self, tool: str, **args) -> str:
        """Allow or deny ``tool`` with ``args``; trace the decision. Returns the span id."""
        span = secrets.token_hex(8)
        with self._lock:
            n = self._calls.get(tool, 0)
            reason = self.policy.decide(tool, args, n)
            if reason is None:
                self._calls[tool] = n + 1
        decision = "allow" if reason is None else "deny"
        # Fail closed: if the trace can't be written, TraceError propagates and nothing runs.
        self.writer.emit("action.decision", span_id=span, tool=tool, decision=decision,
                         reason=reason or "allowed by tool policy", args=args, actor=self.actor,
                         policy_sha256=self.policy.sha256)
        if reason is not None:
            raise ToolDenied(tool, reason)
        return span

    @contextlib.contextmanager
    def action(self, tool: str, **args):
        """Check, then trace the action's result and duration.

        The block may fill in the yielded dict with a short, non-sensitive
        summary (e.g. ``{"workloads": 4}``) that goes into the result event.
        """
        span = self.check(tool, **args)
        summary: dict = {}
        t0 = time.monotonic()
        try:
            yield summary
        except BaseException as e:
            self.writer.emit("action.result", span_id=span, tool=tool, outcome="error",
                             error=f"{type(e).__name__}: {e}", duration_ms=round((time.monotonic() - t0) * 1000, 1),
                             summary=summary, actor=self.actor)
            raise
        self.writer.emit("action.result", span_id=span, tool=tool, outcome="ok",
                         duration_ms=round((time.monotonic() - t0) * 1000, 1), summary=summary, actor=self.actor)

    @contextlib.contextmanager
    def run(self, name: str, trace_id: str | None = None, **fields):
        """Start a trace: everything inside shares one trace_id."""
        tid = trace_id if trace_id and trace_mod.valid_trace_id(trace_id) else trace_mod.new_trace_id()
        token = trace_mod.set_trace_id(tid)
        self.new_run()
        t0 = time.monotonic()
        self.writer.emit("run.start", name=name, actor=self.actor, policy=self.policy.path,
                         policy_sha256=self.policy.sha256, **fields)
        status = "ok"
        try:
            yield tid
        except BaseException as e:
            status = f"error: {type(e).__name__}: {e}"
            raise
        finally:
            try:
                self.writer.emit("run.end", name=name, status=status, actor=self.actor,
                                 duration_ms=round((time.monotonic() - t0) * 1000, 1))
            finally:
                trace_mod.reset_trace_id(token)


def gate_from_config(cfg: dict, component: str, actor: str = "", attach_logs: bool = True) -> ToolGate:
    """Load the policy named by the config and open the trace. Fails closed."""
    from . import config as config_mod

    p = cfg.get("tool_policy_file")
    if not p:
        raise config_mod.ConfigError(
            "tool_policy_file is required: every action is checked against a deny-by-default tool policy"
        )
    policy = ToolPolicy.load(config_mod.resolve_path(cfg, p))
    writer = trace_mod.TraceWriter(policy.trace_file, component)
    if attach_logs:
        trace_mod.attach_logging(writer)
    return ToolGate(policy, writer, actor)
