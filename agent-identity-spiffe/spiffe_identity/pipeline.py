"""Discover -> policy -> optional LLM, plus saving/loading a scan snapshot.

Shared by the CLI (`plan`, `apply`) and the portal, so both run exactly the
same steps and write the same snapshot format.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import config as config_mod, discovery
from .classifier import ClaudeProposer, LLMError
from .policy import Policy, Proposal

SNAPSHOT_VERSION = 1


@dataclass
class Scan:
    results: list[discovery.Result]
    proposals: list[Proposal]
    notes: list[str] = field(default_factory=list)  # e.g. why the LLM step was skipped
    scanned_at: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))


def discover(cfg: dict) -> list[discovery.Result]:
    dcfg = config_mod.section(cfg, "discovery")
    if not dcfg:
        raise config_mod.ConfigError("discovery: enable at least one source")
    return discovery.run(discovery.build(dcfg, lambda p: config_mod.resolve_path(cfg, p)))


def plan(cfg: dict, use_llm: bool | None = None) -> Scan:
    results = discover(cfg)
    policy = Policy.from_config(cfg["trust_domain"], config_mod.section(cfg, "policy"))
    seen, proposals = set(), []
    for r in results:
        for w in r.workloads:
            if w.key() in seen:
                continue
            seen.add(w.key())
            proposals.append(policy.assign(w))
    notes: list[str] = []
    llm_cfg = cfg.get("llm") or {}
    enabled = llm_cfg.get("enabled", False) if use_llm is None else use_llm
    unassigned = [p for p in proposals if not p.assignable]
    if enabled and unassigned:
        try:
            ClaudeProposer(cfg["trust_domain"], llm_cfg).propose(unassigned)
        except LLMError as e:
            notes.append(f"LLM step skipped: {e}")
        except Exception as e:  # noqa: BLE001 - API/network errors leave workloads unassigned
            notes.append(f"LLM step failed ({type(e).__name__}: {e}); those workloads stay unassigned")
    return Scan(results, proposals, notes)


def proposal_id(p: dict) -> str:
    """Stable id for a proposal: same workload + same identity -> same id."""
    w = p["workload"]
    key = f"{w['source']}|{w['kind']}|{','.join(sorted(w['selectors']))}|{p.get('spiffe_id') or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def snapshot(cfg: dict, scan: Scan) -> dict:
    proposals = []
    for p in scan.proposals:
        d = p.to_dict()
        d["id"] = proposal_id(d)
        proposals.append(d)
    return {
        "version": SNAPSHOT_VERSION,
        "trust_domain": cfg["trust_domain"],
        "scanned_at": scan.scanned_at,
        "sources": [
            {"source": r.source, "workload_count": len(r.workloads), "warnings": r.warnings, "error": r.error}
            for r in scan.results
        ],
        "notes": scan.notes,
        "proposals": proposals,
    }


def scan_file(cfg: dict) -> str | None:
    """Path of the saved scan, if the config names one (portal.scan_file)."""
    p = (cfg.get("portal") or {}).get("scan_file")
    return config_mod.resolve_path(cfg, p) if p else None


def save_snapshot(path: str, snap: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(snap, f, indent=2)
    os.replace(tmp, target)


def load_snapshot(path: str, trust_domain: str) -> dict | None:
    """Return the saved scan, or None if there isn't one yet.

    A snapshot from another trust domain or format version is rejected rather
    than shown, so the portal never displays identities for the wrong domain.
    """
    p = Path(path)
    if not p.exists():
        return None
    snap = json.loads(p.read_text())
    if snap.get("version") != SNAPSHOT_VERSION:
        raise ValueError(f"{p}: unsupported snapshot version {snap.get('version')!r}")
    if snap.get("trust_domain") != trust_domain:
        raise ValueError(f"{p}: snapshot is for trust domain {snap.get('trust_domain')!r}, not {trust_domain!r}")
    return snap
