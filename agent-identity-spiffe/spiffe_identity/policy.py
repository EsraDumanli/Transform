"""Rule-based SPIFFE ID assignment.

Rules are checked in order; the first rule whose ``match`` fits a workload
assigns its ID. A workload no rule matches stays *unassigned*: the policy
never invents an ID for it.

Rule shape::

    {
      "name": "k8s-agents",
      "match": {"source": "kubernetes", "kind": "k8s-pod",
                "attributes": {"label.app.kubernetes.io/component": "agent"}},
      "spiffe_id_path": "/k8s/ns/{attr.namespace}/sa/{attr.service_account}"
    }

``match`` values are glob patterns (``fnmatch``). ``spiffe_id_path`` may use
``{name}``, ``{kind}``, ``{source}`` and ``{attr.<key>}``. Each placeholder is
sanitized into a valid path segment. If a placeholder has no value, the rule
does not assign anything and the proposal says which value was missing.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from . import spiffeid
from .discovery.base import Workload

_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


class PolicyError(ValueError):
    pass


@dataclass
class Proposal:
    workload: Workload
    spiffe_id: str | None = None
    assigned_by: str = ""        # "policy:<rule>" or "llm:<model>"
    rationale: str = ""
    confidence: str = ""         # LLM proposals only
    problems: list[str] = field(default_factory=list)

    @property
    def assignable(self) -> bool:
        return self.spiffe_id is not None

    def to_dict(self) -> dict:
        return {
            "workload": self.workload.to_dict(), "spiffe_id": self.spiffe_id,
            "assigned_by": self.assigned_by, "rationale": self.rationale,
            "confidence": self.confidence, "problems": self.problems,
        }


@dataclass
class Rule:
    name: str
    match: dict
    spiffe_id_path: str

    def matches(self, w: Workload) -> bool:
        for key in ("source", "kind", "name"):
            pat = self.match.get(key)
            if pat is not None and not fnmatch.fnmatchcase(getattr(w, key), pat):
                return False
        for k, pat in (self.match.get("attributes") or {}).items():
            if k not in w.attributes or not fnmatch.fnmatchcase(w.attributes[k], pat):
                return False
        return True

    def render(self, w: Workload) -> tuple[str | None, str]:
        """Return (path, problem). Exactly one of them is set."""
        missing: list[str] = []

        def sub(m: re.Match) -> str:
            key = m.group(1)
            if key in ("name", "kind", "source"):
                raw = getattr(w, key)
            elif key.startswith("attr."):
                raw = w.attributes.get(key[5:], "")
            else:
                raise PolicyError(f"rule {self.name!r}: unknown placeholder {{{key}}}")
            seg = spiffeid.sanitize_segment(raw)
            if not seg:
                missing.append(key)
            return seg

        path = _PLACEHOLDER.sub(sub, self.spiffe_id_path)
        if missing:
            return None, f"rule {self.name!r} matched but has no usable value for: {', '.join(missing)}"
        try:
            spiffeid.validate_path(path)
        except spiffeid.SpiffeIDError as e:
            return None, f"rule {self.name!r} produced an invalid path: {e}"
        return path, ""


class Policy:
    def __init__(self, trust_domain: str, rules: list[Rule]):
        self.trust_domain = trust_domain
        self.rules = rules

    @classmethod
    def from_config(cls, trust_domain: str, cfg: dict) -> "Policy":
        raw = cfg.get("rules")
        if not isinstance(raw, list):
            raise PolicyError("policy.rules must be a list (it may be empty)")
        rules, seen = [], set()
        for i, r in enumerate(raw):
            for k in ("name", "match", "spiffe_id_path"):
                if not r.get(k):
                    raise PolicyError(f"policy.rules[{i}].{k} is required")
            if r["name"] in seen:
                raise PolicyError(f"duplicate rule name {r['name']!r}")
            seen.add(r["name"])
            if not r["spiffe_id_path"].startswith("/"):
                raise PolicyError(f"rule {r['name']!r}: spiffe_id_path must start with '/'")
            rules.append(Rule(r["name"], r["match"], r["spiffe_id_path"]))
        return cls(trust_domain, rules)

    def assign(self, w: Workload) -> Proposal:
        for rule in self.rules:
            if not rule.matches(w):
                continue
            path, problem = rule.render(w)
            if path is None:
                return Proposal(w, problems=[problem])
            return Proposal(
                w, spiffe_id=str(spiffeid.SpiffeID(self.trust_domain, path)),
                assigned_by=f"policy:{rule.name}", rationale=f"matched rule {rule.name!r}",
            )
        return Proposal(w, problems=["no policy rule matched"])
