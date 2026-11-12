"""Parse and validate SPIFFE IDs (spec: SPIFFE-ID.md).

A SPIFFE ID is ``spiffe://<trust-domain>/<path>``. The trust domain is lowercase
letters, digits, ``.``, ``-`` and ``_``. Each path segment is letters, digits,
``.``, ``-`` and ``_``, and may not be empty, ``.`` or ``..``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SCHEME = "spiffe://"
MAX_LENGTH = 2048

_TD_RE = re.compile(r"^[a-z0-9._-]+$")
_SEG_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_BAD_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


class SpiffeIDError(ValueError):
    """Raised for an invalid SPIFFE ID, trust domain or path."""


@dataclass(frozen=True)
class SpiffeID:
    trust_domain: str
    path: str = ""  # "" or "/seg/seg..."

    def __str__(self) -> str:
        return SCHEME + self.trust_domain + self.path

    def member_of(self, trust_domain: str) -> bool:
        return self.trust_domain == trust_domain

    @property
    def is_workload(self) -> bool:
        """True if this names a workload rather than the bare trust domain."""
        return self.path != ""


def validate_trust_domain(td: str) -> None:
    if not td:
        raise SpiffeIDError("trust domain is empty")
    if not _TD_RE.match(td):
        raise SpiffeIDError(f"trust domain {td!r} may only contain a-z 0-9 . - _")


def validate_path(path: str) -> None:
    if path == "":
        return
    if not path.startswith("/"):
        raise SpiffeIDError(f"path {path!r} must start with '/'")
    for seg in path[1:].split("/"):
        if seg == "":
            raise SpiffeIDError(f"path {path!r} has an empty segment (or a trailing '/')")
        if seg in (".", ".."):
            raise SpiffeIDError(f"path {path!r} contains a {seg!r} segment")
        if not _SEG_RE.match(seg):
            raise SpiffeIDError(f"path segment {seg!r} may only contain A-Z a-z 0-9 . - _")


def parse(s: str) -> SpiffeID:
    if len(s.encode()) > MAX_LENGTH:
        raise SpiffeIDError(f"SPIFFE ID longer than {MAX_LENGTH} bytes")
    if not s.startswith(SCHEME):
        raise SpiffeIDError(f"SPIFFE ID {s!r} must start with {SCHEME!r}")
    rest = s[len(SCHEME):]
    td, sep, tail = rest.partition("/")
    path = sep + tail if sep else ""
    validate_trust_domain(td)
    validate_path(path)
    return SpiffeID(td, path)


def from_parts(trust_domain: str, *segments: str) -> SpiffeID:
    validate_trust_domain(trust_domain)
    path = "/" + "/".join(segments) if segments else ""
    validate_path(path)
    return SpiffeID(trust_domain, path)


def sanitize_segment(text: str) -> str:
    """Turn arbitrary text (a pod name, an agent name) into a valid path segment.

    Returns "" when nothing usable is left. Callers must treat "" as "cannot
    build an ID from this", never substitute an invented value.
    """
    out = _BAD_CHARS.sub("-", text).strip("-")
    return "" if out in (".", "..") else out
