"""Registration entries: which SPIFFE ID a discovered workload may hold, and who approved it.

The server only issues an SVID for a SPIFFE ID that has an entry here ("no
entry, no identity", the same rule SPIRE uses).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import spiffeid


class RegistryError(ValueError):
    pass


@dataclass
class Entry:
    spiffe_id: str
    selectors: list[str]
    source: str          # discovery source that found the workload
    assigned_by: str     # "policy:<rule>" or "llm:<model>"
    approved_by: str     # who cleared the approval gate
    rationale: str = ""  # why this ID was chosen
    id: str = ""
    created_at: str = ""
    extra: dict = field(default_factory=dict)


class Registry:
    """JSON-file-backed store. ``path=None`` keeps it in memory (tests)."""

    def __init__(self, path: str | os.PathLike | None, trust_domain: str):
        self.path = Path(path) if path else None
        self.trust_domain = trust_domain
        self._lock = threading.Lock()
        self._entries: dict[str, Entry] = {}
        if self.path and self.path.exists():
            for raw in json.loads(self.path.read_text()):
                e = Entry(**raw)
                self._entries[e.id] = e

    def create(self, entry: Entry) -> tuple[Entry, bool]:
        """Validate and store an entry. Returns (entry, created).

        Re-registering the same SPIFFE ID with the same selectors returns the
        existing entry instead of a duplicate.
        """
        sid = spiffeid.parse(entry.spiffe_id)
        if not sid.member_of(self.trust_domain) or not sid.is_workload:
            raise RegistryError(f"{sid} is not a workload ID in trust domain {self.trust_domain!r}")
        if not entry.selectors:
            raise RegistryError("an entry needs at least one selector")
        if not entry.approved_by:
            raise RegistryError("approved_by is required: entries are only created after the approval gate")
        entry.selectors = sorted(entry.selectors)
        with self._lock:
            for existing in self._entries.values():
                if existing.spiffe_id == entry.spiffe_id and existing.selectors == entry.selectors:
                    return existing, False
            entry.id = secrets.token_hex(8)
            entry.created_at = dt.datetime.now(dt.timezone.utc).isoformat()
            self._entries[entry.id] = entry
            self._save()
        return entry, True

    def list(self) -> list[Entry]:
        with self._lock:
            return sorted(self._entries.values(), key=lambda e: e.spiffe_id)

    def has_spiffe_id(self, sid: str) -> bool:
        with self._lock:
            return any(e.spiffe_id == sid for e in self._entries.values())

    def delete(self, entry_id: str) -> bool:
        with self._lock:
            if self._entries.pop(entry_id, None) is None:
                return False
            self._save()
            return True

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        data = [asdict(e) for e in sorted(self._entries.values(), key=lambda e: e.id)]
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)
