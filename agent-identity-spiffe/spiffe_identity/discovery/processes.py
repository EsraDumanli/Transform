"""Discover local processes via procfs (Linux only).

``include`` is required: listing every process on a machine is noise, and
picking "interesting" ones on your behalf would be a guess.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from pathlib import Path

from .base import KIND_PROCESS, ConfigError, Workload


class Processes:
    name = "processes"

    def __init__(self, cfg: dict):
        self.include = cfg.get("include") or []
        self.cmdline_contains = cfg.get("cmdline_contains") or []
        self.proc_root = cfg.get("proc_root") or ""
        if not self.include:
            raise ConfigError("processes: include patterns are required, e.g. [\"python*\", \"node\"]")
        if not self.proc_root:
            raise ConfigError('processes: proc_root is required (normally "/proc")')

    def discover(self) -> tuple[list[Workload], list[str]]:
        if not sys.platform.startswith("linux"):
            raise OSError(f"processes: only Linux (procfs) is supported, this is {sys.platform}")
        out, warns = [], []
        unreadable_exe = 0
        for entry in Path(self.proc_root).iterdir():
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text().strip()
            except OSError:
                continue  # process exited
            try:
                exe = os.readlink(entry / "exe")
            except OSError:
                exe = ""
            if not self._matches(comm, exe):
                continue
            try:
                cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            except OSError:
                cmdline = ""
            if self.cmdline_contains and not any(s in cmdline for s in self.cmdline_contains):
                continue
            uid = _read_uid(entry / "status")
            if uid is None:
                warns.append(f"processes: pid {entry.name}: could not read Uid")
                continue
            attrs = {"pid": entry.name, "uid": uid, "comm": comm, "cmdline": cmdline}
            sel = [f"unix:uid:{uid}", f"unix:comm:{comm}"]
            if exe:
                attrs["exe"] = exe
                sel.append(f"unix:path:{exe}")
            else:
                unreadable_exe += 1
            out.append(Workload(source="processes", kind=KIND_PROCESS, name=f"{comm}[{entry.name}]", attributes=attrs, selectors=sel))
        if unreadable_exe:
            warns.append(
                f"processes: could not read the executable path of {unreadable_exe} matching process(es) "
                "(usually needs the same user or root); their selectors are weaker"
            )
        return out, warns

    def _matches(self, comm: str, exe: str) -> bool:
        names = [comm] + ([os.path.basename(exe)] if exe else [])
        return any(fnmatch.fnmatchcase(n, pat) for pat in self.include for n in names)


def _read_uid(path: Path) -> str | None:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("Uid:"):
                fields = line.split()
                return fields[1] if len(fields) > 1 else None
    except OSError:
        return None
    return None
