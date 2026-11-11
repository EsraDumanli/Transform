"""Discover local processes.

Two methods; pick one explicitly with ``method``:

* ``"procfs"`` (Linux): reads ``<proc_root>/<pid>/{comm,exe,cmdline,status}``.
  ``proc_root`` is required, normally ``"/proc"``.
* ``"ps"`` (macOS, also works on Linux): runs ``ps -axww -o ...`` twice, once
  for pid/uid/executable and once for the full command line.

``include`` is required: listing every process on a machine is noise, and
picking "interesting" ones on your behalf would be a guess.
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
from pathlib import Path

from .base import KIND_PROCESS, ConfigError, Workload

METHODS = ("procfs", "ps")


def _run_ps(fields: str) -> str:
    return subprocess.run(
        ["ps", "-axww", "-o", fields], capture_output=True, text=True, check=True, timeout=30
    ).stdout


class Processes:
    name = "processes"

    def __init__(self, cfg: dict, run_ps=_run_ps):
        self.method = cfg.get("method") or ""
        self.include = cfg.get("include") or []
        self.cmdline_contains = cfg.get("cmdline_contains") or []
        self.proc_root = cfg.get("proc_root") or ""
        self._run_ps = run_ps
        if self.method not in METHODS:
            raise ConfigError('processes: method is required: "procfs" (Linux) or "ps" (macOS, also works on Linux)')
        if not self.include:
            raise ConfigError("processes: include patterns are required, e.g. [\"python*\", \"node\"]")
        if self.method == "procfs" and not self.proc_root:
            raise ConfigError('processes: proc_root is required with method "procfs" (normally "/proc")')

    def discover(self) -> tuple[list[Workload], list[str]]:
        if self.method == "ps":
            return self._discover_ps()
        return self._discover_procfs()

    # ---- shared ---------------------------------------------------------------

    def _matches(self, comm: str, exe: str) -> bool:
        names = [comm] + ([os.path.basename(exe)] if exe else [])
        return any(fnmatch.fnmatchcase(n, pat) for pat in self.include for n in names)

    def _cmdline_ok(self, cmdline: str) -> bool:
        return not self.cmdline_contains or any(s in cmdline for s in self.cmdline_contains)

    @staticmethod
    def _workload(pid: str, uid: str, comm: str, exe: str, cmdline: str) -> Workload:
        attrs = {"pid": pid, "uid": uid, "comm": comm, "cmdline": cmdline}
        sel = [f"unix:uid:{uid}", f"unix:comm:{comm}"]
        if exe:
            attrs["exe"] = exe
            sel.append(f"unix:path:{exe}")
        return Workload(source="processes", kind=KIND_PROCESS, name=f"{comm}[{pid}]", attributes=attrs, selectors=sel)

    # ---- procfs (Linux) -------------------------------------------------------

    def _discover_procfs(self) -> tuple[list[Workload], list[str]]:
        root = Path(self.proc_root)
        if not root.is_dir():
            raise OSError(f'processes: {root} does not exist (procfs is Linux-only; on macOS use method "ps")')
        out, warns = [], []
        unreadable_exe = 0
        for entry in root.iterdir():
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
            if not self._cmdline_ok(cmdline):
                continue
            uid = _read_uid(entry / "status")
            if uid is None:
                warns.append(f"processes: pid {entry.name}: could not read Uid")
                continue
            if not exe:
                unreadable_exe += 1
            out.append(self._workload(entry.name, uid, comm, exe, cmdline))
        if unreadable_exe:
            warns.append(
                f"processes: could not read the executable path of {unreadable_exe} matching process(es) "
                "(usually needs the same user or root); their selectors are weaker"
            )
        return out, warns

    # ---- ps (macOS) -----------------------------------------------------------

    def _discover_ps(self) -> tuple[list[Workload], list[str]]:
        # comm is the last column, so everything after pid and uid is the
        # executable, even when the path contains spaces ("Google Chrome.app").
        execs: dict[str, tuple[str, str]] = {}
        for line in self._run_ps("pid=,uid=,comm=").splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3 and parts[0].isdigit():
                execs[parts[0]] = (parts[1], parts[2])
        args: dict[str, str] = {}
        for line in self._run_ps("pid=,args=").splitlines():
            parts = line.strip().split(None, 1)
            if parts and parts[0].isdigit():
                args[parts[0]] = parts[1] if len(parts) > 1 else ""

        out, warns = [], []
        relative = 0
        for pid, (uid, comm_col) in execs.items():
            # macOS prints the executable path in comm; Linux prints a short name.
            exe = comm_col if comm_col.startswith("/") else ""
            comm = os.path.basename(comm_col) if exe else comm_col
            if not self._matches(comm, exe):
                continue
            cmdline = args.get(pid, "")
            if not self._cmdline_ok(cmdline):
                continue
            if not exe:
                relative += 1
            out.append(self._workload(pid, uid, comm, exe, cmdline))
        if relative:
            warns.append(
                f"processes: ps gave no absolute executable path for {relative} matching process(es); "
                "their selectors are weaker"
            )
        return out, warns


def _read_uid(path: Path) -> str | None:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("Uid:"):
                fields = line.split()
                return fields[1] if len(fields) > 1 else None
    except OSError:
        return None
    return None
