"""One trace file for every action and log message.

Every event is one JSON line in the trace file named by the tool policy
(``trace.file``). Events share a ``trace_id`` per run (one CLI command, one
portal action, or one server request), and each action has a ``span_id`` that
links its policy decision to its result. The agent sends its trace_id to the
identity server in an ``X-Trace-Id`` header, so server-side events join the
same trace.

Event types
-----------
``run.start`` / ``run.end``   a command, portal action or server request began / ended
``action.decision``           the tool policy allowed or denied an action (with the reason)
``action.result``             an allowed action finished: ``ok`` or ``error``, and duration
``log``                       an ordinary log message from the program

What is never written: tokens, API keys, private keys, CSRs, resume text or
other workload attribute values. Actions record only the facts the policy was
checked against (a folder, a host, a SPIFFE ID, a count).

Several processes (agent, portal, server) may append to the same file. Each
event is written with a single ``write()`` on a file opened with ``O_APPEND``,
which keeps lines whole on local filesystems for events of this size.
If the trace can't be written, the action is refused (fail closed).
"""

from __future__ import annotations

import contextvars
import datetime as dt
import getpass
import json
import logging
import os
import re
import secrets
import threading
from pathlib import Path

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_current_trace: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")


class TraceError(RuntimeError):
    """The trace file could not be written."""


def new_trace_id() -> str:
    return secrets.token_hex(16)


def valid_trace_id(value: str) -> bool:
    return bool(_TRACE_ID_RE.match(value or ""))


def current_trace_id() -> str:
    return _current_trace.get()


def set_trace_id(trace_id: str) -> contextvars.Token:
    return _current_trace.set(trace_id)


def reset_trace_id(token: contextvars.Token) -> None:
    _current_trace.reset(token)


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name available (e.g. some containers)
        return ""


class TraceWriter:
    """Appends JSON events to the trace file. Thread-safe within a process."""

    def __init__(self, path: str | os.PathLike, component: str):
        self.path = Path(path)
        self.component = component
        self.pid = os.getpid()
        self.os_user = _os_user()
        self._lock = threading.Lock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.close(fd)
        except OSError as e:
            raise TraceError(f"cannot write trace file {self.path}: {e}") from e

    def emit(self, event: str, **fields) -> dict:
        record = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            "component": self.component,
            "trace_id": fields.pop("trace_id", None) or current_trace_id(),
            "pid": self.pid,
            "os_user": self.os_user,
            **fields,
        }
        line = (json.dumps(record, default=str, separators=(",", ":")) + "\n").encode()
        with self._lock:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND)
                try:
                    os.write(fd, line)
                finally:
                    os.close(fd)
            except OSError as e:
                raise TraceError(f"cannot write trace file {self.path}: {e}") from e
        return record


class TraceLogHandler(logging.Handler):
    """Sends ordinary log messages into the trace as ``log`` events."""

    def __init__(self, writer: TraceWriter, level=logging.INFO):
        super().__init__(level)
        self.writer = writer

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.writer.emit("log", level=record.levelname, logger=record.name, message=record.getMessage())
        except TraceError:
            self.handleError(record)


def attach_logging(writer: TraceWriter, level=logging.INFO) -> TraceLogHandler:
    handler = TraceLogHandler(writer, level)
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level > level or root.level == logging.NOTSET:
        root.setLevel(level)
    return handler


def read_events(path: str | os.PathLike) -> list[dict]:
    events = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"event": "unreadable", "line": n})
    return events
