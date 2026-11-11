"""Discover running containers through the Docker Engine API (read-only: GET /containers/json)."""

from __future__ import annotations

import http.client
import json
import socket

from .base import KIND_CONTAINER, ConfigError, Workload


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.socket_path)
        self.sock = s


class Docker:
    name = "docker"

    def __init__(self, cfg: dict, fetch=None):
        self.socket = cfg.get("socket") or ""
        self.timeout = cfg.get("timeout_seconds")
        self.label_keys = sorted(cfg.get("label_selector_keys") or [])
        self._fetch = fetch or self._fetch_socket
        if not self.socket:
            raise ConfigError("docker: socket is required (e.g. /var/run/docker.sock)")
        if not (isinstance(self.timeout, (int, float)) and self.timeout > 0):
            raise ConfigError("docker: timeout_seconds must be > 0")

    def _fetch_socket(self) -> list:
        conn = _UnixHTTPConnection(self.socket, self.timeout)
        try:
            conn.request("GET", "/containers/json")
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200:
                raise RuntimeError(f"docker: HTTP {resp.status}: {body[:300]!r}")
            return json.loads(body)
        finally:
            conn.close()

    def discover(self) -> tuple[list[Workload], list[str]]:
        out = []
        for c in self._fetch():
            names = c.get("Names") or []
            name = names[0].lstrip("/") if names else c.get("Id", "")
            labels = c.get("Labels") or {}
            attrs = {
                "container_id": c.get("Id", ""), "container_name": name, "image": c.get("Image", ""),
                "image_id": c.get("ImageID", ""), "state": c.get("State", ""),
            }
            attrs.update({f"label.{k}": str(v) for k, v in labels.items()})
            sel = [f"docker:image_id:{c.get('ImageID', '')}"]
            sel += [f"docker:label:{k}:{labels[k]}" for k in self.label_keys if k in labels]
            out.append(Workload(source="docker", kind=KIND_CONTAINER, name=name, attributes=attrs, selectors=sel))
        return out, []
