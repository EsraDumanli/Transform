"""Discover pods through the Kubernetes REST API (read-only: GET .../pods).

Needs "list pods" RBAC permission in each namespace you name. Every value that
would otherwise be guessed (which cluster, which namespaces, which credentials)
is explicit in the config.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.parse
import urllib.request

from .base import KIND_K8S_POD, ConfigError, Workload

SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


class Kubernetes:
    name = "kubernetes"

    def __init__(self, cfg: dict, opener=None):
        self.namespaces = cfg.get("namespaces") or []
        self.timeout = cfg.get("timeout_seconds")
        self.label_keys = sorted(cfg.get("label_selector_keys") or [])
        self.in_cluster = bool(cfg.get("in_cluster"))
        self.api_server = (cfg.get("api_server") or "").rstrip("/")
        self.token_file = cfg.get("token_file") or ""
        self.ca_file = cfg.get("ca_file") or ""
        self._opener = opener
        if not self.namespaces:
            raise ConfigError('kubernetes: namespaces is required (use ["*"] to ask for every namespace)')
        if not (isinstance(self.timeout, (int, float)) and self.timeout > 0):
            raise ConfigError("kubernetes: timeout_seconds must be > 0")
        if self.in_cluster:
            host, port = os.environ.get("KUBERNETES_SERVICE_HOST"), os.environ.get("KUBERNETES_SERVICE_PORT")
            if not host or not port:
                raise ConfigError("kubernetes: in_cluster is set but KUBERNETES_SERVICE_HOST/PORT are not; are you running in a pod?")
            self.api_server, self.token_file, self.ca_file = f"https://{host}:{port}", SA_TOKEN, SA_CA
        if not (self.api_server and self.token_file and self.ca_file):
            raise ConfigError("kubernetes: set in_cluster, or all of api_server, token_file and ca_file")

    def _get(self, url: str, token: str) -> dict:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        if self._opener:
            resp = self._opener(req, timeout=self.timeout)
        else:
            ctx = ssl.create_default_context(cafile=self.ca_file)
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
        with resp:
            return json.loads(resp.read())

    def discover(self) -> tuple[list[Workload], list[str]]:
        with open(self.token_file) as f:
            token = f.read().strip()
        out, warns = [], []
        for ns in self.namespaces:
            path = "/api/v1/pods" if ns == "*" else f"/api/v1/namespaces/{urllib.parse.quote(ns, safe='')}/pods"
            try:
                data = self._get(self.api_server + path, token)
            except Exception as e:  # noqa: BLE001
                warns.append(f"kubernetes: namespace {ns}: {e}")
                continue
            out += [self._workload(p) for p in data.get("items", [])]
        return out, warns

    def _workload(self, pod: dict) -> Workload:
        md, spec = pod.get("metadata", {}), pod.get("spec", {})
        ns, name, sa = md.get("namespace", ""), md.get("name", ""), spec.get("serviceAccountName", "")
        labels = md.get("labels") or {}
        attrs = {
            "namespace": ns, "pod": name, "uid": md.get("uid", ""), "service_account": sa,
            "node": spec.get("nodeName", ""), "phase": pod.get("status", {}).get("phase", ""),
            "images": ",".join(sorted(c.get("image", "") for c in spec.get("containers", []))),
        }
        attrs.update({f"label.{k}": str(v) for k, v in labels.items()})
        sel = [f"k8s:ns:{ns}"]
        if sa:
            sel.append(f"k8s:sa:{sa}")
        sel += [f"k8s:pod-label:{k}:{labels[k]}" for k in self.label_keys if k in labels]
        return Workload(source="kubernetes", kind=KIND_K8S_POD, name=f"{ns}/{name}", attributes=attrs, selectors=sel)
