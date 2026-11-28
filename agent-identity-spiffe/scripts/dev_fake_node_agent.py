#!/usr/bin/env python3
"""TEST ONLY: a stand-in for the Swift node agent, using a SOFTWARE key.

It speaks the same wire protocol as the real agent (ATTESTATION-MACOS.md,
section 11), so the server, portal and policy can be exercised without a Mac.
It is NOT attestation: the key is a file on disk, not in a Secure Enclave,
and the "workload evidence" is whatever you type on the command line. Every
enrollment it makes is marked `software_key_test_only: true`, and the portal
shows that in red. Never approve such a device for anything real.

  python scripts/dev_fake_node_agent.py enroll --config examples/demo.config.json --key out/fake-node.pem
  python scripts/dev_fake_node_agent.py svid   --config examples/demo.config.json --key out/fake-node.pem \\
      --spiffe-id spiffe://demo.local/mac/my-mcp-client --signing-id com.example.mcp-client \\
      --cdhash <40 hex chars> --hardened-runtime --path /usr/local/bin/my-mcp-client --out out/attested
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from spiffe_identity import config as config_mod  # noqa: E402
from spiffe_identity.nodes import canonical_json, fingerprint, short_code  # noqa: E402


def post(cfg, path, body, token=None):
    c = cfg["client"]
    ctx = ssl.create_default_context(cafile=config_mod.resolve_path(cfg, c["bundle_file"]))
    req = urllib.request.Request(c["server_url"].rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"server said HTTP {e.code}: {e.read().decode(errors='replace')}")


def load_or_create_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--config", required=True)
    e.add_argument("--key", required=True, help="where the TEST software key is kept")
    s = sub.add_parser("svid")
    s.add_argument("--config", required=True)
    s.add_argument("--key", required=True)
    s.add_argument("--spiffe-id", required=True)
    s.add_argument("--signing-id", required=True)
    s.add_argument("--team-id")
    s.add_argument("--cdhash", required=True)
    s.add_argument("--hardened-runtime", action="store_true")
    s.add_argument("--path", required=True)
    s.add_argument("--parent-signing-id")
    s.add_argument("--parent-team-id")
    s.add_argument("--grant", help="issue under this delegation grant")
    s.add_argument("--scope", action="append", help="subset of the grant's scopes")
    s.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    cfg = config_mod.load(a.config)
    key = load_or_create_key(Path(a.key))
    node_id = fingerprint(key.public_key())

    if a.cmd == "enroll":
        token = os.environ.get(cfg["client"]["admin_token_env"], "")
        if not token:
            sys.exit(f"set {cfg['client']['admin_token_env']} (enrollment uses the admin token, plus portal approval)")
        pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        node = post(cfg, "/v1/nodes/enroll", {"public_key": pem, "facts": {
            "hostname": "test-machine", "software_key_test_only": True, "touch_id_confirmed": False}}, token)
        print(f"TEST device enrolled as {node['status']}. Compare this code in the portal: {short_code(node_id)}")
        return 0

    nonce = post(cfg, "/v1/node/challenge", {"node_id": node_id})["nonce"]
    wkey = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(wkey, hashes.SHA256())
    workload = {"signing_id": a.signing_id, "cdhash": a.cdhash, "hardened_runtime": a.hardened_runtime, "path": a.path}
    if a.team_id:
        workload["team_id"] = a.team_id
    if a.parent_signing_id:
        workload["parent"] = {"signing_id": a.parent_signing_id, **({"team_id": a.parent_team_id} if a.parent_team_id else {})}
    request = {"node_id": node_id, "nonce": nonce, "spiffe_id": a.spiffe_id,
               "csr": csr.public_bytes(serialization.Encoding.PEM).decode(), "workload": workload}
    if a.grant:
        request["delegation"] = {"grant": a.grant, **({"scopes": a.scope} if a.scope else {})}
    sig = base64.b64encode(key.sign(canonical_json(request), ec.ECDSA(hashes.SHA256()))).decode()
    resp = post(cfg, "/v1/node/svid", {"request": request, "signature": sig})
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "svid.pem").write_text(resp["svid"])
    (out / "bundle.pem").write_text(resp["bundle"])
    fd = os.open(out / "svid-key.pem", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(wkey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    d = resp.get("delegation")
    print(f"attested SVID for {a.spiffe_id}: serial {resp['serial']}, {resp['attestation']['method']} → {resp['attestation']['confidence']}"
          + (f", acting for {d['principal']} (unverified) with {d['scopes']}" if d else ", service identity"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
