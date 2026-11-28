import base64
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from spiffe_identity import ca as ca_mod, server
from spiffe_identity.nodes import (NodeError, NodeRegistry, attestation_method, canonical_json, confidence,
                                   evidence_selectors, fingerprint, validate_evidence)
from spiffe_identity.registry import Registry
from tests.helpers import events, make_gate

TOKEN = "t" * 40
TD = "test.local"
AUTH = "Bearer " + TOKEN
CD1, CD2 = "a" * 40, "b" * 40
RUBRIC = {"macos-se-node+codesign": "medium", "macos-codesign-parent": "low", "macos-se-node": "low", "mcp-config": "low"}
SERVER_TOOLS = {
    "server.entries.list": {}, "server.entries.create": {"spiffe_id_prefixes": [f"spiffe://{TD}/"]},
    "server.nodes.enroll": {"max_pending": 2}, "server.nodes.list": {}, "server.nodes.manage": {},
    "server.nodes.challenge": {},
    "server.svid.attested": {"spiffe_id_prefixes": [f"spiffe://{TD}/mac/"], "max_ttl_minutes": 30,
                             "require_hardened_runtime": True},
}


def pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def csr():
    k = ec.generate_private_key(ec.SECP256R1())
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(k, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def workload(cdhash=CD1, hardened=True, parent=None):
    w = {"signing_id": "com.example.mcp-client", "cdhash": cdhash, "hardened_runtime": hardened,
         "path": "/usr/local/bin/mcp-client"}
    if parent:
        w["parent"] = parent
    return w


# ---- unit --------------------------------------------------------------------------

def test_evidence_validation_rejects_bad_input():
    validate_evidence(workload())
    for bad in [{**workload(), "extra": 1}, {**workload(), "cdhash": "XYZ"}, {**workload(), "hardened_runtime": "yes"},
                {**workload(), "path": "relative/path"}, {**workload(), "team_id": "short"},
                {**workload(), "signing_id": "bad id with spaces"}]:
        with pytest.raises(NodeError):
            validate_evidence(bad)


def test_selectors_are_derived_by_the_server():
    sel = evidence_selectors("n1", validate_evidence(workload(parent={"signing_id": "com.anthropic.claudefordesktop", "team_id": "ABCDE12345"})))
    assert "node:id:n1" in sel and f"macos:cdhash:{CD1}" in sel and "macos:parent_team_id:ABCDE12345" in sel


@pytest.mark.parametrize("selectors, method", [
    (["node:id:n", f"macos:cdhash:{CD1}", "macos:hardened_runtime:true", "macos:signing_id:x"], "macos-se-node+codesign"),
    (["node:id:n", f"macos:cdhash:{CD1}", "macos:hardened_runtime:false"], "macos-se-node"),
    (["node:id:n", "macos:parent_team_id:ABCDE12345"], "macos-codesign-parent"),
    (["node:id:n"], "macos-se-node"),
    (["ai:mcp-config:/x", "ai:mcp-server:y"], "mcp-config"),
    (["k8s:ns:a", "k8s:sa:b"], "k8s-api"),
    (["weird:thing"], "unknown"),
])
def test_method_from_selectors(selectors, method):
    assert attestation_method(selectors) == method


def test_unlisted_methods_are_low():
    assert confidence("macos-se-node+codesign", RUBRIC) == "medium"
    assert confidence("docker-image", RUBRIC) == "low"      # not in this rubric -> low
    assert confidence("unknown", {}) == "low"


def test_nonce_single_use_and_bound_to_node(tmp_path):
    reg = NodeRegistry(None)
    k1, k2 = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    n1, _ = reg.enroll(pem(k1), {}, 5)
    n2, _ = reg.enroll(pem(k2), {}, 5)
    with pytest.raises(NodeError, match="pending"):
        reg.challenge(n1.id)
    reg.decide(n1.id, "approve", "me")
    reg.decide(n2.id, "approve", "me")
    nonce, _ = reg.challenge(n1.id)
    with pytest.raises(NodeError, match="different node"):
        reg.consume_nonce(nonce, n2.id)
    nonce, _ = reg.challenge(n1.id)
    reg.consume_nonce(nonce, n1.id)
    with pytest.raises(NodeError, match="already-used"):
        reg.consume_nonce(nonce, n1.id)


def test_registry_persists_and_limits_pending(tmp_path):
    reg = NodeRegistry(tmp_path / "nodes.json")
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    reg.enroll(pem(keys[0]), {"hostname": "mac"}, 2)
    reg.enroll(pem(keys[1]), {}, 2)
    with pytest.raises(NodeError, match="too many pending"):
        reg.enroll(pem(keys[2]), {}, 2)
    again, created = reg.enroll(pem(keys[0]), {}, 2)
    assert not created
    assert len(NodeRegistry(tmp_path / "nodes.json").list()) == 2
    with pytest.raises(NodeError):
        reg.enroll(pem(keys[2]), {"unknown_fact": "x"}, 5)
    rsa_pem = "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n"
    with pytest.raises(NodeError):
        reg.enroll(rsa_pem, {}, 5)


# ---- server flow ---------------------------------------------------------------------

@pytest.fixture()
def app(tmp_path):
    g = make_gate(tmp_path, SERVER_TOOLS, "server")
    g.policy.rubric = RUBRIC
    c = ca_mod.CertificateAuthority.create(TD, dt.timedelta(hours=2))
    return server.App(c, Registry(None, TD), TOKEN, dt.timedelta(minutes=60), dt.timedelta(minutes=5), g,
                      NodeRegistry(None), dt.timedelta(minutes=30))


def call(app, method, path, body=None, auth=AUTH):
    status, _, out = app.handle(method, path, auth, json.dumps(body).encode() if body is not None else b"")
    return status, json.loads(out)


def enroll_and_approve(app, key):
    st, node = call(app, "POST", "/v1/nodes/enroll", {"public_key": pem(key), "facts": {"touch_id_confirmed": True}})
    assert st == 201 and node["status"] == "pending"
    st, node = call(app, "POST", f"/v1/nodes/{node['id']}/approve", {"decided_by": "Esra"})
    assert st == 200 and node["status"] == "approved"
    return node["id"]


def signed(key, node_id, nonce, spiffe_id, wl):
    request = {"node_id": node_id, "nonce": nonce, "spiffe_id": spiffe_id, "csr": csr(), "workload": wl}
    return {"request": request, "signature": base64.b64encode(key.sign(canonical_json(request), ec.ECDSA(hashes.SHA256()))).decode()}


def attest(app, key, node_id, spiffe_id, wl):
    st, ch = call(app, "POST", "/v1/node/challenge", {"node_id": node_id}, auth=None)
    if st != 200:
        return st, ch
    return call(app, "POST", "/v1/node/svid", signed(key, node_id, ch["nonce"], spiffe_id, wl), auth=None)


def register(app, node_id, spiffe_id, cdhash=CD1):
    st, e = call(app, "POST", "/v1/entries", {"spiffe_id": spiffe_id, "approved_by": "Esra", "selectors": [
        f"node:id:{node_id}", "macos:signing_id:com.example.mcp-client", f"macos:cdhash:{cdhash}", "macos:hardened_runtime:true"]})
    assert st == 201 and e["extra"]["attestation"] == {"method": "macos-se-node+codesign", "confidence": "medium"}
    return e


def test_full_attested_flow_issues_a_30_minute_medium_svid(app):
    key = ec.generate_private_key(ec.SECP256R1())
    nid = enroll_and_approve(app, key)
    sid = f"spiffe://{TD}/mac/mcp-client"
    register(app, nid, sid)
    st, out = attest(app, key, nid, sid, workload())
    assert st == 200, out
    assert out["ttl_minutes"] == 30 and out["attestation"] == {"method": "macos-se-node+codesign", "confidence": "medium"}
    cert = x509.load_pem_x509_certificate(out["svid"].encode())
    life = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert dt.timedelta(minutes=29) < life <= dt.timedelta(minutes=31)
    assert str(ca_mod.verify_x509_svid(out["svid"].encode(), out["bundle"].encode())) == sid


def test_unapproved_or_revoked_nodes_get_nothing(app):
    key = ec.generate_private_key(ec.SECP256R1())
    st, node = call(app, "POST", "/v1/nodes/enroll", {"public_key": pem(key), "facts": {}})
    st, out = call(app, "POST", "/v1/node/challenge", {"node_id": node["id"]}, auth=None)
    assert st == 403 and "pending" in out["error"]
    call(app, "POST", f"/v1/nodes/{node['id']}/approve", {"decided_by": "Esra"})
    sid = f"spiffe://{TD}/mac/mcp-client"
    register(app, node["id"], sid)
    assert attest(app, key, node["id"], sid, workload())[0] == 200
    call(app, "POST", f"/v1/nodes/{node['id']}/revoke", {"decided_by": "Esra"})
    assert attest(app, key, node["id"], sid, workload())[0] == 403


def test_wrong_key_replay_and_tampering_are_refused(app):
    key, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    nid = enroll_and_approve(app, key)
    sid = f"spiffe://{TD}/mac/mcp-client"
    register(app, nid, sid)
    _, ch = call(app, "POST", "/v1/node/challenge", {"node_id": nid}, auth=None)
    st, out = call(app, "POST", "/v1/node/svid", signed(other, nid, ch["nonce"], sid, workload()), auth=None)
    assert st == 403 and "does not verify" in out["error"]
    body = signed(key, nid, ch["nonce"], sid, workload())
    assert call(app, "POST", "/v1/node/svid", body, auth=None)[0] == 200
    st, out = call(app, "POST", "/v1/node/svid", body, auth=None)              # replay
    assert st == 403 and "already-used" in out["error"]
    _, ch = call(app, "POST", "/v1/node/challenge", {"node_id": nid}, auth=None)
    body = signed(key, nid, ch["nonce"], sid, workload())
    body["request"]["workload"]["signing_id"] = "com.evil.tool"                 # tampered after signing
    assert call(app, "POST", "/v1/node/svid", body, auth=None)[0] == 403
    denied = [e for e in events(app.gate) if e.get("tool") == "server.node.auth"]
    assert denied and all("BEGIN" not in json.dumps(e) for e in denied)        # no key material traced


def test_policy_limits_apply_to_attested_issuance(app):
    key = ec.generate_private_key(ec.SECP256R1())
    nid = enroll_and_approve(app, key)
    outside = f"spiffe://{TD}/admin/x"
    call(app, "POST", "/v1/entries", {"spiffe_id": outside, "approved_by": "Esra", "selectors": [
        f"node:id:{nid}", "macos:signing_id:com.example.mcp-client", f"macos:cdhash:{CD1}", "macos:hardened_runtime:true"]})
    st, out = attest(app, key, nid, outside, workload())
    assert st == 403 and "prefixes" in out["error"]
    sid = f"spiffe://{TD}/mac/soft"
    call(app, "POST", "/v1/entries", {"spiffe_id": sid, "approved_by": "Esra", "selectors": [
        f"node:id:{nid}", "macos:signing_id:com.example.mcp-client", f"macos:cdhash:{CD1}"]})
    st, out = attest(app, key, nid, sid, workload(hardened=False))
    assert st == 403 and "Hardened Runtime" in out["error"]


def test_evidence_must_match_an_entry_for_this_node(app):
    key, key2 = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    nid, nid2 = enroll_and_approve(app, key), enroll_and_approve(app, key2)
    sid = f"spiffe://{TD}/mac/mcp-client"
    register(app, nid, sid)
    st, out = attest(app, key2, nid2, sid, workload())                          # same program, other device
    assert st == 403 and "no registration entry" in out["error"]
    wl = workload()
    wl["signing_id"] = "com.other.app"
    assert attest(app, key, nid, sid, wl)[0] == 403                            # other program, same device


def test_new_build_waits_for_approval_then_works(app):
    key = ec.generate_private_key(ec.SECP256R1())
    nid = enroll_and_approve(app, key)
    sid = f"spiffe://{TD}/mac/mcp-client"
    register(app, nid, sid, CD1)
    st, out = attest(app, key, nid, sid, workload(cdhash=CD2))
    assert st == 403 and "new build" in out["error"]
    st, builds = call(app, "GET", "/v1/builds")
    assert [(b["old_cdhash"], b["new_cdhash"]) for b in builds] == [(CD1, CD2)]
    st, res = call(app, "POST", f"/v1/builds/{builds[0]['id']}/approve", {"decided_by": "Esra"})
    assert st == 200 and f"macos:cdhash:{CD2}" in res["entry"]["selectors"]
    assert attest(app, key, nid, sid, workload(cdhash=CD2))[0] == 200
    assert attest(app, key, nid, sid, workload(cdhash=CD1))[0] == 200          # old build until its entry is revoked


def test_claude_desktop_parent_mode_is_low(app):
    key = ec.generate_private_key(ec.SECP256R1())
    nid = enroll_and_approve(app, key)
    sid = f"spiffe://{TD}/mac/stdio-server-under-claude"
    st, e = call(app, "POST", "/v1/entries", {"spiffe_id": sid, "approved_by": "Esra", "selectors": [
        f"node:id:{nid}", "macos:signing_id:com.example.mcp-client", f"macos:cdhash:{CD1}",
        "macos:parent_signing_id:com.anthropic.claudefordesktop", "macos:parent_team_id:ABCDE12345"]})
    assert e["extra"]["attestation"]["confidence"] == "low"
    st, out = attest(app, key, nid, sid, workload(parent={"signing_id": "com.anthropic.claudefordesktop", "team_id": "ABCDE12345"}))
    assert st == 200 and out["attestation"] == {"method": "macos-codesign-parent", "confidence": "low"}
    st, out = attest(app, key, nid, sid, workload(parent={"signing_id": "com.evil.launcher"}))
    assert st == 403


def test_node_tools_need_the_policy(tmp_path):
    g = make_gate(tmp_path, {"server.entries.list": {}}, "server")
    c = ca_mod.CertificateAuthority.create(TD, dt.timedelta(hours=1))
    a = server.App(c, Registry(None, TD), TOKEN, dt.timedelta(minutes=5), dt.timedelta(minutes=5), g, NodeRegistry(None))
    key = ec.generate_private_key(ec.SECP256R1())
    st, out = call(a, "POST", "/v1/nodes/enroll", {"public_key": pem(key), "facts": {}})
    assert st == 403 and "not listed" in out["error"]
    st, out = call(a, "POST", "/v1/node/challenge", {"node_id": fingerprint(key.public_key())}, auth=None)
    assert st == 403


def test_policy_rejects_bad_rubric_and_attested_limits():
    from spiffe_identity.toolpolicy import ToolPolicy, ToolPolicyError
    base = {"version": 1, "default": "deny", "trace": {"file": "t"}, "tools": {}}
    with pytest.raises(ToolPolicyError, match="unknown method"):
        ToolPolicy.from_dict({**base, "attestation_rubric": {"made-up": "high"}})
    with pytest.raises(ToolPolicyError, match="must be one of"):
        ToolPolicy.from_dict({**base, "attestation_rubric": {"mcp-config": "very-high"}})
    with pytest.raises(ToolPolicyError, match="require_hardened_runtime"):
        ToolPolicy.from_dict({**base, "tools": {"server.svid.attested": {"spiffe_id_prefixes": ["spiffe://td/"], "max_ttl_minutes": 30}}})
