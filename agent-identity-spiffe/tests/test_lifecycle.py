import base64
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from spiffe_identity import ca as ca_mod, server
from spiffe_identity.ca import DELEGATION_OID, jwt_claims_unverified
from spiffe_identity.lifecycle import (GrantStore, IdentityRevoked, IssuanceLog, LifecycleError, RevocationChecker,
                                       RevocationStore, RevocationUnavailable, scope_type)
from spiffe_identity.nodes import NodeRegistry, canonical_json
from spiffe_identity.registry import Registry
from tests.helpers import events, make_gate

TOKEN = "t" * 40
AUTH = "Bearer " + TOKEN
TD = "test.local"
SID = f"spiffe://{TD}/agent/triage"
TOOLS = {
    "server.entries.list": {}, "server.entries.create": {"spiffe_id_prefixes": [f"spiffe://{TD}/"]},
    "server.svid.x509": {"spiffe_id_prefixes": [f"spiffe://{TD}/"]},
    "server.svid.jwt": {"spiffe_id_prefixes": [f"spiffe://{TD}/"], "audiences": ["ticket-api"]},
    "server.svid.list_issued": {},
    "server.svid.revoke": {"reasons": ["key_compromise", "superseded"]},
    "server.grants.create": {"max_grant_minutes": 60, "allowed_scope_types": ["tool", "data:path"]},
    "server.grants.list": {}, "server.grants.withdraw": {},
}


def csr():
    k = ec.generate_private_key(ec.SECP256R1())
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(k, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture()
def app(tmp_path):
    g = make_gate(tmp_path, TOOLS, "server")
    c = ca_mod.CertificateAuthority.create(TD, dt.timedelta(hours=2))
    a = server.App(c, Registry(None, TD), TOKEN, dt.timedelta(minutes=60), dt.timedelta(minutes=30), g, NodeRegistry(None),
                   None, IssuanceLog(tmp_path / "issued.jsonl"), RevocationStore(tmp_path / "rev.json"),
                   GrantStore(tmp_path / "grants.json"), dt.timedelta(minutes=5))
    st, _ = call(a, "POST", "/v1/entries", {"spiffe_id": SID, "selectors": ["ai:agent-name:triage"], "approved_by": "Esra"})
    assert st == 201
    return a


def call(app, method, path, body=None, auth=AUTH):
    status, ctype, out = app.handle(method, path, auth, json.dumps(body).encode() if body is not None else b"")
    return status, (json.loads(out) if ctype == "application/json" else out)


def checker(app):
    return RevocationChecker(app.ca.cert, app.ca.jwks(), refresh_seconds=60,
                             fetch_crl=lambda: call(app, "GET", "/v1/crl", auth=None)[1],
                             fetch_jwt_list=lambda: call(app, "GET", "/v1/revoked-jwt", auth=None)[1].decode())


# ---- issuance log + revocation ---------------------------------------------------------

def test_issuance_is_logged_without_key_material(app, tmp_path):
    st, out = call(app, "POST", "/v1/svid/x509", {"spiffe_id": SID, "csr": csr()})
    assert st == 200 and out["serial"]
    st, tok = call(app, "POST", "/v1/svid/jwt", {"spiffe_id": SID, "audience": ["ticket-api"]})
    assert jwt_claims_unverified(tok["token"])["jti"] == tok["jti"]
    st, rows = call(app, "GET", "/v1/svids")
    assert {(r["kind"], r["ident"]) for r in rows} == {("x509", out["serial"]), ("jwt", tok["jti"])}
    raw = (tmp_path / "issued.jsonl").read_text()
    assert "BEGIN" not in raw and tok["token"] not in raw


def test_revoked_certificate_is_rejected_by_verifiers(app):
    st, out = call(app, "POST", "/v1/svid/x509", {"spiffe_id": SID, "csr": csr()})
    chk = checker(app)
    chk.check_x509(out["svid"].encode())                     # not revoked yet
    st, rev = call(app, "POST", "/v1/svids/revoke", {"kind": "x509", "ident": out["serial"], "reason": "key_compromise",
                                                     "revoked_by": "Esra", "note": "laptop stolen"})
    assert st == 201 and rev["created"]
    chk.refresh(force=True)
    with pytest.raises(IdentityRevoked):
        chk.check_x509(out["svid"].encode())
    crl = x509.load_der_x509_crl(call(app, "GET", "/v1/crl", auth=None)[1])
    entry = crl.get_revoked_certificate_by_serial_number(int(out["serial"], 16))
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.key_compromise
    assert crl.is_signature_valid(app.ca.cert.public_key())
    assert call(app, "POST", "/v1/svids/revoke", {"kind": "x509", "ident": out["serial"], "reason": "key_compromise",
                                                  "revoked_by": "Esra"})[1]["created"] is False   # idempotent


def test_revoked_jwt_is_rejected(app):
    st, tok = call(app, "POST", "/v1/svid/jwt", {"spiffe_id": SID, "audience": ["ticket-api"]})
    chk = checker(app)
    chk.check_jwt(tok["jti"])
    call(app, "POST", "/v1/svids/revoke", {"kind": "jwt", "ident": tok["jti"], "reason": "superseded", "revoked_by": "Esra"})
    chk.refresh(force=True)
    with pytest.raises(IdentityRevoked):
        chk.check_jwt(tok["jti"])


def test_revocation_rules(app):
    st, out = call(app, "POST", "/v1/svid/x509", {"spiffe_id": SID, "csr": csr()})
    st, err = call(app, "POST", "/v1/svids/revoke", {"kind": "x509", "ident": out["serial"], "reason": "device_lost", "revoked_by": "Esra"})
    assert st == 403 and "isn't allowed by the policy" in err["error"]       # reason not in this policy
    st, err = call(app, "POST", "/v1/svids/revoke", {"kind": "x509", "ident": "deadbeef", "reason": "superseded", "revoked_by": "Esra"})
    assert st == 400 and "no identity" in err["error"]
    st, err = call(app, "POST", "/v1/svids/revoke", {"kind": "x509", "ident": out["serial"], "reason": "superseded", "revoked_by": ""})
    assert st == 400
    assert call(app, "POST", "/v1/svids/revoke", {"kind": "x509", "ident": out["serial"], "reason": "superseded",
                                                  "revoked_by": "Esra"}, auth="Bearer wrong" + "x" * 40)[0] == 401


def test_verifiers_fail_closed(app):
    st, out = call(app, "POST", "/v1/svid/x509", {"spiffe_id": SID, "csr": csr()})
    cert = out["svid"].encode()
    nolist = RevocationChecker(app.ca.cert, app.ca.jwks(), refresh_seconds=60)
    with pytest.raises(RevocationUnavailable, match="no revocation list"):
        nolist.check_x509(cert)
    down = RevocationChecker(app.ca.cert, app.ca.jwks(), refresh_seconds=60, fetch_crl=lambda: (_ for _ in ()).throw(OSError("server down")))
    with pytest.raises(RevocationUnavailable, match="server down"):
        down.check_x509(cert)
    chk = checker(app)
    chk.refresh(force=True)
    chk.clock = lambda: __import__("time").time() + 6 * 60   # past the 5-minute validity, refresh fails
    chk.fetch_crl = lambda: (_ for _ in ()).throw(OSError("server down"))
    with pytest.raises(RevocationUnavailable, match="expired"):
        chk.check_x509(cert)
    other = ca_mod.CertificateAuthority.create(TD, dt.timedelta(hours=1))
    forged = RevocationStore(None).crl_der(other, dt.timedelta(minutes=5))
    with pytest.raises(RevocationUnavailable, match="isn't signed"):
        RevocationChecker(app.ca.cert, app.ca.jwks(), refresh_seconds=60).load_crl(forged)


def test_older_list_is_refused(app):
    chk = RevocationChecker(app.ca.cert, app.ca.jwks(), refresh_seconds=60)
    old = call(app, "GET", "/v1/crl", auth=None)[1]
    import time
    time.sleep(0.01)
    chk.load_crl(call(app, "GET", "/v1/crl", auth=None)[1])
    with pytest.raises(RevocationUnavailable, match="older"):
        chk.load_crl(old)


def test_lists_are_public_but_need_revocation_enabled(tmp_path):
    g = make_gate(tmp_path, {}, "server")
    c = ca_mod.CertificateAuthority.create(TD, dt.timedelta(hours=1))
    a = server.App(c, Registry(None, TD), TOKEN, dt.timedelta(minutes=5), dt.timedelta(minutes=5), g)
    assert a.handle("GET", "/v1/crl", None, b"")[0] == 404


# ---- delegation --------------------------------------------------------------------------

def grant(app, minutes=30, scopes=("tool:filesystem.read_file", "data:path:~/Projects/transform/**"), agent=SID):
    return call(app, "POST", "/v1/grants", {"principal": "Esra", "agent_spiffe_id": agent, "scopes": list(scopes),
                                            "minutes": minutes, "created_by": "Esra"})


def test_scope_types():
    assert scope_type("tool:filesystem.read_file") == "tool"
    assert scope_type("data:path:~/x/**") == "data:path"
    assert scope_type("data:host:api.example.com") == "data:host"
    for bad in ("tool:noserver", "data:path:", "files:everything", "data:host:bad host"):
        with pytest.raises(LifecycleError):
            scope_type(bad)


def test_grant_limits(app):
    assert grant(app, minutes=61)[0] == 403                                   # policy max 60
    st, err = grant(app, scopes=("data:host:api.example.com",))
    assert st == 403 and "scope type" in err["error"]                         # type not allowed here
    st, err = grant(app, agent=f"spiffe://{TD}/agent/unregistered")
    assert st == 400 and "registration entry" in err["error"]
    st, g = grant(app)
    assert st == 201 and g["principal_verified"] is False and g["state"] == "active"


def test_delegated_identities_carry_the_grant_and_never_outlive_it(app):
    st, g = grant(app, minutes=10)
    st, out = call(app, "POST", "/v1/svid/x509", {"spiffe_id": SID, "csr": csr(), "delegation": {"grant": g["id"]}})
    assert st == 200
    cert = x509.load_pem_x509_certificate(out["svid"].encode())
    ext = cert.extensions.get_extension_for_oid(DELEGATION_OID)
    assert not ext.critical
    claim = json.loads(ext.value.value)
    assert claim["principal"] == "Esra" and claim["principal_verified"] is False and claim["grant"] == g["id"]
    assert cert.not_valid_after_utc <= dt.datetime.fromisoformat(g["not_after"]) + dt.timedelta(seconds=1)  # capped at grant end
    st, tok = call(app, "POST", "/v1/svid/jwt", {"spiffe_id": SID, "audience": ["ticket-api"],
                                                 "delegation": {"grant": g["id"], "scopes": ["tool:filesystem.read_file"]}})
    claims = jwt_claims_unverified(tok["token"])
    assert claims["sub"] == SID and claims["del"]["scopes"] == ["tool:filesystem.read_file"]
    st, rows = call(app, "GET", "/v1/svids")
    assert all(r["delegation"]["principal"] == "Esra" for r in rows)


def test_delegation_cannot_be_widened_or_borrowed(app):
    st, g = grant(app)
    st, err = call(app, "POST", "/v1/svid/jwt", {"spiffe_id": SID, "audience": ["ticket-api"],
                                                 "delegation": {"grant": g["id"], "scopes": ["tool:shell.exec"]}})
    assert st == 400 and "not in the grant" in err["error"]
    call(app, "POST", "/v1/entries", {"spiffe_id": f"spiffe://{TD}/agent/other", "selectors": ["a:b"], "approved_by": "Esra"})
    st, err = call(app, "POST", "/v1/svid/jwt", {"spiffe_id": f"spiffe://{TD}/agent/other", "audience": ["ticket-api"],
                                                 "delegation": {"grant": g["id"]}})
    assert st == 400 and "different agent" in err["error"]
    st, err = call(app, "POST", "/v1/svid/jwt", {"spiffe_id": SID, "audience": ["ticket-api"], "delegation": {"grant": "g_nope"}})
    assert st == 400 and "unknown" in err["error"]


def test_withdrawn_grant_stops_new_delegated_identities(app):
    st, g = grant(app)
    st, w = call(app, "POST", f"/v1/grants/{g['id']}/withdraw", {"withdrawn_by": "Esra"})
    assert w["state"] == "withdrawn"
    st, err = call(app, "POST", "/v1/svid/jwt", {"spiffe_id": SID, "audience": ["ticket-api"], "delegation": {"grant": g["id"]}})
    assert st == 400 and "withdrawn" in err["error"]
    # service identities are still allowed (owner decision)
    assert call(app, "POST", "/v1/svid/jwt", {"spiffe_id": SID, "audience": ["ticket-api"]})[0] == 200


def test_attested_requests_can_carry_signed_delegation(tmp_path):
    tools = {**TOOLS, "server.nodes.enroll": {"max_pending": 2}, "server.nodes.list": {}, "server.nodes.manage": {},
             "server.nodes.challenge": {}, "server.svid.attested": {"spiffe_id_prefixes": [f"spiffe://{TD}/mac/"],
                                                                     "max_ttl_minutes": 30, "require_hardened_runtime": True}}
    g = make_gate(tmp_path, tools, "server")
    c = ca_mod.CertificateAuthority.create(TD, dt.timedelta(hours=2))
    a = server.App(c, Registry(None, TD), TOKEN, dt.timedelta(minutes=60), dt.timedelta(minutes=30), g, NodeRegistry(None),
                   dt.timedelta(minutes=30), IssuanceLog(None), RevocationStore(None), GrantStore(None), dt.timedelta(minutes=5))
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    nid = call(a, "POST", "/v1/nodes/enroll", {"public_key": pem, "facts": {}})[1]["id"]
    call(a, "POST", f"/v1/nodes/{nid}/approve", {"decided_by": "Esra"})
    sid = f"spiffe://{TD}/mac/client"
    call(a, "POST", "/v1/entries", {"spiffe_id": sid, "approved_by": "Esra", "selectors": [
        f"node:id:{nid}", "macos:signing_id:com.example.c", "macos:cdhash:" + "a" * 40, "macos:hardened_runtime:true"]})
    gr = call(a, "POST", "/v1/grants", {"principal": "Esra", "agent_spiffe_id": sid, "scopes": ["tool:fs.read"],
                                        "minutes": 20, "created_by": "Esra"})[1]
    nonce = call(a, "POST", "/v1/node/challenge", {"node_id": nid}, auth=None)[1]["nonce"]
    req = {"node_id": nid, "nonce": nonce, "spiffe_id": sid, "csr": csr(), "delegation": {"grant": gr["id"]},
           "workload": {"signing_id": "com.example.c", "cdhash": "a" * 40, "hardened_runtime": True, "path": "/bin/c"}}
    sig = base64.b64encode(key.sign(canonical_json(req), ec.ECDSA(hashes.SHA256()))).decode()
    st, out = call(a, "POST", "/v1/node/svid", {"request": req, "signature": sig}, auth=None)
    assert st == 200 and out["delegation"]["principal"] == "Esra"
    assert any(e.get("summary", {}).get("delegated_for") == "Esra" for e in events(g))


def test_policy_validation_for_new_tools():
    from spiffe_identity.toolpolicy import ToolPolicy, ToolPolicyError
    base = {"version": 1, "default": "deny", "trace": {"file": "t"}}
    with pytest.raises(ToolPolicyError, match="unknown reason"):
        ToolPolicy.from_dict({**base, "tools": {"server.svid.revoke": {"reasons": ["oops"]}}})
    with pytest.raises(ToolPolicyError, match="unknown scope type"):
        ToolPolicy.from_dict({**base, "tools": {"server.grants.create": {"max_grant_minutes": 60, "allowed_scope_types": ["files"]}}})
