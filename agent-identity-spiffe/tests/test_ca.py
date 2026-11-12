import datetime as dt
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from spiffe_identity import ca as ca_mod, spiffeid
from spiffe_identity.ca import CAError, CertificateAuthority

TD = "test.local"


@pytest.fixture(scope="module")
def ca():
    return CertificateAuthority.create(TD, dt.timedelta(hours=1))


def csr_pem(sans=()):
    key = ec.generate_private_key(ec.SECP256R1())
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(s) for s in sans]), critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def test_x509_svid_shape_and_verify(ca):
    sid = spiffeid.parse(f"spiffe://{TD}/ai-agent/triage")
    pem = ca.issue_x509_svid(csr_pem(), sid, dt.timedelta(minutes=5))
    cert = x509.load_pem_x509_certificate(pem)
    uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == [str(sid)]
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and not ku.key_cert_sign
    assert ca_mod.verify_x509_svid(pem, ca.bundle_pem()) == sid


def test_csr_sans_are_ignored(ca):
    sid = spiffeid.parse(f"spiffe://{TD}/a")
    pem = ca.issue_x509_svid(csr_pem([f"spiffe://{TD}/admin"]), sid, dt.timedelta(minutes=5))
    assert ca_mod.verify_x509_svid(pem, ca.bundle_pem()) == sid


def test_svid_ttl_clamped_to_ca(ca):
    pem = ca.issue_x509_svid(csr_pem(), spiffeid.parse(f"spiffe://{TD}/a"), dt.timedelta(days=365))
    assert x509.load_pem_x509_certificate(pem).not_valid_after_utc <= ca.cert.not_valid_after_utc


def test_refuses_foreign_trust_domain_and_bare_td(ca):
    with pytest.raises(CAError):
        ca.issue_x509_svid(csr_pem(), spiffeid.parse("spiffe://other.local/a"), dt.timedelta(minutes=5))
    with pytest.raises(CAError):
        ca.issue_x509_svid(csr_pem(), spiffeid.parse(f"spiffe://{TD}"), dt.timedelta(minutes=5))


def test_verify_rejects_other_ca(ca):
    other = CertificateAuthority.create(TD, dt.timedelta(hours=1))
    pem = other.issue_x509_svid(csr_pem(), spiffeid.parse(f"spiffe://{TD}/a"), dt.timedelta(minutes=5))
    with pytest.raises(CAError):
        ca_mod.verify_x509_svid(pem, ca.bundle_pem())


def test_jwt_svid_roundtrip_and_failures(ca):
    sid = spiffeid.parse(f"spiffe://{TD}/ai-agent/triage")
    tok = ca.mint_jwt_svid(sid, ["ticket-api"], dt.timedelta(minutes=5))
    assert ca_mod.verify_jwt_svid(tok, ca.jwks(), "ticket-api") == sid
    with pytest.raises(CAError, match="audience"):
        ca_mod.verify_jwt_svid(tok, ca.jwks(), "someone-else")
    with pytest.raises(CAError, match="expired"):
        ca_mod.verify_jwt_svid(tok, ca.jwks(), "ticket-api", now=time.time() + 3600)
    h, p, s = tok.split(".")
    tampered = h + "." + p[:-2] + ("A" if p[-2] != "A" else "B") + p[-1] + "." + s
    with pytest.raises(CAError):
        ca_mod.verify_jwt_svid(tampered, ca.jwks(), "ticket-api")
    other = CertificateAuthority.create(TD, dt.timedelta(hours=1))
    with pytest.raises(CAError):
        ca_mod.verify_jwt_svid(tok, other.jwks(), "ticket-api")
    with pytest.raises(CAError):
        ca.mint_jwt_svid(sid, [], dt.timedelta(minutes=5))


def test_load_or_create_persists_and_guards_trust_domain(tmp_path):
    c1, created = CertificateAuthority.load_or_create(tmp_path, TD, dt.timedelta(hours=1))
    assert created and (tmp_path / "bundle.pem").exists()
    assert oct((tmp_path / "ca-key.pem").stat().st_mode & 0o777) == "0o600"
    c2, created = CertificateAuthority.load_or_create(tmp_path, TD, dt.timedelta(hours=1))
    assert not created and c2.key_id == c1.key_id
    with pytest.raises(CAError, match="trust domain"):
        CertificateAuthority.load_or_create(tmp_path, "other.local", dt.timedelta(hours=1))
