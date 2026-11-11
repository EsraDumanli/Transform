"""A small, readable CA that issues SVIDs for one trust domain.

This is a learning implementation, not SPIRE: no key rotation, no upstream
authority, no HSM, no federation, and the signing key is a file on disk. What
it does follow is the *shape* the SPIFFE specs define, so its documents verify
with standard SPIFFE tooling:

* X.509-SVID (X509-SVID.md): exactly one URI SAN holding the SPIFFE ID; the
  leaf is not a CA; key usage digitalSignature; never keyCertSign.
* JWT-SVID (JWT-SVID.md): ES256-signed JWT with ``sub`` = SPIFFE ID, a
  non-empty ``aud`` and ``exp``.
* Trust bundle: the CA certificate (PEM) and the JWT key as a JWKS.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import time
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import spiffeid
from .spiffeid import SpiffeID

CA_KEY_FILE = "ca-key.pem"
CA_CERT_FILE = "ca-cert.pem"
BUNDLE_FILE = "bundle.pem"


class CAError(Exception):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class CertificateAuthority:
    def __init__(self, trust_domain: str, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate):
        self.trust_domain = trust_domain
        self.key = key
        self.cert = cert
        pub_der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.key_id = _b64(hashlib.sha256(pub_der).digest()[:12])

    # ---- construction -------------------------------------------------------

    @classmethod
    def create(cls, trust_domain: str, ttl: dt.timedelta) -> "CertificateAuthority":
        spiffeid.validate_trust_domain(trust_domain)
        if ttl.total_seconds() <= 0:
            raise CAError("CA TTL must be positive")
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "agent-identity-spiffe"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{trust_domain} CA"),
        ])
        now = _now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + ttl)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(str(spiffeid.from_parts(trust_domain)))]),
                critical=False,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return cls(trust_domain, key, cert)

    @classmethod
    def load_or_create(cls, data_dir: str | os.PathLike, trust_domain: str, ttl: dt.timedelta) -> tuple["CertificateAuthority", bool]:
        """Load the CA from ``data_dir`` or create one there.

        A data dir holding a CA for a *different* trust domain is an error: the
        server never silently re-keys or switches trust domains.
        """
        spiffeid.validate_trust_domain(trust_domain)
        d = Path(data_dir)
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        key_path, cert_path = d / CA_KEY_FILE, d / CA_CERT_FILE
        created = False
        if key_path.exists():
            ca = cls._load(key_path, cert_path)
            if ca.trust_domain != trust_domain:
                raise CAError(
                    f"{d} holds a CA for trust domain {ca.trust_domain!r}, not {trust_domain!r}; use a different data dir"
                )
        else:
            ca = cls.create(trust_domain, ttl)
            key_pem = ca.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key_pem)
            cert_path.write_bytes(ca.bundle_pem())
            created = True
        (d / BUNDLE_FILE).write_bytes(ca.bundle_pem())
        return ca, created

    @classmethod
    def _load(cls, key_path: Path, cert_path: Path) -> "CertificateAuthority":
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CAError("CA key must be an EC key")
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.UniformResourceIdentifier
        )
        if len(uris) != 1:
            raise CAError("CA cert must carry exactly one URI SAN (the trust domain)")
        return cls(spiffeid.parse(uris[0]).trust_domain, key, cert)

    # ---- bundle -------------------------------------------------------------

    def bundle_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def jwks(self) -> dict:
        nums = self.key.public_key().public_numbers()
        return {"keys": [{
            "kty": "EC", "crv": "P-256", "use": "jwt-svid", "kid": self.key_id,
            "x": _b64(nums.x.to_bytes(32, "big")), "y": _b64(nums.y.to_bytes(32, "big")),
        }]}

    # ---- X.509-SVIDs --------------------------------------------------------

    def _check_workload_id(self, sid: SpiffeID) -> None:
        if not sid.member_of(self.trust_domain):
            raise CAError(f"{sid} is not in trust domain {self.trust_domain!r}")
        if not sid.is_workload:
            raise CAError("refusing to issue an SVID for the bare trust domain ID")

    def _clamp(self, ttl: dt.timedelta) -> tuple[dt.datetime, dt.datetime]:
        if ttl.total_seconds() <= 0:
            raise CAError("SVID TTL must be positive")
        now = _now()
        return now, min(now + ttl, self.cert.not_valid_after_utc)  # never outlive the CA

    def _sign_leaf(self, public_key, sid: SpiffeID, ttl: dt.timedelta, dns_names=(), ips=()) -> x509.Certificate:
        self._check_workload_id(sid)
        now, not_after = self._clamp(ttl)
        sans: list[x509.GeneralName] = [x509.UniformResourceIdentifier(str(sid))]
        sans += [x509.DNSName(n) for n in dns_names]
        sans += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SPIFFE")]))
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(seconds=30))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=True, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False
            )
            .sign(self.key, hashes.SHA256())
        )

    def issue_x509_svid(self, csr_pem: bytes, sid: SpiffeID, ttl: dt.timedelta) -> bytes:
        """Sign the public key in a CSR into an X.509-SVID for ``sid``.

        The CSR's own subject and SANs are ignored: the CA decides what goes in
        the certificate, never the requester.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as e:
            raise CAError(f"invalid CSR: {e}") from e
        if not csr.is_signature_valid:
            raise CAError("CSR signature does not verify")
        return self._sign_leaf(csr.public_key(), sid, ttl).public_bytes(serialization.Encoding.PEM)

    def issue_server_cert(self, sid: SpiffeID, dns_names, ips, ttl: dt.timedelta) -> tuple[bytes, bytes]:
        """The server's own TLS cert: an X.509-SVID that also carries DNS/IP SANs."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._sign_leaf(key.public_key(), sid, ttl, dns_names, ips)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return cert.public_bytes(serialization.Encoding.PEM), key_pem

    # ---- JWT-SVIDs ----------------------------------------------------------

    def mint_jwt_svid(self, sid: SpiffeID, audience: list[str], ttl: dt.timedelta) -> str:
        self._check_workload_id(sid)
        if not audience:
            raise CAError("a JWT-SVID needs at least one audience")
        now, exp = self._clamp(ttl)
        header = {"alg": "ES256", "kid": self.key_id, "typ": "JWT"}
        claims = {"sub": str(sid), "aud": audience, "exp": int(exp.timestamp()), "iat": int(now.timestamp())}
        signing_input = _b64(json.dumps(header, separators=(",", ":")).encode()) + "." + _b64(
            json.dumps(claims, separators=(",", ":")).encode()
        )
        der = self.key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return signing_input + "." + _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


# ---- verification (usable without the CA's private key) ----------------------

def verify_x509_svid(cert_pem: bytes, bundle_pem: bytes, at: dt.datetime | None = None) -> SpiffeID:
    """Check that ``cert_pem`` is an X.509-SVID signed by a CA in the bundle."""
    at = at or _now()
    leaf = x509.load_pem_x509_certificate(cert_pem)
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    if bc.ca:
        raise CAError("leaf SVID must not be a CA")
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    if ku.key_cert_sign:
        raise CAError("leaf SVID must not have keyCertSign")
    uris = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.UniformResourceIdentifier
    )
    if len(uris) != 1:
        raise CAError(f"an X.509-SVID must have exactly one URI SAN, found {len(uris)}")
    sid = spiffeid.parse(uris[0])
    if not (leaf.not_valid_before_utc <= at <= leaf.not_valid_after_utc):
        raise CAError("certificate is not valid at this time")
    for root in x509.load_pem_x509_certificates(bundle_pem):
        if root.subject != leaf.issuer:
            continue
        try:
            leaf.verify_directly_issued_by(root)
        except (ValueError, TypeError, InvalidSignature):
            continue
        root_uris = root.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.UniformResourceIdentifier
        )
        if root_uris and spiffeid.parse(root_uris[0]).trust_domain != sid.trust_domain:
            raise CAError("SVID trust domain does not match the signing CA's trust domain")
        return sid
    raise CAError("SVID is not signed by any CA in the bundle")


def verify_jwt_svid(token: str, jwks: dict, audience: str, now: float | None = None) -> SpiffeID:
    """Verify a JWT-SVID against a JWKS and return its SPIFFE ID."""
    now = time.time() if now is None else now
    try:
        h64, p64, s64 = token.split(".")
        header = json.loads(_unb64(h64))
        claims = json.loads(_unb64(p64))
        sig = _unb64(s64)
    except (ValueError, json.JSONDecodeError) as e:
        raise CAError("malformed JWT") from e
    if header.get("alg") != "ES256":
        raise CAError(f"unexpected alg {header.get('alg')!r}")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise CAError("no key in the bundle matches the token's kid")
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_unb64(key["x"]), "big"), int.from_bytes(_unb64(key["y"]), "big"), ec.SECP256R1()
    ).public_key()
    if len(sig) != 64:
        raise CAError("bad signature length")
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, f"{h64}.{p64}".encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise CAError("signature does not verify") from e
    if now >= claims.get("exp", 0):
        raise CAError("token expired")
    aud = claims.get("aud")
    aud = [aud] if isinstance(aud, str) else (aud or [])
    if audience not in aud:
        raise CAError(f"audience {audience!r} not in token")
    return spiffeid.parse(claims["sub"])
