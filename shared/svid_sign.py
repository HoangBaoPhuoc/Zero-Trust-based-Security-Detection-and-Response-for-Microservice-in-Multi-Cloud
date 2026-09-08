# ZTLab - SPIFFE X.509-SVID asymmetric signing/verification (T-1.5)
#
# Replaces the old CORE_BANKING_SHARED_SECRET HMAC between payment-service and
# core-banking: the service that actually computes the fraud verdict
# (fraud-detection) signs it with its own SPIRE-issued X.509-SVID private key;
# the verifier (core-banking) checks the signature against that certificate's
# public key, and the certificate itself against the SPIRE trust bundle. No
# shared secret to leak or to get out of sync between services, and a
# compromised payment-service (which only ever holds the *public*, signed
# verdict, never fraud-detection's private key) can no longer forge a passing
# verdict.
#
# Not literally a "JWT-SVID" as originally sketched in the remediation plan:
# SPIFFE JWT-SVIDs only carry standard claims (sub/aud/exp/iat) via the
# Workload API's FetchJWTSVID call, with no way to bind arbitrary application
# data (the fraud score, trace_id, amount) into the token itself -- a
# compromised payment-service could keep a genuine JWT-SVID and simply swap
# the score in a plaintext header, defeating the whole point. X.509-SVID
# signing is still SPIRE-issued and asymmetric, just applied to the actual
# payload instead of used as a bearer token. See KET-QUA-KIEM-TRA.md T-1.5.
#
# No pyspiffe on PyPI at the time this was written (checked 2026-09-05 --
# 404). Certs/keys land on disk instead, refreshed by a small sidecar
# container in each pod running `spire-agent api fetch x509 -write <dir>` on
# a loop against the same Workload API socket istio-proxy already uses.

import base64
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

SVID_DIR_DEFAULT = "/svid"


def build_canonical(
    timestamp: int, trace_id: str, from_account: str, to_account: str, amount: float, currency: str, score: int
) -> bytes:
    """Canonical byte string covered by the signature -- same field order/
    formatting must be used by both the signer (fraud-detection) and the
    verifier (core-banking), or every verdict fails. Kept in one place
    (instead of duplicated per service, which is what caused the 2026-08-13
    issuer-mismatch incident elsewhere in this codebase) specifically to
    avoid that class of bug here."""
    canonical = "|".join(
        [str(timestamp), trace_id, from_account, to_account, f"{amount:.2f}", currency, str(score)]
    )
    return canonical.encode("utf-8")


def load_own_svid(svid_dir: str = SVID_DIR_DEFAULT) -> tuple[object, bytes]:
    """Return (private_key, cert_chain_pem_bytes) for this workload's current SVID."""
    with open(f"{svid_dir}/svid.0.key", "rb") as f:
        key_pem = f.read()
    with open(f"{svid_dir}/svid.0.pem", "rb") as f:
        cert_pem = f.read()
    private_key = serialization.load_pem_private_key(key_pem, password=None)
    return private_key, cert_pem


def load_trust_bundle(svid_dir: str = SVID_DIR_DEFAULT) -> bytes:
    with open(f"{svid_dir}/bundle.0.pem", "rb") as f:
        return f.read()


def sign(private_key, canonical: bytes) -> str:
    """Sign canonical bytes with this workload's SVID private key, base64-encoded."""
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        sig = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, rsa.RSAPrivateKey):
        sig = private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError(f"unsupported private key type: {type(private_key)}")
    return base64.b64encode(sig).decode()


def _spiffe_id_from_cert(cert: x509.Certificate) -> str | None:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return None
    for name in san.get_values_for_type(x509.UniformResourceIdentifier):
        if name.startswith("spiffe://"):
            return name
    return None


def verify(
    cert_chain_pem: bytes,
    signature_b64: str,
    canonical: bytes,
    expected_spiffe_id: str,
    trust_bundle_pem: bytes,
) -> tuple[bool, str]:
    """Verify signer identity, cert trust chain, and signature over canonical.

    Returns (ok, reason) -- reason is always populated (for audit logs).
    """
    try:
        certs = x509.load_pem_x509_certificates(cert_chain_pem)
    except Exception as exc:
        return False, f"cert_parse_error: {exc}"
    if not certs:
        return False, "cert_chain_empty"
    leaf, intermediates = certs[0], certs[1:]

    now = time.time()
    if now < leaf.not_valid_before_utc.timestamp() or now > leaf.not_valid_after_utc.timestamp():
        return False, "cert_expired_or_not_yet_valid"

    spiffe_id = _spiffe_id_from_cert(leaf)
    if spiffe_id != expected_spiffe_id:
        return False, f"spiffe_id_mismatch: got {spiffe_id!r}, expected {expected_spiffe_id!r}"

    try:
        bundle_certs = x509.load_pem_x509_certificates(trust_bundle_pem)
        store = Store(bundle_certs)
        verifier = PolicyBuilder().store(store).build_client_verifier()
        verifier.verify(leaf, intermediates)
    except VerificationError as exc:
        return False, f"cert_not_trusted_by_bundle: {exc}"
    except Exception as exc:
        return False, f"bundle_parse_error: {exc}"

    try:
        signature = base64.b64decode(signature_b64)
    except Exception as exc:
        return False, f"signature_decode_error: {exc}"

    pub = leaf.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, canonical, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False, f"unsupported_public_key_type: {type(pub)}"
    except InvalidSignature:
        return False, "signature_invalid"

    return True, "ok"
