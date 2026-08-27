import json
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import records

DESCRIPTION = "Admit a PEM certificate under vectors/mdoc/certificates/."


def _verify_certificate_signature(child: x509.Certificate, parent: x509.Certificate) -> None:
    """Verify child's signature under parent's key."""
    # Certificate.extensions raises on the AV test PKI's malformed issuerAltName; the
    # signature check does not read extensions.
    key = parent.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        sys.exit("error: only EC-signed certificates are supported")
    algorithm = child.signature_hash_algorithm
    if algorithm is None:
        sys.exit("error: certificate has no signature hash algorithm")
    try:
        key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(algorithm))
    except InvalidSignature:
        sys.exit("error: signature does not verify against the named certificate")


def import_certificate(
    pem_path: str,
    repo: str | None,
    generator: str | None,
    ref: str | None,
    name: str,
    role: str,
    signed_by: str | None,
    key_name: str | None,
    comment: str | None,
) -> None:
    source = Path(pem_path)
    pem = source.read_bytes()
    sidecar: dict[str, Any] = {
        "schema": "mdoc-certificates-v1.schema.json",
        "role": role,
        "sha256": records.sha256(pem),
    }
    try:
        certificate: x509.Certificate | None = x509.load_pem_x509_certificate(pem)
    except (ValueError, UnsupportedAlgorithm):
        certificate = None
        print("PEM does not parse; public_key_x and public_key_y are not recorded")
    if certificate is not None:
        public_key = certificate.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
            public_key.curve, ec.SECP256R1
        ):
            numbers = public_key.public_numbers()
            sidecar["public_key_x"] = f"{numbers.x:064x}"
            sidecar["public_key_y"] = f"{numbers.y:064x}"
        else:
            print("certificate key is not EC P-256; public_key_x and public_key_y are not recorded")
    if repo is not None:
        sidecar["provenance"] = records.provenance(source, repo)
    else:
        sidecar["provenance"] = records.constructed(generator, ref)
    if certificate is None and (signed_by is not None or key_name is not None):
        sys.exit("error: PEM does not parse; --signed-by and --key cannot be verified")
    if signed_by is not None:
        assert certificate is not None
        parent_path = records.CERTIFICATES / f"{signed_by}.pem"
        if not parent_path.is_file():
            sys.exit(f"error: certificate {signed_by!r} not in the corpus; import it first")
        parent = x509.load_pem_x509_certificate(parent_path.read_bytes())
        _verify_certificate_signature(certificate, parent)
        sidecar["signed_by"] = signed_by
    if key_name is not None:
        assert certificate is not None
        records.require_key(key_name)
        key_sidecar = json.loads((records.KEYS / f"{key_name}.json").read_text())
        if "fingerprint" not in key_sidecar:
            sys.exit(f"error: key {key_name!r} has no fingerprint; cannot verify")
        cert_pub_der = certificate.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        cert_fingerprint = records.sha256(cert_pub_der)
        if cert_fingerprint != key_sidecar["fingerprint"]:
            sys.exit(
                f"error: certificate fingerprint {cert_fingerprint} "
                f"does not match key fingerprint {key_sidecar['fingerprint']}"
            )
        sidecar["key"] = key_name
    if comment is not None:
        sidecar["comment"] = comment
    records.write_record(records.CERTIFICATES / f"{name}.pem", pem, sidecar)
