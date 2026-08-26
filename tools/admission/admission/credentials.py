"""credential: admit IssuerSigned CBOR and its verified key and certificate relations."""

import sys
from pathlib import Path
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    load_pem_private_key,
    load_pem_public_key,
)

from . import records

DESCRIPTION = """\
Admit a CBOR credential as a vector under vectors/mdoc/credentials/.
The source is a file holding IssuerSigned CBOR, {nameSpaces, issuerAuth}, the
structure an issuer delivers. A DeviceResponse is refused; admit one with
admit.py presentation.
The vector derives sha256 from the bytes and doctype from the MSO inside
issuerAuth.
docs/admission.md holds the rules that span the commands.
"""


def _issuer_auth(blob: bytes) -> Any:
    """The top-level issuerAuth of an IssuerSigned credential.

    Args:
        blob: The credential's CBOR bytes.

    Returns:
        The COSE_Sign1 array, or None when the bytes do not parse as
        IssuerSigned.
    """
    try:
        issuer_signed = cbor2.loads(blob)
        return issuer_signed["issuerAuth"]
    except Exception:
        return None


def _mso(issuer_auth: Any) -> Any:
    """The MSO an issuerAuth's payload carries.

    Args:
        issuer_auth: The COSE_Sign1 array, or None.

    Returns:
        The decoded MSO map, or None when the payload does not decode.
    """
    try:
        return cbor2.loads(cbor2.loads(issuer_auth[2]).value)
    except Exception:
        return None


def _refuse_device_response(blob: bytes) -> None:
    """Exit when the bytes are a DeviceResponse, which belongs under presentations."""
    try:
        decoded = cbor2.loads(blob)
    except Exception:
        return
    if isinstance(decoded, dict) and "documents" in decoded:
        sys.exit(
            "error: the bytes are a DeviceResponse, not IssuerSigned; a credential holds what "
            "an issuer delivers, and a DeviceResponse is admitted with admit.py presentation"
        )


def import_credential(
    cbor_path: str,
    repo: str | None,
    generator: str | None,
    ref: str | None,
    name: str,
    device_key_name: str | None,
    ds_certificate_name: str | None,
    comment: str | None,
) -> None:
    source = Path(cbor_path)
    blob = source.read_bytes()
    _refuse_device_response(blob)
    sidecar: dict[str, Any] = {
        "schema": "mdoc-credentials-v1.schema.json",
        "sha256": records.sha256(blob),
    }
    issuer_auth = _issuer_auth(blob)
    mso = _mso(issuer_auth)
    try:
        sidecar["doctype"] = mso["docType"]
    except Exception:
        print("CBOR does not parse as IssuerSigned with a decodable MSO; doctype is not recorded")
    if device_key_name is not None:
        records.require_key(device_key_name)
        try:
            cose_key = mso["deviceKeyInfo"]["deviceKey"]
            cose_x: bytes = cose_key[-2]
            cose_y: bytes = cose_key[-3]
        except Exception:
            sys.exit("error: credential does not parse; cannot verify --device-key")
        key_pem = (records.KEYS / f"{device_key_name}.pem").read_bytes()
        try:
            private_key = load_pem_private_key(key_pem, password=None)
            public_key = private_key.public_key()
        except (ValueError, TypeError, UnsupportedAlgorithm):
            try:
                public_key = load_pem_public_key(key_pem)
            except (ValueError, UnsupportedAlgorithm):
                sys.exit(f"error: key {device_key_name!r} PEM does not parse; cannot verify")
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            sys.exit("error: device key is not an EC key; cannot verify --device-key")
        nums = public_key.public_numbers()
        key_size = (public_key.key_size + 7) // 8
        expected_x = nums.x.to_bytes(key_size, "big")
        expected_y = nums.y.to_bytes(key_size, "big")
        if cose_x != expected_x or cose_y != expected_y:
            sys.exit("error: device key coordinates do not match the credential's deviceKeyInfo")
        sidecar["device_key"] = device_key_name
    if ds_certificate_name is not None:
        records.require_certificate(ds_certificate_name)
        try:
            chain = issuer_auth[1][33]
            leaf_der: bytes = chain[0] if isinstance(chain, list) else chain
        except Exception:
            sys.exit("error: credential does not parse; cannot verify --ds-certificate")
        cert_pem = (records.CERTIFICATES / f"{ds_certificate_name}.pem").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        cert_der = cert.public_bytes(Encoding.DER)
        if leaf_der != cert_der:
            sys.exit(f"error: x5chain leaf does not match certificate {ds_certificate_name!r}")
        sidecar["ds_certificate"] = ds_certificate_name
    if repo is not None:
        sidecar["provenance"] = records.provenance(source, repo)
    else:
        sidecar["provenance"] = records.constructed(generator, ref)
    if comment is not None:
        sidecar["comment"] = comment
    records.write_record(records.CREDENTIALS / f"{name}.cbor", blob, sidecar)
