"""Mdoc builder under locally held keys, copied from pylongfellow.mdoc.testing.

Certificates, ``IssuerSigned``, and ``DeviceResponse`` are assembled and signed
without loading a backend. Every signature is ECDSA over SHA-256 with the
nonce derived per RFC 6979, so the same inputs give the same bytes.
"""

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.x509.oid import NameOID


class Error(Exception):
    """A signature self-check failed."""


# COSE protected header {1: -7}: ES256, the only algorithm on this path.
_COSE_ES256_PROTECTED = b"\xa1\x01\x26"
_ECDSA = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)


def _require_utc(value: datetime, name: str) -> datetime:
    """Reject a naive datetime and normalize an aware one to UTC."""
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _tdate(value: datetime) -> cbor2.CBORTag:
    """Encode a UTC datetime as CBOR tag 0, `YYYY-MM-DDTHH:MM:SSZ`."""
    return cbor2.CBORTag(0, value.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _device_authentication_bytes(transcript: bytes, doc_type: str, namespaces: object) -> bytes:
    """Build ``DeviceAuthenticationBytes``, the device signature's detached payload."""
    authentication = ["DeviceAuthentication", cbor2.loads(transcript), doc_type, namespaces]
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(authentication)))


def _cose_sign(key: ec.EllipticCurvePrivateKey, payload: bytes) -> bytes:
    """Sign a COSE ``Signature1`` structure over the payload, returning raw ``r || s``."""
    structure = cbor2.dumps(["Signature1", _COSE_ES256_PROTECTED, b"", payload])
    r, s = decode_dss_signature(key.sign(structure, _ECDSA))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _cose_verify(key: ec.EllipticCurvePublicKey, payload: bytes, signature: bytes) -> None:
    """Check a COSE ``Signature1`` signature; raises ``InvalidSignature`` on mismatch."""
    structure = cbor2.dumps(["Signature1", _COSE_ES256_PROTECTED, b"", payload])
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    key.verify(der, structure, ec.ECDSA(hashes.SHA256()))


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    """Build the keyUsage extension: keyCertSign for a CA, digitalSignature for a leaf."""
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def create_certificate(
    subject: str,
    public_key: ec.EllipticCurvePublicKey,
    issuer: str,
    signing_key: ec.EllipticCurvePrivateKey,
    valid_from: datetime,
    valid_until: datetime,
    *,
    serial: int,
    ca: bool = False,
) -> x509.Certificate:
    """Create a test X.509 certificate, CA or leaf.

    Args:
        subject: Subject common name.
        public_key: Public key the certificate certifies.
        issuer: Issuer common name; equals `subject` on a self-signed
            certificate.
        signing_key: Private key that signs the certificate.
        valid_from: Start of the validity window; timezone-aware.
        valid_until: End of the validity window; timezone-aware.
        serial: Serial number to carry.
        ca: True builds a CA certificate (`basicConstraints` CA, keyUsage
            `keyCertSign`); False builds a leaf (keyUsage `digitalSignature`).

    Returns:
        The signed certificate.

    Raises:
        ValueError: `valid_from` or `valid_until` is naive.
    """
    valid_from = _require_utc(valid_from, "valid_from")
    valid_until = _require_utc(valid_until, "valid_until")

    def _name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(_key_usage(ca=ca), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    return builder.sign(signing_key, hashes.SHA256(), ecdsa_deterministic=True)


def sign_device_authentication(
    device_key: ec.EllipticCurvePrivateKey,
    transcript: bytes,
    doc_type: str,
    device_namespaces: object,
) -> bytes:
    """Sign ``DeviceAuthentication`` over a session transcript.

    Builds the detached ``DeviceAuthenticationBytes`` payload from the
    transcript, the doctype, and the device namespaces, and signs it as a COSE
    ``Signature1`` structure with ES256.

    Args:
        device_key: The credential's device private key.
        transcript: CBOR-encoded session transcript.
        doc_type: The credential's doctype.
        device_namespaces: The data item held in the response's
            ``deviceSigned.nameSpaces``: tag 24 over the encoded namespace map.

    Returns:
        The 64-byte ``r || s`` signature; a document carries it as the final
            element of its ``deviceAuth.deviceSignature`` array.
    """
    payload = _device_authentication_bytes(transcript, doc_type, device_namespaces)
    return _cose_sign(device_key, payload)


def verify_device_authentication(mdoc: bytes, transcript: bytes) -> None:
    """Verify a response's device signature over a session transcript.

    The device key comes from the document's MSO. The signed payload is
    rebuilt from the document's own doctype and device namespaces.

    Args:
        mdoc: CBOR-encoded ``DeviceResponse``.
        transcript: CBOR-encoded session transcript the signature is bound to.

    Raises:
        Error: The device signature does not verify over the transcript.
    """
    document = cbor2.loads(mdoc)["documents"][0]
    mso = cbor2.loads(cbor2.loads(document["issuerSigned"]["issuerAuth"][2]).value)
    cose_key = mso["deviceKeyInfo"]["deviceKey"]
    device_public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(cose_key[-2], "big"), int.from_bytes(cose_key[-3], "big"), ec.SECP256R1()
    ).public_key()
    payload = _device_authentication_bytes(
        transcript, document["docType"], document["deviceSigned"]["nameSpaces"]
    )
    signature = document["deviceSigned"]["deviceAuth"]["deviceSignature"][3]
    try:
        _cose_verify(device_public, payload, signature)
    except InvalidSignature as e:
        raise Error("device signature does not verify over the transcript") from e


def _check_issuer_auth(issuer_signed: bytes) -> None:
    """Verify the issuer signature against the embedded certificate.

    Decodes ``IssuerSigned`` back the way a consumer would, so a certificate
    that does not certify the signing key, or drift between encode and decode,
    fails here.

    Args:
        issuer_signed: CBOR-encoded ``IssuerSigned``.

    Raises:
        Error: The embedded certificate carries no EC public key, or the
            issuer signature does not verify against it.
    """
    issuer_auth = cbor2.loads(issuer_signed)["issuerAuth"]
    certificate = x509.load_der_x509_certificate(issuer_auth[1][33])
    public = certificate.public_key()
    if not isinstance(public, ec.EllipticCurvePublicKey):
        raise Error("embedded certificate does not carry an EC public key")
    try:
        _cose_verify(public, issuer_auth[2], issuer_auth[3])
    except InvalidSignature as e:
        raise Error("issuer signature does not verify against the embedded certificate") from e


def _item_salt(seed: bytes, namespace: str, identifier: str) -> bytes:
    """The 16-byte ``IssuerSignedItem`` salt a seed fixes for one attribute."""
    return hashlib.sha256(seed + namespace.encode() + identifier.encode()).digest()[:16]


def create_issuer_signed(
    doc_type: str,
    claims: Mapping[str, Mapping[str, object]],
    valid_from: datetime,
    valid_until: datetime,
    *,
    seed: bytes,
    device_public_key: ec.EllipticCurvePublicKey,
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_certificate: x509.Certificate,
) -> bytes:
    """Issuer-sign a set of claims into ``IssuerSigned``, the structure an issuer delivers.

    The claims become tag-24 ``IssuerSignedItem`` entries under
    ``nameSpaces``, digested into the MSO that ``issuerAuth`` signs. The MSO
    binds the device public key, so only that key can present the credential.
    The issuer signature is verified before returning.

    Args:
        doc_type: Doctype the MSO carries.
        claims: Issuer-signed claims, as namespace to element identifier to
            element value. Values are encoded with `cbor2`; map order is
            preserved, and digest ids run from 0 within each namespace.
        valid_from: MSO ``signed``/``validFrom`` timestamp; timezone-aware.
        valid_until: MSO ``validUntil`` timestamp; timezone-aware.
        seed: Seed the item salts are derived from, as
            `SHA-256(seed || namespace || identifier)` truncated to 16 bytes.
        device_public_key: Device key to bind in ``deviceKeyInfo``.
        issuer_key: Document-signer private key that signs the MSO.
        issuer_certificate: Certificate to embed in ``issuerAuth``'s x5chain
            header; must certify `issuer_key`.

    Returns:
        CBOR-encoded ``IssuerSigned``: ``{nameSpaces, issuerAuth}``.

    Raises:
        ValueError: `valid_from` or `valid_until` is naive.
        Error: The encoded bytes failed the issuer signature self-check, which
            means `issuer_certificate` does not certify `issuer_key` or does
            not carry an EC key.
    """
    valid_from = _require_utc(valid_from, "valid_from")
    valid_until = _require_utc(valid_until, "valid_until")
    namespaces: dict[str, list[cbor2.CBORTag]] = {}
    digests: dict[str, dict[int, bytes]] = {}
    for space, elements in claims.items():
        for digest_id, (identifier, value) in enumerate(elements.items()):
            item = cbor2.CBORTag(
                24,
                cbor2.dumps(
                    {
                        "random": _item_salt(seed, space, identifier),
                        "digestID": digest_id,
                        "elementIdentifier": identifier,
                        "elementValue": value,
                    }
                ),
            )
            namespaces.setdefault(space, []).append(item)
            digests.setdefault(space, {})[digest_id] = hashlib.sha256(cbor2.dumps(item)).digest()

    device_numbers = device_public_key.public_numbers()
    mso = {
        "docType": doc_type,
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": digests,
        "deviceKeyInfo": {
            "deviceKey": {
                1: 2,
                -1: 1,
                -2: device_numbers.x.to_bytes(32, "big"),
                -3: device_numbers.y.to_bytes(32, "big"),
            }
        },
        "validityInfo": {
            "signed": _tdate(valid_from),
            "validFrom": _tdate(valid_from),
            "validUntil": _tdate(valid_until),
        },
    }
    mso_payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
    issuer_signed = cbor2.dumps(
        {
            "nameSpaces": namespaces,
            "issuerAuth": [
                _COSE_ES256_PROTECTED,
                {33: issuer_certificate.public_bytes(serialization.Encoding.DER)},
                mso_payload,
                _cose_sign(issuer_key, mso_payload),
            ],
        }
    )
    _check_issuer_auth(issuer_signed)
    return issuer_signed


def create_device_response(
    doc_type: str,
    issuer_signed: Mapping[str, object],
    device_namespaces: cbor2.CBORTag,
    device_signature: bytes,
) -> bytes:
    """Assemble a ``DeviceResponse`` holding one document.

    Args:
        doc_type: Doctype of the document.
        issuer_signed: Decoded ``IssuerSigned`` map, ``{nameSpaces,
            issuerAuth}``; a subset of the credential's items discloses less
            than the credential holds, and ``issuerAuth`` is carried through
            unchanged.
        device_namespaces: The data item ``deviceSigned.nameSpaces`` holds:
            tag 24 over the encoded namespace map.
        device_signature: The 64-byte ``r || s`` signature over
            ``DeviceAuthenticationBytes``.

    Returns:
        CBOR-encoded ``DeviceResponse``.
    """
    return cbor2.dumps(
        {
            "version": "1.0",
            "documents": [
                {
                    "docType": doc_type,
                    "issuerSigned": issuer_signed,
                    "deviceSigned": {
                        "nameSpaces": device_namespaces,
                        "deviceAuth": {
                            "deviceSignature": [
                                _COSE_ES256_PROTECTED,
                                {},
                                None,
                                device_signature,
                            ]
                        },
                    },
                }
            ],
            "status": 0,
        }
    )
