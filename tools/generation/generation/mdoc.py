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
    pass


_COSE_ES256_PROTECTED = b"\xa1\x01\x26"
_ECDSA = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)


def _require_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _tdate(value: datetime) -> cbor2.CBORTag:
    return cbor2.CBORTag(0, value.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _device_authentication_bytes(transcript: bytes, doc_type: str, namespaces: object) -> bytes:
    authentication = ["DeviceAuthentication", cbor2.loads(transcript), doc_type, namespaces]
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(authentication)))


def _cose_sign(key: ec.EllipticCurvePrivateKey, payload: bytes) -> bytes:
    structure = cbor2.dumps(["Signature1", _COSE_ES256_PROTECTED, b"", payload])
    r, s = decode_dss_signature(key.sign(structure, _ECDSA))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _cose_verify(key: ec.EllipticCurvePublicKey, payload: bytes, signature: bytes) -> None:
    structure = cbor2.dumps(["Signature1", _COSE_ES256_PROTECTED, b"", payload])
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    key.verify(der, structure, ec.ECDSA(hashes.SHA256()))


def _key_usage(*, ca: bool) -> x509.KeyUsage:
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
    payload = _device_authentication_bytes(transcript, doc_type, device_namespaces)
    return _cose_sign(device_key, payload)


def verify_device_authentication(mdoc: bytes, transcript: bytes) -> None:
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
