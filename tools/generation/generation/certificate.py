import sys
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from . import mdoc, staging

DESCRIPTION = "Certify a key vector and stage <name>.pem."


def _common_name(certificate: x509.Certificate, name: str) -> str:
    attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        sys.exit(f"error: certificate {name!r} has no subject common name; pass --issuer")
    return str(attributes[0].value)


def certificate(
    command: str,
    name: str,
    key_name: str,
    signed_by: str | None,
    subject: str,
    issuer: str | None,
    ca: bool,
    valid_from: datetime,
    valid_until: datetime,
    serial: int | None,
) -> None:
    vectors = staging.collection()
    try:
        subject_key = vectors.mdoc.key(key_name)
    except KeyError:
        staging.missing("key", key_name)
    subject_public = staging.public_key(subject_key)
    if signed_by is None:
        signing_key = staging.private_key(subject_key)
        issuer = issuer if issuer is not None else subject
    else:
        try:
            signer = vectors.mdoc.certificate(signed_by)
        except KeyError:
            staging.missing("certificate", signed_by)
        if signer.key is None:
            sys.exit(f"error: certificate {signed_by!r} records no key vector; cannot sign")
        signing_key = staging.private_key(signer.key)
        if issuer is None:
            issuer = _common_name(x509.load_pem_x509_certificate(signer.pem), signed_by)
    if serial is None:
        serial = x509.random_serial_number()
        command = staging.command_with(command, "--serial", str(serial))
    built = mdoc.create_certificate(
        subject,
        subject_public,
        issuer,
        signing_key,
        valid_from,
        valid_until,
        serial=serial,
        ca=ca,
    )
    path = staging.write(staging.stage(name) / f"{name}.pem", built.public_bytes(Encoding.PEM))
    flags = ["--role", "iaca" if ca else "document-signer"]
    if signed_by is not None:
        flags += ["--signed-by", signed_by]
    flags += ["--key", key_name]
    staging.print_commands([staging.admit("certificate", path, name, command, *flags)])
