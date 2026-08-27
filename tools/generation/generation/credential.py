import secrets
import sys
from datetime import datetime

from cryptography import x509

from . import mdoc, staging

DESCRIPTION = "Generate a credential."


def credential(
    command: str,
    name: str,
    ds_certificate_name: str,
    device_key_name: str,
    doctype: str,
    claims: list[list[str]],
    valid_from: datetime,
    valid_until: datetime,
    seed: str | None,
) -> None:
    vectors = staging.collection()
    try:
        ds_certificate = vectors.mdoc.certificate(ds_certificate_name)
    except KeyError:
        staging.missing("certificate", ds_certificate_name)
    try:
        device_key = vectors.mdoc.key(device_key_name)
    except KeyError:
        staging.missing("key", device_key_name)
    if ds_certificate.key is None:
        sys.exit(f"error: certificate {ds_certificate_name!r} records no key vector; cannot sign")
    if seed is None:
        seed = secrets.token_hex(32)
        command = staging.command_with(command, "--seed", seed)
    issuer_signed = mdoc.create_issuer_signed(
        doctype,
        staging.namespaces(claims),
        valid_from,
        valid_until,
        seed=bytes.fromhex(seed),
        device_public_key=staging.private_key(device_key).public_key(),
        issuer_key=staging.private_key(ds_certificate.key),
        issuer_certificate=x509.load_pem_x509_certificate(ds_certificate.pem),
    )
    path = staging.write(staging.stage(name) / f"{name}.cbor", issuer_signed)
    staging.print_commands(
        [
            staging.admit(
                "credential",
                path,
                name,
                command,
                "--device-key",
                device_key_name,
                "--ds-certificate",
                ds_certificate_name,
            )
        ]
    )
