"""create-presentation: build a presentation under fresh keys and stage it."""

import json
import sys
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from . import presentation, staging

DESCRIPTION = """\
Build a presentation under a fresh issuer key and a fresh device key, and
stage presentation.json, issuer-key.pem, device-key.pem, and
issuer-certificate.pem under tools/generation/staging/<name>/.
The claims are issuer-signed; the device signature covers the transcript, the
doctype, and the device namespaces.
The printed commands admit the presentation and the three PEMs.
"""


def _namespaces(triples: list[list[str]]) -> dict[str, dict[str, object]]:
    """Group namespace, id, and JSON value triples into the nested map the builder takes."""
    grouped: dict[str, dict[str, object]] = {}
    for namespace, identifier, value in triples:
        try:
            grouped.setdefault(namespace, {})[identifier] = json.loads(value)
        except json.JSONDecodeError as e:
            sys.exit(f"error: value for {identifier!r} is not JSON: {e}")
    return grouped


def _private_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    """The key as an unencrypted PKCS#8 PEM."""
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def create_presentation(
    command: str,
    name: str,
    doctype: str,
    claims: list[list[str]],
    device_namespaces: list[list[str]],
    transcript: str,
    valid_from: datetime,
    valid_until: datetime,
) -> None:
    # PresentationSpecimen carries the issuer public key, not the private half,
    # so the issuer key is generated here and passed in to be staged as a PEM.
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    device_key = ec.generate_private_key(ec.SECP256R1())
    specimen = presentation.create_presentation(
        doctype,
        _namespaces(claims),
        bytes.fromhex(transcript),
        valid_from,
        valid_until,
        device_namespaces=_namespaces(device_namespaces) or None,
        issuer_key=issuer_key,
        device_key=device_key,
    )
    directory = staging.stage(name)
    document = {"mdoc": specimen.mdoc.hex(), "transcript": transcript.lower()}
    presentation_json = staging.write(
        directory / "presentation.json", (json.dumps(document, indent=2) + "\n").encode()
    )
    issuer_pem = staging.write(directory / "issuer-key.pem", _private_pem(issuer_key))
    device_pem = staging.write(directory / "device-key.pem", _private_pem(device_key))
    certificate = staging.write(
        directory / "issuer-certificate.pem",
        specimen.issuer_certificate.public_bytes(Encoding.PEM),
    )
    staging.print_commands(
        [
            staging.admit("import-presentation", presentation_json, name, command),
            staging.admit(
                "import-key",
                issuer_pem,
                f"{name}-issuer-key",
                command,
                "--role",
                "document-signer",
            ),
            staging.admit(
                "import-key", device_pem, f"{name}-device-key", command, "--role", "device"
            ),
            staging.admit(
                "import-certificate",
                certificate,
                f"{name}-issuer-certificate",
                command,
                "--role",
                "document-signer",
            ),
        ]
    )
