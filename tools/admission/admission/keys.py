"""key: admit a PEM key and the material it encodes."""

from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from . import records

DESCRIPTION = """\
Admit a PEM key as a vector under vectors/mdoc/keys/.
The source is a PEM file holding one private or public key.
The vector derives sha256, fingerprint, public_key_x, public_key_y, and
private_key from the PEM.
docs/admission.md holds the rules that span the commands.
"""


def import_key(
    pem_path: str,
    repo: str | None,
    generator: str | None,
    ref: str | None,
    name: str,
    role: str,
    comment: str | None,
) -> None:
    source = Path(pem_path)
    pem = source.read_bytes()
    sidecar: dict[str, Any] = {
        "schema": "mdoc-keys-v1.schema.json",
        "role": role,
        "sha256": records.sha256(pem),
    }
    public_key = None
    private_value = None
    try:
        private_key = load_pem_private_key(pem, password=None)
        public_key = private_key.public_key()
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            private_value = private_key.private_numbers().private_value
    except (ValueError, TypeError, UnsupportedAlgorithm):
        try:
            public_key = load_pem_public_key(pem)
        except (ValueError, UnsupportedAlgorithm):
            print("PEM does not parse; fingerprint and key material are not recorded")
    if public_key is not None:
        sidecar["fingerprint"] = records.sha256(
            public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )
        if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
            public_key.curve, ec.SECP256R1
        ):
            numbers = public_key.public_numbers()
            sidecar["public_key_x"] = f"{numbers.x:064x}"
            sidecar["public_key_y"] = f"{numbers.y:064x}"
            if private_value is not None:
                sidecar["private_key"] = f"{private_value:064x}"
        else:
            print(
                "key is not EC P-256; public_key_x, public_key_y, and private_key are not recorded"
            )
    if repo is not None:
        sidecar["provenance"] = records.provenance(source, repo)
    else:
        sidecar["provenance"] = records.constructed(generator, ref)
    if comment is not None:
        sidecar["comment"] = comment
    records.write_record(records.KEYS / f"{name}.pem", pem, sidecar)
