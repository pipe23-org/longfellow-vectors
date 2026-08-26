"""The temporary collection the command tests admit into."""

import hashlib
import json
from pathlib import Path

import pytest

from admission import records

DATA = Path(__file__).parent / "data"
CREDENTIAL_NAME = "av-credential"
DOCTYPE = "eu.europa.ec.av.1"
PROVENANCE = {
    "type": "constructed",
    "generator": "tools/admission/tests/conftest.py",
    "created": "2026-08-26",
}


@pytest.fixture
def collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A collection holding the device key, the document-signer certificate, and a credential.

    The keys, certificate, credential, and responses under tests/data were
    built with `generation.mdoc` under fixed P-256 scalars: ds-certificate
    certifies the key that signs credential.cbor, which binds device-key over
    age_over_18 and age_over_21 in eu.europa.ec.av.1. other-key is a second
    device key the credential does not bind. Each presentation.json holds a
    DeviceResponse over the same transcript: presentation.json presents the
    credential, presentation-other-credential.json presents a credential
    signed under a second salt seed, and presentation-foreign-item.json
    carries the credential's issuerAuth over that other credential's item.

    admit.py resolves the collection through `admission.records`, so the
    module's paths are pointed at the temporary directory.
    """
    root = tmp_path / "vectors" / "mdoc"
    for subtree in ("keys", "certificates", "credentials", "presentations"):
        (root / subtree).mkdir(parents=True)
    monkeypatch.setattr(records, "ROOT", tmp_path)
    monkeypatch.setattr(records, "KEYS", root / "keys")
    monkeypatch.setattr(records, "CERTIFICATES", root / "certificates")
    monkeypatch.setattr(records, "CREDENTIALS", root / "credentials")
    monkeypatch.setattr(records, "PRESENTATIONS", root / "presentations")

    for name in ("device-key", "other-key"):
        pem = (DATA / f"{name}.pem").read_bytes()
        (root / "keys" / f"{name}.pem").write_bytes(pem)
        (root / "keys" / f"{name}.json").write_text(
            json.dumps(
                {
                    "schema": "mdoc-keys-v1.schema.json",
                    "role": "device",
                    "sha256": hashlib.sha256(pem).hexdigest(),
                    "provenance": PROVENANCE,
                },
                indent=2,
            )
            + "\n"
        )

    certificate = (DATA / "ds-certificate.pem").read_bytes()
    (root / "certificates" / "ds-certificate.pem").write_bytes(certificate)
    (root / "certificates" / "ds-certificate.json").write_text(
        json.dumps(
            {
                "schema": "mdoc-certificates-v1.schema.json",
                "role": "document-signer",
                "sha256": hashlib.sha256(certificate).hexdigest(),
                "provenance": PROVENANCE,
            },
            indent=2,
        )
        + "\n"
    )

    credential = (DATA / "credential.cbor").read_bytes()
    (root / "credentials" / f"{CREDENTIAL_NAME}.cbor").write_bytes(credential)
    (root / "credentials" / f"{CREDENTIAL_NAME}.json").write_text(
        json.dumps(
            {
                "schema": "mdoc-credentials-v1.schema.json",
                "sha256": hashlib.sha256(credential).hexdigest(),
                "doctype": DOCTYPE,
                "provenance": PROVENANCE,
            },
            indent=2,
        )
        + "\n"
    )
    return root
