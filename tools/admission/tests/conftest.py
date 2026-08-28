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
}


@pytest.fixture
def collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
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
