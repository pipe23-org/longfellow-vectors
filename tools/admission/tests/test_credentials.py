import hashlib
import json
import sys
from datetime import date
from pathlib import Path

import pytest

import admit
from admission import records

DATA = Path(__file__).parent / "data"
GENERATOR = "generate.py credential --name staged"


def test_credential_admitted_with_references(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "credential",
            str(DATA / "credential.cbor"),
            "--generator",
            GENERATOR,
            "--ref",
            "0" * 40,
            "--name",
            "staged",
            "--device-key",
            "device-key",
            "--ds-certificate",
            "ds-certificate",
        ],
    )

    admit.main()

    blob = (DATA / "credential.cbor").read_bytes()
    assert json.loads((records.CREDENTIALS / "staged.json").read_text()) == {
        "schema": "mdoc-credentials-v1.schema.json",
        "sha256": hashlib.sha256(blob).hexdigest(),
        "doctype": "eu.europa.ec.av.1",
        "device_key": "device-key",
        "ds_certificate": "ds-certificate",
        "provenance": {
            "type": "constructed",
            "generator": GENERATOR,
            "ref": "0" * 40,
            "created": date.today().isoformat(),
        },
    }


def test_wrong_device_key_rejected(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "credential",
            str(DATA / "credential.cbor"),
            "--generator",
            GENERATOR,
            "--ref",
            "0" * 40,
            "--name",
            "staged",
            "--device-key",
            "other-key",
        ],
    )

    with pytest.raises(SystemExit) as refused:
        admit.main()

    assert "do not match the credential's deviceKeyInfo" in str(refused.value)
