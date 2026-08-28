import json
import sys
from pathlib import Path

import cbor2
import pytest

import admit
from admission import records

DATA = Path(__file__).parent / "data"
CREDENTIAL_NAME = "av-credential"
GENERATOR = "generate.py presentation --name presented"


def test_presentation_admitted_with_credential(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "presentation",
            str(DATA / "presentation.json"),
            "--generator",
            GENERATOR,
            "--name",
            "presented",
            "--credential",
            CREDENTIAL_NAME,
        ],
    )

    admit.main()

    sidecar = json.loads((records.PRESENTATIONS / "presented.json").read_text())
    assert sidecar["credential"] == CREDENTIAL_NAME


def test_other_issuer_auth_rejected(collection: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "presentation",
            str(DATA / "presentation-other-credential.json"),
            "--generator",
            GENERATOR,
            "--name",
            "presented",
            "--credential",
            CREDENTIAL_NAME,
        ],
    )

    with pytest.raises(SystemExit) as refused:
        admit.main()

    assert "presented issuerAuth does not equal" in str(refused.value)


def test_foreign_item_rejected(collection: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "presentation",
            str(DATA / "presentation-foreign-item.json"),
            "--generator",
            GENERATOR,
            "--name",
            "presented",
            "--credential",
            CREDENTIAL_NAME,
        ],
    )

    with pytest.raises(SystemExit) as refused:
        admit.main()

    assert "is not one of credential" in str(refused.value)


def test_no_items_admitted(
    collection: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    document = json.loads((DATA / "presentation.json").read_text())
    response = cbor2.loads(bytes.fromhex(document["mdoc"]))
    response["documents"][0]["issuerSigned"]["nameSpaces"] = {}
    document["mdoc"] = cbor2.dumps(response).hex()
    source = tmp_path / "presentation-no-items.json"
    source.write_text(json.dumps(document))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "presentation",
            str(source),
            "--generator",
            GENERATOR,
            "--name",
            "presented",
            "--credential",
            CREDENTIAL_NAME,
        ],
    )

    admit.main()

    sidecar = json.loads((records.PRESENTATIONS / "presented.json").read_text())
    assert sidecar["credential"] == CREDENTIAL_NAME
