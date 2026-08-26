"""admit.py presentation --credential verifies the response against the credential it names."""

import json
import sys
from pathlib import Path

import pytest

import admit
from admission import records

DATA = Path(__file__).parent / "data"
CREDENTIAL_NAME = "av-credential"
GENERATOR = "generate.py presentation --name presented"


def test_response_presenting_the_credential_is_admitted(
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


def test_response_under_another_issuer_auth_is_refused(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def test_item_the_credential_does_not_hold_is_refused(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
