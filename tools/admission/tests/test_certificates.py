import json
import sys
from datetime import date
from pathlib import Path

import pytest

import admit
from admission import records

DATA = Path(__file__).parent / "data"
GENERATOR = "generate.py certificate --name signer --serial 2"
REF = "0" * 40


def test_generator_provenance(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "certificate",
            str(DATA / "ds-certificate.pem"),
            "--generator",
            GENERATOR,
            "--ref",
            REF,
            "--name",
            "signer",
            "--role",
            "document-signer",
        ],
    )

    admit.main()

    sidecar = json.loads((records.CERTIFICATES / "signer.json").read_text())
    assert sidecar["provenance"] == {
        "type": "constructed",
        "generator": GENERATOR,
        "ref": REF,
        "created": date.today().isoformat(),
    }


def test_ref_without_generator_rejected(
    collection: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "certificate",
            str(DATA / "ds-certificate.pem"),
            "--repo",
            "github.com/pipe23-org/longfellow-vectors",
            "--ref",
            REF,
            "--name",
            "signer",
            "--role",
            "document-signer",
        ],
    )

    with pytest.raises(SystemExit) as refused:
        admit.main()

    assert refused.value.code == 2
    assert "--ref requires --generator" in capsys.readouterr().err


def test_generator_without_ref_rejected(
    collection: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "certificate",
            str(DATA / "ds-certificate.pem"),
            "--generator",
            GENERATOR,
            "--name",
            "signer",
            "--role",
            "document-signer",
        ],
    )

    with pytest.raises(SystemExit) as refused:
        admit.main()

    assert refused.value.code == 2
    assert "--generator requires --ref" in capsys.readouterr().err
