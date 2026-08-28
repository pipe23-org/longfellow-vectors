import json
import sys
from pathlib import Path

import pytest

import admit
from admission import records

DATA = Path(__file__).parent / "data"
GENERATOR = "generate.py certificate --name signer --serial 2"


def test_generator_provenance(collection: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    admit.main()

    sidecar = json.loads((records.CERTIFICATES / "signer.json").read_text())
    assert sidecar["provenance"] == {
        "type": "constructed",
        "generator": GENERATOR,
    }
