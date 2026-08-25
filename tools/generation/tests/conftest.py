"""The generated circuit and the temporary collection the mode tests read vectors from."""

import hashlib
import json
from pathlib import Path

import pytest

from generation import staging

DATA = Path(__file__).parent / "data"
PRESENTATION_NAME = "smoke"
CIRCUIT_NAME = "v7-1attr"
PROOF_NAME = "source"
CIRCUIT_VERSION = 7
CIRCUIT_ATTRIBUTES = 1
PROVER = "google-cpp"
TIMESTAMP = "2026-08-02T00:00:00Z"
CLAIM = {"namespace": "eu.europa.ec.av.1", "id": "age_over_18", "cbor_value": "f5"}
SOURCE_PROOF = bytes(range(64))
PROVENANCE = {
    "type": "constructed",
    "generator": "tools/generation/tests/conftest.py",
    "created": "2026-08-25",
}


@pytest.fixture(scope="session")
def circuit() -> bytes:
    """google/longfellow-zk's v7 one-attribute circuit export.

    lib/circuits/mdoc/circuits/8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121
    at fe83ec6, copied from pylongfellow 36916aa tests/api/data/circuits/.
    """
    return (DATA / "v7-1attr.circuit").read_bytes()


@pytest.fixture
def collection(tmp_path: Path, circuit: bytes, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A collection holding the staged presentation, the v7 circuit, and a proof over both.

    The modes read the collection and write the staging tree through
    `generation.staging`, so both are pointed at the temporary directory.
    """
    root = tmp_path / "mdoc"
    for subtree in ("presentations", "circuits", "proofs"):
        (root / subtree).mkdir(parents=True)

    presentation = json.loads((DATA / "presentation.json").read_text())
    (root / "presentations" / f"{PRESENTATION_NAME}.json").write_text(
        json.dumps(presentation, indent=2) + "\n"
    )

    (root / "circuits" / f"{CIRCUIT_NAME}.circuit").write_bytes(circuit)
    (root / "circuits" / f"{CIRCUIT_NAME}.json").write_text(
        json.dumps(
            {
                "schema": "mdoc-circuits-v1.schema.json",
                "system": "longfellow-libzk-v1",
                "sha256": hashlib.sha256(circuit).hexdigest(),
                "version": CIRCUIT_VERSION,
                "num_attributes": CIRCUIT_ATTRIBUTES,
                "provenance": PROVENANCE,
            },
            indent=2,
        )
        + "\n"
    )

    (root / "proofs" / f"{PROOF_NAME}.proof").write_bytes(SOURCE_PROOF)
    (root / "proofs" / f"{PROOF_NAME}.json").write_text(
        json.dumps(
            {
                "schema": "mdoc-proofs-v1.schema.json",
                "prover": PROVER,
                "circuit": CIRCUIT_NAME,
                "sha256": hashlib.sha256(SOURCE_PROOF).hexdigest(),
                "doctype": presentation["doctype"],
                "claims": [CLAIM],
                "transcript": presentation["transcript"],
                "issuer_public_key_x": presentation["issuer_public_key_x"],
                "issuer_public_key_y": presentation["issuer_public_key_y"],
                "timestamp": TIMESTAMP,
                "device_namespaces": presentation["device_namespaces"],
                "presentation": PRESENTATION_NAME,
                "provenance": PROVENANCE,
            },
            indent=2,
        )
        + "\n"
    )

    monkeypatch.setattr(staging, "VECTORS", root)
    monkeypatch.setattr(staging, "STAGING", tmp_path / "staging")
    return root
