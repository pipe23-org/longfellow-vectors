"""The generated circuit and the temporary collection the mode tests read vectors from."""

import hashlib
import json
from pathlib import Path

import pytest
from pylongfellow import Pylongfellow
from pylongfellow.backends import google_cpp

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
    """The compiled-in v7 one-attribute circuit, generated once because a call takes about 15 s."""
    spec = next(
        spec
        for spec in google_cpp.zk_specs()
        if spec.version == CIRCUIT_VERSION and spec.num_attributes == CIRCUIT_ATTRIBUTES
    )
    return Pylongfellow(backend=PROVER).generate_circuit(spec)


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
