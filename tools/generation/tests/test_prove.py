from datetime import UTC, datetime
from pathlib import Path

import pytest
from pylongfellow import Pylongfellow
from pylongfellow.backends import google_cpp
from pylongfellow.mdoc import PublicKey, RequestedAttribute

from generation import prove, staging

PRESENTATION_NAME = "smoke"
CIRCUIT_NAME = "v7-1attr"
BACKEND = "google-cpp"
ATTR_ID = "age_over_18"
DOCTYPE = "eu.europa.ec.av.1"
NAME = "proved"
TIMESTAMP = datetime(2026, 8, 2, tzinfo=UTC)


def test_proof_verifies(collection: Path) -> None:
    prove.prove(
        "generate.py proof",
        NAME,
        PRESENTATION_NAME,
        CIRCUIT_NAME,
        BACKEND,
        [ATTR_ID],
        TIMESTAMP,
    )

    proof = (staging.STAGING / NAME / f"{NAME}.proof").read_bytes()
    vectors = staging.collection()
    presentation = vectors.mdoc.presentation(PRESENTATION_NAME)
    circuit = vectors.mdoc.circuit(CIRCUIT_NAME)
    claim = next(claim for claim in presentation.claims() if claim.id == ATTR_ID)
    assert presentation.issuer_public_key is not None
    assert presentation.transcript is not None
    longfellow = Pylongfellow(backend=BACKEND)
    longfellow.load_circuit(
        google_cpp.find_zk_spec(circuit.system, google_cpp.circuit_id(circuit.bytes)),
        circuit.bytes,
    )
    longfellow.verify(
        PublicKey(presentation.issuer_public_key.x, presentation.issuer_public_key.y),
        presentation.transcript,
        [RequestedAttribute(claim.namespace, claim.id, claim.cbor_value)],
        TIMESTAMP,
        proof,
        DOCTYPE,
        device_namespaces=presentation.device_namespaces,
    )


def test_wrong_attribute_count_rejected(collection: Path) -> None:
    with pytest.raises(SystemExit) as refused:
        prove.prove(
            "generate.py proof",
            NAME,
            PRESENTATION_NAME,
            CIRCUIT_NAME,
            BACKEND,
            [ATTR_ID, ATTR_ID],
            TIMESTAMP,
        )

    assert "2 attributes given" in str(refused.value)
    assert "proves over 1" in str(refused.value)
