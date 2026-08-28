import json
import sys
from pathlib import Path

import cbor2
import pytest

import admit
from admission import mdoc, records

DATA = Path(__file__).parent / "data"
GENERATOR = "generate.py proof --name p"
NAMESPACE = "org.iso.18013.5.1"
OTHER_NAMESPACE = "org.iso.18013.5.1.aamva"
TIMESTAMP = "2026-08-28T00:00:00+00:00"
PRESENTATION_NAME = "av-presentation"


def _issuer_signed_item(identifier: str, value: object) -> cbor2.CBORTag:
    item = {"digestID": 0, "random": b"\x00" * 16, "elementIdentifier": identifier}
    item["elementValue"] = value
    return cbor2.CBORTag(24, cbor2.dumps(item))


def _device_response(name_spaces: dict[str, list[cbor2.CBORTag]]) -> bytes:
    return cbor2.dumps(
        {
            "version": "1.0",
            "documents": [
                {"docType": "eu.europa.ec.av.1", "issuerSigned": {"nameSpaces": name_spaces}}
            ],
            "status": 0,
        }
    )


def test_claims_from_ids_resolves_the_same_id_in_two_namespaces() -> None:
    mdoc_bytes = _device_response(
        {
            NAMESPACE: [_issuer_signed_item("age_over_18", True)],
            OTHER_NAMESPACE: [_issuer_signed_item("age_over_18", False)],
        }
    )

    claims = mdoc.claims_from_ids(
        [[NAMESPACE, "age_over_18"], [OTHER_NAMESPACE, "age_over_18"]], mdoc_bytes
    )

    assert claims == [
        {"namespace": NAMESPACE, "id": "age_over_18", "cbor_value": cbor2.dumps(True).hex()},
        {"namespace": OTHER_NAMESPACE, "id": "age_over_18", "cbor_value": cbor2.dumps(False).hex()},
    ]


def test_claims_from_ids_names_the_namespace_it_could_not_find() -> None:
    mdoc_bytes = _device_response({NAMESPACE: [_issuer_signed_item("age_over_18", True)]})

    with pytest.raises(SystemExit) as refused:
        mdoc.claims_from_ids([[OTHER_NAMESPACE, "age_over_18"]], mdoc_bytes)

    assert f"{OTHER_NAMESPACE}/age_over_18" in str(refused.value)


def _admit_presentation(monkeypatch: pytest.MonkeyPatch) -> None:
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
            PRESENTATION_NAME,
        ],
    )
    admit.main()


def test_proof_from_presentation_without_timestamp_refused(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _admit_presentation(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "proof",
            str(DATA / "device-key.pem"),
            "--generator",
            GENERATOR,
            "--name",
            "proof",
            "--presentation",
            PRESENTATION_NAME,
            "--attr",
            "eu.europa.ec.av.1",
            "age_over_18",
        ],
    )

    with pytest.raises(SystemExit) as refused:
        admit.main()

    assert "--timestamp is required" in str(refused.value)
    assert not (records.PROOFS / "proof.json").exists()


def test_proof_from_presentation_records_the_namespaced_claim(
    collection: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _admit_presentation(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "proof",
            str(DATA / "device-key.pem"),
            "--generator",
            GENERATOR,
            "--name",
            "proof",
            "--presentation",
            PRESENTATION_NAME,
            "--attr",
            "eu.europa.ec.av.1",
            "age_over_18",
            "--timestamp",
            TIMESTAMP,
        ],
    )

    admit.main()

    sidecar = json.loads((records.PROOFS / "proof.json").read_text())
    assert sidecar["claims"] == [
        {"namespace": "eu.europa.ec.av.1", "id": "age_over_18", "cbor_value": "f5"}
    ]
    assert sidecar["timestamp"] == TIMESTAMP
