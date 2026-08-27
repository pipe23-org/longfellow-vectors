import json
from pathlib import Path

import cbor2

from generation import mdoc, presentation, staging

CREDENTIAL_NAME = "av-credential"
NAMESPACE = "eu.europa.ec.av.1"
TRANSCRIPT = (
    "83f6f68265646361706958200000000000000000000000000000000000000000000000000000000000000000"
)


def test_issuer_auth_carried(collection: Path) -> None:
    presentation.presentation(
        "generate.py presentation --name presented",
        "presented",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [],
        [],
    )

    document = json.loads((staging.STAGING / "presented" / "presentation.json").read_text())
    response = cbor2.loads(bytes.fromhex(document["mdoc"]))
    credential = cbor2.loads(staging.collection().mdoc.credential(CREDENTIAL_NAME).bytes)
    assert response["documents"][0]["issuerSigned"]["issuerAuth"] == credential["issuerAuth"]


def test_disclose_subset(collection: Path) -> None:
    presentation.presentation(
        "generate.py presentation --name presented",
        "presented",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [],
        [[NAMESPACE, "age_over_18"]],
    )

    document = json.loads((staging.STAGING / "presented" / "presentation.json").read_text())
    response = cbor2.loads(bytes.fromhex(document["mdoc"]))
    items = response["documents"][0]["issuerSigned"]["nameSpaces"][NAMESPACE]
    assert [cbor2.loads(item.value)["elementIdentifier"] for item in items] == ["age_over_18"]


def test_disclose_keeps_mso(collection: Path) -> None:
    presentation.presentation(
        "generate.py presentation --name presented",
        "presented",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [],
        [[NAMESPACE, "age_over_18"]],
    )

    document = json.loads((staging.STAGING / "presented" / "presentation.json").read_text())
    response = cbor2.loads(bytes.fromhex(document["mdoc"]))
    credential = cbor2.loads(staging.collection().mdoc.credential(CREDENTIAL_NAME).bytes)
    assert response["documents"][0]["issuerSigned"]["issuerAuth"][2] == credential["issuerAuth"][2]


def test_empty_device_namespaces(collection: Path) -> None:
    presentation.presentation(
        "generate.py presentation --name presented",
        "presented",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [],
        [],
    )

    document = json.loads((staging.STAGING / "presented" / "presentation.json").read_text())
    response = cbor2.loads(bytes.fromhex(document["mdoc"]))
    assert cbor2.loads(response["documents"][0]["deviceSigned"]["nameSpaces"].value) == {}


def test_device_namespace_signed(collection: Path) -> None:
    presentation.presentation(
        "generate.py presentation --name presented",
        "presented",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [[NAMESPACE, "nym", '"c7a1"']],
        [],
    )

    document = json.loads((staging.STAGING / "presented" / "presentation.json").read_text())
    response = cbor2.loads(bytes.fromhex(document["mdoc"]))
    assert cbor2.loads(response["documents"][0]["deviceSigned"]["nameSpaces"].value) == {
        NAMESPACE: {"nym": "c7a1"}
    }


def test_device_signature(collection: Path) -> None:
    presentation.presentation(
        "generate.py presentation --name presented",
        "presented",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [[NAMESPACE, "nym", '"c7a1"']],
        [],
    )

    document = json.loads((staging.STAGING / "presented" / "presentation.json").read_text())
    mdoc.verify_device_authentication(
        bytes.fromhex(document["mdoc"]), bytes.fromhex(document["transcript"])
    )


def test_presentation_reproducible(collection: Path) -> None:
    presentation.presentation(
        "generate.py presentation --name first",
        "first",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [],
        [],
    )
    presentation.presentation(
        "generate.py presentation --name second",
        "second",
        CREDENTIAL_NAME,
        TRANSCRIPT,
        [],
        [],
    )

    first = json.loads((staging.STAGING / "first" / "presentation.json").read_text())
    second = json.loads((staging.STAGING / "second" / "presentation.json").read_text())
    assert first["mdoc"] == second["mdoc"]
