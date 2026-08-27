import sys
from datetime import UTC, datetime
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import generate
from generation import credential, staging

DS_CERTIFICATE_NAME = "ds-certificate"
DEVICE_KEY_NAME = "device-key"
DOCTYPE = "eu.europa.ec.av.1"
NAMESPACE = "eu.europa.ec.av.1"
CLAIMS = [[NAMESPACE, "age_over_18", "true"], [NAMESPACE, "age_over_21", "true"]]
VALID_FROM = datetime(2026, 1, 1, tzinfo=UTC)
VALID_UNTIL = datetime(2027, 1, 1, tzinfo=UTC)
SEED = "00" * 31 + "07"


def test_staged_bytes_are_issuer_signed(collection: Path) -> None:
    credential.credential(
        "generate.py credential --name staged",
        "staged",
        DS_CERTIFICATE_NAME,
        DEVICE_KEY_NAME,
        DOCTYPE,
        CLAIMS,
        VALID_FROM,
        VALID_UNTIL,
        SEED,
    )

    staged = cbor2.loads((staging.STAGING / "staged" / "staged.cbor").read_bytes())
    assert set(staged) == {"nameSpaces", "issuerAuth"}


def test_one_seed_gives_one_credential(collection: Path) -> None:
    credential.credential(
        "generate.py credential --name first",
        "first",
        DS_CERTIFICATE_NAME,
        DEVICE_KEY_NAME,
        DOCTYPE,
        CLAIMS,
        VALID_FROM,
        VALID_UNTIL,
        SEED,
    )
    credential.credential(
        "generate.py credential --name second",
        "second",
        DS_CERTIFICATE_NAME,
        DEVICE_KEY_NAME,
        DOCTYPE,
        CLAIMS,
        VALID_FROM,
        VALID_UNTIL,
        SEED,
    )

    first = (staging.STAGING / "first" / "first.cbor").read_bytes()
    second = (staging.STAGING / "second" / "second.cbor").read_bytes()
    assert first == second


def test_salts_differ_across_identifiers(collection: Path) -> None:
    credential.credential(
        "generate.py credential --name staged",
        "staged",
        DS_CERTIFICATE_NAME,
        DEVICE_KEY_NAME,
        DOCTYPE,
        CLAIMS,
        VALID_FROM,
        VALID_UNTIL,
        SEED,
    )

    staged = cbor2.loads((staging.STAGING / "staged" / "staged.cbor").read_bytes())
    items = [cbor2.loads(item.value) for item in staged["nameSpaces"][NAMESPACE]]
    assert [item["elementIdentifier"] for item in items] == ["age_over_18", "age_over_21"]
    assert items[0]["random"] != items[1]["random"]


def test_device_key_info_holds_the_device_key(collection: Path) -> None:
    credential.credential(
        "generate.py credential --name staged",
        "staged",
        DS_CERTIFICATE_NAME,
        DEVICE_KEY_NAME,
        DOCTYPE,
        CLAIMS,
        VALID_FROM,
        VALID_UNTIL,
        SEED,
    )

    staged = cbor2.loads((staging.STAGING / "staged" / "staged.cbor").read_bytes())
    mso = cbor2.loads(cbor2.loads(staged["issuerAuth"][2]).value)
    device_key = load_pem_private_key(
        staging.collection().mdoc.key(DEVICE_KEY_NAME).pem, password=None
    )
    numbers = device_key.public_key().public_numbers()
    cose_key = mso["deviceKeyInfo"]["deviceKey"]
    assert cose_key[-2] == numbers.x.to_bytes(32, "big")
    assert cose_key[-3] == numbers.y.to_bytes(32, "big")


def test_x5chain_leaf_is_the_ds_certificate(collection: Path) -> None:
    credential.credential(
        "generate.py credential --name staged",
        "staged",
        DS_CERTIFICATE_NAME,
        DEVICE_KEY_NAME,
        DOCTYPE,
        CLAIMS,
        VALID_FROM,
        VALID_UNTIL,
        SEED,
    )

    staged = cbor2.loads((staging.STAGING / "staged" / "staged.cbor").read_bytes())
    assert (
        staged["issuerAuth"][1][33]
        == staging.collection().mdoc.certificate(DS_CERTIFICATE_NAME).der
    )


def test_claim_is_required(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate.py",
            "credential",
            "--name",
            "staged",
            "--ds-certificate",
            DS_CERTIFICATE_NAME,
            "--device-key",
            DEVICE_KEY_NAME,
            "--valid-from",
            "2026-01-01T00:00:00+00:00",
            "--valid-until",
            "2027-01-01T00:00:00+00:00",
        ],
    )

    with pytest.raises(SystemExit) as refused:
        generate.main()

    assert refused.value.code == 2
    assert "--claim" in capsys.readouterr().err
