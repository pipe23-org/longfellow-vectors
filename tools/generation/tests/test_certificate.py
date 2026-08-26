"""certificate signs under the key its inputs name and records the serial it used."""

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key

from generation import certificate, staging

SUBJECT = "pipe23 staged signer"
KEY_NAME = "issuer-key"
CA_NAME = "ca-certificate"
VALID_FROM = datetime(2026, 1, 1, tzinfo=UTC)
VALID_UNTIL = datetime(2027, 1, 1, tzinfo=UTC)
SERIAL = 4919


def test_self_signed_certificate_verifies_under_its_subject_key(collection: Path) -> None:
    certificate.certificate(
        "generate.py certificate --name self-signed",
        "self-signed",
        KEY_NAME,
        None,
        SUBJECT,
        None,
        False,
        VALID_FROM,
        VALID_UNTIL,
        SERIAL,
    )

    staged = x509.load_pem_x509_certificate(
        (staging.STAGING / "self-signed" / "self-signed.pem").read_bytes()
    )
    subject_key = load_pem_private_key(staging.collection().mdoc.key(KEY_NAME).pem, password=None)
    subject_key.public_key().verify(
        staged.signature, staged.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )


def test_signed_certificate_verifies_under_the_signers_key_reference(collection: Path) -> None:
    certificate.certificate(
        "generate.py certificate --name leaf",
        "leaf",
        KEY_NAME,
        CA_NAME,
        SUBJECT,
        None,
        False,
        VALID_FROM,
        VALID_UNTIL,
        SERIAL,
    )

    staged = x509.load_pem_x509_certificate((staging.STAGING / "leaf" / "leaf.pem").read_bytes())
    signer = staging.collection().mdoc.certificate(CA_NAME)
    assert signer.key is not None, f"certificate {CA_NAME} records no key vector"
    signing_key = load_pem_private_key(signer.key.pem, password=None)
    signing_key.public_key().verify(
        staged.signature, staged.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )


def test_one_serial_gives_one_certificate(collection: Path) -> None:
    certificate.certificate(
        "generate.py certificate --name first",
        "first",
        KEY_NAME,
        CA_NAME,
        SUBJECT,
        None,
        False,
        VALID_FROM,
        VALID_UNTIL,
        SERIAL,
    )
    certificate.certificate(
        "generate.py certificate --name second",
        "second",
        KEY_NAME,
        CA_NAME,
        SUBJECT,
        None,
        False,
        VALID_FROM,
        VALID_UNTIL,
        SERIAL,
    )

    first = x509.load_pem_x509_certificate((staging.STAGING / "first" / "first.pem").read_bytes())
    second = x509.load_pem_x509_certificate(
        (staging.STAGING / "second" / "second.pem").read_bytes()
    )
    assert first.public_bytes(Encoding.DER) == second.public_bytes(Encoding.DER)


def test_command_carries_the_serial_it_generated(
    collection: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    certificate.certificate(
        "generate.py certificate --name generated",
        "generated",
        KEY_NAME,
        CA_NAME,
        SUBJECT,
        None,
        False,
        VALID_FROM,
        VALID_UNTIL,
        None,
    )

    printed = capsys.readouterr().out
    generated = x509.load_pem_x509_certificate(
        (staging.STAGING / "generated" / "generated.pem").read_bytes()
    )
    recorded = re.search(r"--serial ([0-9]+)", printed)
    assert recorded is not None, "the printed command carries no --serial"
    certificate.certificate(
        "generate.py certificate --name repeated",
        "repeated",
        KEY_NAME,
        CA_NAME,
        SUBJECT,
        None,
        False,
        VALID_FROM,
        VALID_UNTIL,
        int(recorded.group(1)),
    )
    repeated = x509.load_pem_x509_certificate(
        (staging.STAGING / "repeated" / "repeated.pem").read_bytes()
    )
    assert repeated.public_bytes(Encoding.DER) == generated.public_bytes(Encoding.DER)


def test_signer_without_a_key_reference_is_refused(collection: Path) -> None:
    with pytest.raises(SystemExit) as refused:
        certificate.certificate(
            "generate.py certificate --name leaf",
            "leaf",
            KEY_NAME,
            "ds-certificate-no-key",
            SUBJECT,
            None,
            False,
            VALID_FROM,
            VALID_UNTIL,
            SERIAL,
        )

    assert "records no key vector" in str(refused.value)
