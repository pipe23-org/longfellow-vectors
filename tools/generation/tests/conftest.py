"""The generated circuit and the temporary collection the command tests read vectors from."""

import hashlib
import json
from pathlib import Path

import pytest

from generation import staging

DATA = Path(__file__).parent / "data"
CREDENTIAL_NAME = "av-credential"
DOCTYPE = "eu.europa.ec.av.1"
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
    """A collection holding a trust chain, a credential, a presentation, a circuit, and a proof.

    The keys, certificates, and credential under tests/data were built with
    `generation.mdoc` under fixed P-256 scalars: ca-key certifies itself,
    ds-certificate certifies issuer-key under ca-key, and the credential is
    issuer-signed under issuer-key over age_over_18 and age_over_21 in
    eu.europa.ec.av.1, binding device-key. ds-certificate-no-key holds the same
    PEM as ds-certificate with no `key` reference.

    The commands read the collection and write the staging tree through
    `generation.staging`, so both are pointed at the temporary directory.
    """
    root = tmp_path / "mdoc"
    for subtree in ("keys", "certificates", "credentials", "presentations", "circuits", "proofs"):
        (root / subtree).mkdir(parents=True)

    for name, role in (
        ("ca-key", "iaca"),
        ("issuer-key", "document-signer"),
        ("device-key", "device"),
    ):
        key_pem = (DATA / f"{name}.pem").read_bytes()
        (root / "keys" / f"{name}.pem").write_bytes(key_pem)
        (root / "keys" / f"{name}.json").write_text(
            json.dumps(
                {
                    "schema": "mdoc-keys-v1.schema.json",
                    "role": role,
                    "sha256": hashlib.sha256(key_pem).hexdigest(),
                    "provenance": PROVENANCE,
                },
                indent=2,
            )
            + "\n"
        )

    for name, source, references in (
        ("ca-certificate", "ca-certificate", {"role": "iaca", "key": "ca-key"}),
        (
            "ds-certificate",
            "ds-certificate",
            {"role": "document-signer", "signed_by": "ca-certificate", "key": "issuer-key"},
        ),
        (
            "ds-certificate-no-key",
            "ds-certificate",
            {"role": "document-signer", "signed_by": "ca-certificate"},
        ),
    ):
        certificate_pem = (DATA / f"{source}.pem").read_bytes()
        (root / "certificates" / f"{name}.pem").write_bytes(certificate_pem)
        (root / "certificates" / f"{name}.json").write_text(
            json.dumps(
                {
                    "schema": "mdoc-certificates-v1.schema.json",
                    "sha256": hashlib.sha256(certificate_pem).hexdigest(),
                    **references,
                    "provenance": PROVENANCE,
                },
                indent=2,
            )
            + "\n"
        )

    credential = (DATA / "credential.cbor").read_bytes()
    (root / "credentials" / f"{CREDENTIAL_NAME}.cbor").write_bytes(credential)
    (root / "credentials" / f"{CREDENTIAL_NAME}.json").write_text(
        json.dumps(
            {
                "schema": "mdoc-credentials-v1.schema.json",
                "sha256": hashlib.sha256(credential).hexdigest(),
                "doctype": DOCTYPE,
                "device_key": "device-key",
                "ds_certificate": "ds-certificate",
                "provenance": PROVENANCE,
            },
            indent=2,
        )
        + "\n"
    )

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
