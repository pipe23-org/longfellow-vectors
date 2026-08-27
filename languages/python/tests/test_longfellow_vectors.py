import dataclasses
import json
import shutil
from pathlib import Path
from typing import Any

import cbor2
import pytest

from longfellow_vectors import CorpusError, LongfellowVectors, PublicKey
from longfellow_vectors import mdoc as mdoc_module

DATA = Path(__file__).parent / "data"
VALID_COLLECTION = DATA / "corpus"
BROKEN_TREES = DATA / "trees"
REJECTED_SIDECARS = DATA / "invalid"


EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

ROOT_CA_PEM = (VALID_COLLECTION / "certificates" / "root-ca.pem").read_bytes()
SIGNER_PEM = (VALID_COLLECTION / "certificates" / "signer.pem").read_bytes()
FULL_KEY_PEM = (VALID_COLLECTION / "keys" / "full-key.pem").read_bytes()
FULL_CRED_CBOR = (VALID_COLLECTION / "credentials" / "full-cred.cbor").read_bytes()

MISSING_STATEMENT_FIELDS = [
    pytest.param(
        {"doctype": None},
        "proof synthetic-v1: statement field doctype not recorded",
        id="doctype",
    ),
    pytest.param(
        {"transcript": None},
        "proof synthetic-v1: statement field transcript not recorded",
        id="transcript",
    ),
    pytest.param(
        {"issuer_public_key": None},
        "proof synthetic-v1: statement field issuer_public_key not recorded",
        id="issuer-public-key",
    ),
    pytest.param(
        {"claims": None},
        "proof synthetic-v1: statement field claims not recorded",
        id="claims-absent",
    ),
    pytest.param(
        {"claims": ()},
        "proof synthetic-v1: statement field claims not recorded",
        id="claims-empty",
    ),
    pytest.param(
        {"timestamp": None},
        "proof synthetic-v1: statement field timestamp not recorded",
        id="timestamp",
    ),
]

REJECTED_SIDECAR_MESSAGES = [
    pytest.param(
        "unknown-schema.json", r"names no known vector schema: 'widget\.schema\.json'", id="schema"
    ),
    pytest.param("not-an-object.json", r"names no known vector schema: None", id="not-an-object"),
    pytest.param("missing-required.json", r"'system' is a required property", id="no-system"),
    pytest.param("missing-version.json", r"'version' is a required property", id="no-version"),
    pytest.param("bad-hex.json", r"does not match", id="uppercase-hex"),
    pytest.param(
        "extra-property.json",
        r"Additional properties are not allowed \('bogus'",
        id="extra-property",
    ),
    pytest.param("short-ref.json", r"is not valid under any of the given schemas", id="short-ref"),
    pytest.param(
        "provenance-type.json",
        r"is not valid under any of the given schemas",
        id="provenance-type",
    ),
    pytest.param("empty-claims.json", r"\[\] should be non-empty", id="empty-claims"),
    pytest.param("bad-timestamp.json", r"'garbage' is not a 'date-time'", id="bad-timestamp"),
    pytest.param("bad-date.json", r"'2026-13-01' is not a 'date'", id="bad-date"),
    pytest.param("nonstring-formats.json", r"5 is not of type 'string'", id="nonstring-timestamp"),
    pytest.param("trailing-newline.json", r"does not match", id="trailing-newline"),
    pytest.param(
        "date-basic-form.json",
        r"is not valid under any of the given schemas",
        id="date-basic-form",
    ),
    pytest.param(
        "timestamp-bare-date.json",
        r"'2024-10-01' is not a 'date-time'",
        id="timestamp-bare-date",
    ),
    pytest.param(
        "timestamp-no-offset.json",
        r"'2024-10-01T09:00:00' is not a 'date-time'",
        id="timestamp-no-offset",
    ),
    pytest.param(
        "public-key-x-alone.json",
        r"'public_key_y' is a dependency of 'public_key_x'",
        id="public-key-x-alone",
    ),
]

MALFORMED_CLAIM_PAYLOADS = [
    pytest.param(cbor2.dumps(42), "payload is not a CBOR map", id="not-a-map"),
    pytest.param(cbor2.dumps({}), "payload has no documents array", id="no-documents"),
    pytest.param(cbor2.dumps({"documents": [42]}), "document is not a CBOR map", id="document-int"),
    pytest.param(
        cbor2.dumps({"documents": [{}]}), "document has no issuerSigned map", id="no-issuer-signed"
    ),
    pytest.param(
        cbor2.dumps({"documents": [{"issuerSigned": {}}]}),
        "issuerSigned has no nameSpaces map",
        id="no-namespaces",
    ),
    pytest.param(
        cbor2.dumps({"documents": [{"issuerSigned": {"nameSpaces": {"ns": 42}}}]}),
        "nameSpaces.*is not an array",
        id="namespace-int",
    ),
    pytest.param(
        cbor2.dumps({"documents": [{"issuerSigned": {"nameSpaces": {"ns": [b"raw"]}}}]}),
        "nameSpaces item is not tag-24 wrapped",
        id="item-untagged",
    ),
    pytest.param(
        cbor2.dumps(
            {
                "documents": [
                    {"issuerSigned": {"nameSpaces": {"ns": [cbor2.CBORTag(24, cbor2.dumps(42))]}}}
                ]
            }
        ),
        "tag-24 content is not a map",
        id="tag24-int",
    ),
    pytest.param(
        cbor2.dumps(
            {
                "documents": [
                    {
                        "issuerSigned": {
                            "nameSpaces": {
                                "ns": [
                                    cbor2.CBORTag(
                                        24,
                                        cbor2.dumps(
                                            {"elementIdentifier": 99, "elementValue": True}
                                        ),
                                    )
                                ]
                            }
                        }
                    }
                ]
            }
        ),
        "missing or non-string elementIdentifier",
        id="element-id-int",
    ),
]


def corpus_copy(tmp_path: Path) -> Path:
    copy = tmp_path / "corpus"
    shutil.copytree(VALID_COLLECTION, copy)
    return copy


def edit_sidecar(root: Path, rel: str, **changes: object) -> None:
    path = root / rel
    doc = json.loads(path.read_text())
    doc.update(changes)
    path.write_text(json.dumps(doc))


def test_keys_sorted_by_name() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.keys()] == [
        "bare-device",
        "full-key",
        "p256-device",
    ]


def test_key_fields() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("full-key")
    assert key.pem == FULL_KEY_PEM
    assert key.role == "iaca"
    assert key.sha256 == "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"
    assert key.fingerprint == "aa" * 32
    assert key.comment is not None
    assert key.provenance.type == "constructed"
    assert key.provenance.generator == "fixture"
    assert key.provenance.created == "2026-08-21"


def test_key_optional_fields_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("bare-device")
    assert key.pem == b""
    assert key.role == "device"
    assert key.sha256 == EMPTY_SHA256
    assert key.fingerprint is None
    assert key.provenance.type == "repository"
    assert key.provenance.repo == "github.com/example/fixtures"


def test_key_material() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("full-key")
    assert key.public_key == PublicKey(x=int("77" * 32, 16), y=int("88" * 32, 16))
    assert key.private_key == int("99" * 32, 16)


def test_key_material_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("bare-device")
    assert key.public_key is None
    assert key.private_key is None


def test_key_der() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("p256-device")
    der = key.der
    assert len(der) == 138
    assert der[:16] == bytes.fromhex("308187020100301306072a8648ce3d02")


def test_key_der_rejects_malformed_pem() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("bare-device")
    with pytest.raises(ValueError, match="bare-device: not a single PEM block"):
        _ = key.der


def test_credentials_sorted_by_name() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.credentials()] == [
        "bare-cred",
        "claims-cred",
        "ds-cred",
        "full-cred",
    ]


def test_credential_fields() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("full-cred")
    assert credential.bytes == FULL_CRED_CBOR
    assert credential.sha256 == "0a43b22d89fa2499be5c7704c9bf273260b0ca9588e4cd1897cd80f9c96cd97a"
    assert credential.doctype == "org.iso.18013.5.1.mDL"
    assert credential.provenance.type == "constructed"


def test_credential_optional_fields_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("bare-cred")
    assert credential.bytes == b""
    assert credential.sha256 == EMPTY_SHA256
    assert credential.doctype is None
    assert credential.device_key is None
    assert credential.ds_certificate is None
    assert credential.provenance.type == "repository"


def test_credential_device_key_resolves() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("full-cred")
    assert credential.device_key is not None
    assert credential.device_key.name == "full-key"
    assert credential.ds_certificate is None


def test_credential_ds_certificate_resolves() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("ds-cred")
    assert credential.ds_certificate is not None
    assert credential.ds_certificate.name == "signer"
    assert credential.device_key is None


def test_credential_unknown_device_key_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "credentials/full-cred.json", device_key="no-such-key")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="device_key 'no-such-key' matches no key vector"):
        vectors.mdoc.credentials()


def test_credential_unknown_ds_certificate_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "credentials/ds-cred.json", ds_certificate="no-such-cert")
    vectors = LongfellowVectors(root)
    with pytest.raises(
        CorpusError, match="ds_certificate 'no-such-cert' matches no certificate vector"
    ):
        vectors.mdoc.credentials()


def test_credential_claims() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("claims-cred")
    claims = credential.claims()
    assert len(claims) == 2
    assert claims[0].namespace == "org.iso.18013.5.1"
    assert claims[0].id == "age_over_18"
    assert claims[0].cbor_value == b"\xf5"
    assert claims[1].namespace == "org.iso.18013.5.1"
    assert claims[1].id == "issue_date"
    assert claims[1].cbor_value == b"\x6a2026-01-01"


def test_credential_claims_rejects_non_cbor() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("bare-cred")
    with pytest.raises(cbor2.CBORDecodeError):
        credential.claims()


def test_presentations_sorted_by_name() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.presentations()] == [
        "bare",
        "claims",
        "full",
        "minimal",
    ]


def test_presentation_fields() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.doctype == "org.iso.18013.5.1.mDL"
    assert presentation.mdoc == b"\xa0"
    assert presentation.device_namespaces == b"\xa0"
    assert presentation.transcript == b"\x83"
    assert presentation.comment is not None


def test_presentation_constructed_provenance() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.provenance.type == "constructed"
    assert presentation.provenance.generator == "tools/generation/generate.py presentation"
    assert presentation.provenance.created == "2026-08-21"
    assert presentation.provenance.ref == "dd" * 20
    assert presentation.provenance.repo is None
    assert presentation.provenance.path is None
    assert presentation.provenance.captured is None


def test_presentation_repository_provenance() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("bare")
    assert presentation.provenance.type == "repository"
    assert presentation.provenance.repo == "github.com/example/fixtures"
    assert presentation.provenance.ref == "ab" * 20
    assert presentation.provenance.path == "inputs/bare.json"
    assert presentation.provenance.captured == "2026-08-21"
    assert presentation.provenance.index is None
    assert presentation.provenance.via is None
    assert presentation.provenance.generator is None
    assert presentation.provenance.created is None


def test_presentation_optional_fields_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("minimal")
    assert presentation.mdoc == b"\xa0"
    assert presentation.doctype is None
    assert presentation.device_namespaces is None
    assert presentation.transcript is None
    assert presentation.credential is None
    assert presentation.provenance.type == "constructed"
    assert presentation.provenance.generator == "fixture"
    assert presentation.provenance.created == "2026-08-24"


def test_presentation_issuer_public_key() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.issuer_public_key == PublicKey(x=int("11" * 32, 16), y=int("22" * 32, 16))


def test_presentation_issuer_public_key_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("minimal")
    assert presentation.issuer_public_key is None


def test_presentation_credential_resolves() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.credential is not None
    assert presentation.credential.name == "full-cred"


def test_presentation_unknown_credential_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "presentations/full.json", credential="no-such-cred")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="credential 'no-such-cred' matches no credential vector"):
        vectors.mdoc.presentations()


def test_presentation_claims() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("claims")
    claims = presentation.claims()
    assert len(claims) == 2
    assert claims[0].namespace == "org.iso.18013.5.1"
    assert claims[0].id == "age_over_18"
    assert claims[0].cbor_value == b"\xf5"
    assert claims[1].namespace == "org.iso.18013.5.1"
    assert claims[1].id == "issue_date"


def test_presentation_claims_rejects_empty_documents() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("minimal")
    with pytest.raises(ValueError, match="payload has no documents array"):
        presentation.claims()


def test_circuits_sorted_by_name() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.circuits()] == ["other", "tiny"]


def test_circuit_fields() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    circuit = vectors.mdoc.circuit("tiny")
    assert circuit.bytes == b""
    assert circuit.system == "longfellow-libzk-v1"
    assert circuit.sha256 == EMPTY_SHA256
    assert circuit.version == 6
    assert circuit.num_attributes == 1
    assert circuit.provenance.index == "circuits[0]"
    assert circuit.provenance.via == "an intermediate export"


def test_circuit_provenance_optional_fields_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    circuit = vectors.mdoc.circuit("other")
    assert circuit.sha256 == "8349d0fe15cb2c176df2f7007df8f7e8651bfdca6836bcfcd7029398c28a1797"
    assert circuit.version == 7
    assert circuit.num_attributes == 1
    assert circuit.provenance.index is None
    assert circuit.provenance.via is None


def test_circuit_fractional_version_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "circuits/tiny.json", version=6.0)
    vectors = LongfellowVectors(root)
    with pytest.raises(ValueError, match="circuits/tiny.json: version is not an integer: 6.0"):
        vectors.mdoc.circuits()


def test_circuit_fractional_num_attributes_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "circuits/tiny.json", num_attributes=1.0)
    vectors = LongfellowVectors(root)
    with pytest.raises(
        ValueError, match="circuits/tiny.json: num_attributes is not an integer: 1.0"
    ):
        vectors.mdoc.circuits()


def test_proofs_sorted_by_name() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.proofs()] == [
        "bare",
        "synthetic-v1",
        "synthetic-v2",
    ]


def test_proof_fields() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("synthetic-v1")
    assert proof.bytes == b""
    assert proof.sha256 == EMPTY_SHA256
    assert proof.prover == "synthetic"
    assert proof.doctype == "org.iso.18013.5.1.mDL"
    assert proof.claims is not None
    assert [(claim.namespace, claim.id) for claim in proof.claims] == [
        ("org.iso.18013.5.1", "age_over_18"),
        ("org.iso.18013.5.1", "issue_date"),
    ]
    assert proof.claims[0].cbor_value == b"\xf5"
    assert proof.transcript == b"\x83"
    assert proof.timestamp is not None
    assert proof.timestamp.isoformat() == "2026-08-21T12:00:00+00:00"
    assert proof.device_namespaces == b"\xa0"
    assert proof.provenance.type == "repository"
    assert proof.provenance.path == "proofs/synthetic-v1.proof"


def test_proof_optional_fields_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("synthetic-v2")
    assert proof.device_namespaces is None
    assert proof.presentation is None


def test_proof_statement_fields_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("bare")
    assert proof.bytes == b""
    assert proof.sha256 == EMPTY_SHA256
    assert proof.prover is None
    assert proof.circuit is None
    assert proof.doctype is None
    assert proof.claims is None
    assert proof.transcript is None
    assert proof.timestamp is None
    assert proof.device_namespaces is None
    assert proof.presentation is None
    assert proof.provenance.type == "constructed"
    assert proof.provenance.generator == "fixture"
    assert proof.provenance.created == "2026-08-24"


def test_proof_issuer_public_key() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("synthetic-v1")
    assert proof.issuer_public_key == PublicKey(x=int("11" * 32, 16), y=int("22" * 32, 16))


def test_proof_issuer_public_key_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("bare")
    assert proof.issuer_public_key is None


def test_proof_references_resolve() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("synthetic-v1")
    assert proof.circuit is not None
    assert proof.circuit.name == "tiny"
    assert proof.presentation is not None
    assert proof.presentation.name == "full"


def test_proof_unknown_circuit_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "proofs/synthetic-v1.json", circuit="no-such-circuit")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="circuit 'no-such-circuit' matches no circuit vector"):
        vectors.mdoc.proofs()


def test_proof_unknown_presentation_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "proofs/synthetic-v1.json", presentation="no-such-presentation")
    vectors = LongfellowVectors(root)
    with pytest.raises(
        CorpusError, match="presentation 'no-such-presentation' matches no presentation vector"
    ):
        vectors.mdoc.proofs()


def test_proof_statement() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    statement = vectors.mdoc.proof("synthetic-v1").statement()
    assert statement.doctype == "org.iso.18013.5.1.mDL"
    assert statement.transcript == b"\x83"
    assert statement.issuer_public_key == PublicKey(x=int("11" * 32, 16), y=int("22" * 32, 16))
    assert [claim.id for claim in statement.claims] == ["age_over_18", "issue_date"]
    assert statement.timestamp.isoformat() == "2026-08-21T12:00:00+00:00"
    assert statement.device_namespaces == b"\xa0"


@pytest.mark.parametrize(("changes", "message"), MISSING_STATEMENT_FIELDS)
def test_proof_statement_incomplete_rejected(changes: dict[str, Any], message: str) -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = dataclasses.replace(vectors.mdoc.proof("synthetic-v1"), **changes)
    with pytest.raises(CorpusError, match=message):
        proof.statement()


def test_certificates_sorted_by_name() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.certificates()] == [
        "keyed",
        "root-ca",
        "signer",
    ]


def test_certificate_fields() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("signer")
    assert certificate.pem == SIGNER_PEM
    assert certificate.role == "document-signer"
    assert certificate.sha256 == "40caffb079b6e5380923bcd4f0565f4b80e1aaca45d13005f140d54cecd680fd"
    assert certificate.provenance.type == "repository"
    assert certificate.provenance.path == "certificates/signer.pem"


def test_certificate_optional_fields_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("root-ca")
    assert certificate.pem == ROOT_CA_PEM
    assert certificate.role == "iaca"
    assert certificate.sha256 == "9d03e8eb237bc5212dde611f2014956e2aefcd39c827431f18365cfdd41e8181"
    assert certificate.signed_by is None
    assert certificate.key is None


def test_certificate_public_key() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("keyed")
    assert certificate.public_key == PublicKey(
        x=0x460C9D6E9D60AA81CDEEB7020998AE2F41B6100FB40FB341927189D3A7CD2692,
        y=0x52D68CFE920979229EA1BBF2B6759F84BAEA8C49BF52397BB95F1C79A1397D18,
    )


def test_certificate_public_key_absent() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("root-ca")
    assert certificate.public_key is None


def test_certificate_references_resolve() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("keyed")
    assert certificate.signed_by is not None
    assert certificate.signed_by.name == "root-ca"
    assert certificate.key is not None
    assert certificate.key.name == "full-key"


def test_certificate_signer_loaded_first(tmp_path: Path) -> None:
    certificates = tmp_path / "certificates"
    certificates.mkdir()
    for name, role, reference in (
        ("aa-child", "document-signer", {"signed_by": "zz-root"}),
        ("zz-root", "iaca", {}),
    ):
        (certificates / f"{name}.pem").write_bytes(b"")
        (certificates / f"{name}.json").write_text(
            json.dumps(
                {
                    "schema": "mdoc-certificates-v1.schema.json",
                    "role": role,
                    "sha256": EMPTY_SHA256,
                    "provenance": {
                        "type": "constructed",
                        "generator": "fixture",
                        "created": "2026-08-22",
                    },
                    **reference,
                }
            )
        )
    vectors = LongfellowVectors(tmp_path)
    certificate = vectors.mdoc.certificate("aa-child")
    assert certificate.signed_by is not None
    assert certificate.signed_by.name == "zz-root"


def test_certificate_unknown_signer_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "certificates/signer.json", signed_by="no-such-cert")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="signed_by 'no-such-cert' matches no certificate vector"):
        vectors.mdoc.certificates()


def test_certificate_unknown_key_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "certificates/keyed.json", key="no-such-key")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="key 'no-such-key' matches no key vector"):
        vectors.mdoc.certificates()


def test_certificate_signing_cycle_rejected(tmp_path: Path) -> None:
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "certificates/root-ca.json", signed_by="signer")
    vectors = LongfellowVectors(root)
    with pytest.raises(
        CorpusError, match="signing references form a cycle: keyed, root-ca, signer"
    ):
        vectors.mdoc.certificates()


def test_certificate_der() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("keyed")
    der = certificate.der
    assert len(der) == 312
    assert der[:16] == bytes.fromhex("308201343081dba00302010202010130")


def test_certificate_der_rejects_malformed_pem() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = dataclasses.replace(vectors.mdoc.certificate("root-ca"), pem=b"")
    with pytest.raises(ValueError, match="root-ca: not a single PEM block"):
        _ = certificate.der


@pytest.mark.parametrize(("payload", "match"), MALFORMED_CLAIM_PAYLOADS)
def test_presentation_claims_rejects_malformed_payload(payload: bytes, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        mdoc_module._presentation_claims(payload)


def test_credential_claims_rejects_non_map() -> None:
    with pytest.raises(ValueError, match="payload is not a CBOR map"):
        mdoc_module._credential_claims(cbor2.dumps(42))


def test_lookup_by_name() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert vectors.mdoc.key("full-key").name == "full-key"
    assert vectors.mdoc.credential("full-cred").name == "full-cred"
    assert vectors.mdoc.presentation("full").name == "full"
    assert vectors.mdoc.proof("synthetic-v1").name == "synthetic-v1"
    assert vectors.mdoc.circuit("tiny").name == "tiny"
    assert vectors.mdoc.certificate("signer").name == "signer"


def test_lookup_unknown_name_rejected() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    with pytest.raises(KeyError, match="no key vector"):
        vectors.mdoc.key("nope")
    with pytest.raises(KeyError, match="no credential vector"):
        vectors.mdoc.credential("nope")
    with pytest.raises(KeyError, match="no presentation vector"):
        vectors.mdoc.presentation("nope")
    with pytest.raises(KeyError, match="no proof vector"):
        vectors.mdoc.proof("nope")
    with pytest.raises(KeyError, match="no circuit vector"):
        vectors.mdoc.circuit("nope")
    with pytest.raises(KeyError, match="no certificate vector"):
        vectors.mdoc.certificate("nope")


def test_vectors_loaded_once() -> None:
    vectors = LongfellowVectors(VALID_COLLECTION)
    keys = vectors.mdoc.keys()
    credentials = vectors.mdoc.credentials()
    presentations = vectors.mdoc.presentations()
    proofs = vectors.mdoc.proofs()
    circuits = vectors.mdoc.circuits()
    certificates = vectors.mdoc.certificates()
    assert vectors.mdoc.keys() is keys
    assert vectors.mdoc.credentials() is credentials
    assert vectors.mdoc.presentations() is presentations
    assert vectors.mdoc.proofs() is proofs
    assert vectors.mdoc.circuits() is circuits
    assert vectors.mdoc.certificates() is certificates

    other = LongfellowVectors(VALID_COLLECTION)
    assert other.mdoc.keys() is not keys
    assert other.mdoc.credentials() is not credentials
    assert other.mdoc.presentations() is not presentations
    assert other.mdoc.proofs() is not proofs
    assert other.mdoc.circuits() is not circuits
    assert other.mdoc.certificates() is not certificates


def test_packaged_collection_checks() -> None:
    LongfellowVectors().check()


def test_check_ignores_root_dotfile(tmp_path: Path) -> None:
    (tmp_path / ".gitkeep").write_bytes(b"")
    LongfellowVectors(tmp_path).check()


def test_check_ignores_subtree_dotfile(tmp_path: Path) -> None:
    (tmp_path / "circuits").mkdir()
    (tmp_path / "circuits" / ".gitkeep").write_bytes(b"")
    (tmp_path / "presentations").mkdir()
    (tmp_path / "presentations" / ".gitkeep").write_bytes(b"")
    LongfellowVectors(tmp_path).check()


def test_load_ignores_subtree_dotfile(tmp_path: Path) -> None:
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / ".gitkeep").write_bytes(b"")
    assert LongfellowVectors(tmp_path).mdoc.keys() == ()


def test_missing_subtree_loads_empty(tmp_path: Path) -> None:
    vectors = LongfellowVectors(tmp_path)
    assert vectors.mdoc.keys() == ()
    assert vectors.mdoc.credentials() == ()
    assert vectors.mdoc.presentations() == ()
    assert vectors.mdoc.proofs() == ()
    assert vectors.mdoc.circuits() == ()
    assert vectors.mdoc.certificates() == ()


def test_load_missing_root_rejected(tmp_path: Path) -> None:
    vectors = LongfellowVectors(tmp_path / "no-such-collection")
    with pytest.raises(CorpusError, match="no-such-collection: collection root is not a directory"):
        vectors.mdoc.circuits()


def test_load_file_root_rejected(tmp_path: Path) -> None:
    root = tmp_path / "collection"
    root.write_text("a file, not a directory")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="collection: collection root is not a directory"):
        vectors.mdoc.keys()


def test_load_missing_blob_rejected() -> None:
    vectors = LongfellowVectors(BROKEN_TREES / "missing-blob")
    with pytest.raises(FileNotFoundError):
        vectors.mdoc.proofs()


def test_load_skips_non_sidecars() -> None:
    vectors = LongfellowVectors(BROKEN_TREES / "missing-blob")
    assert [record.name for record in vectors.mdoc.presentations()] == ["lone"]


def test_load_non_json_sidecar_rejected() -> None:
    vectors = LongfellowVectors(BROKEN_TREES / "malformed")
    with pytest.raises(ValueError, match=r"^circuits/broken\.json: Expecting value"):
        vectors.mdoc.circuits()


def test_load_invalid_sidecar_rejected() -> None:
    vectors = LongfellowVectors(BROKEN_TREES / "rejected")
    with pytest.raises(ValueError, match=r"circuits/bad\.json: rejected by schema"):
        vectors.mdoc.circuits()


def test_load_wrong_schema_rejected() -> None:
    vectors = LongfellowVectors(BROKEN_TREES / "integrity-violations")
    with pytest.raises(
        ValueError,
        match="keys/misplaced-schema.json: schema mdoc-circuits-v1.schema.json"
        " does not belong in keys",
    ):
        vectors.mdoc.keys()


@pytest.mark.parametrize(("filename", "match"), REJECTED_SIDECAR_MESSAGES)
def test_invalid_sidecar_error_names_violation(filename: str, match: str) -> None:
    text = (REJECTED_SIDECARS / filename).read_text()
    with pytest.raises(ValueError, match=match):
        mdoc_module._load_sidecar(text, filename)


def test_check_clean_collection() -> None:
    LongfellowVectors(VALID_COLLECTION).check()


def test_check_empty_root(tmp_path: Path) -> None:
    LongfellowVectors(tmp_path).check()


def test_check_missing_root_rejected(tmp_path: Path) -> None:
    vectors = LongfellowVectors(tmp_path / "no-such-collection")
    with pytest.raises(CorpusError, match="no-such-collection: collection root is not a directory"):
        vectors.check()


def test_check_file_root_rejected(tmp_path: Path) -> None:
    root = tmp_path / "collection"
    root.write_text("a file, not a directory")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="collection: collection root is not a directory"):
        vectors.check()


def test_check_reports_every_finding() -> None:
    vectors = LongfellowVectors(BROKEN_TREES / "integrity-violations")
    with pytest.raises(CorpusError) as excinfo:
        vectors.check()
    assert sorted(str(excinfo.value).splitlines()) == [
        "certificates/dangling-key.json: key 'no-such-key' matches no key vector",
        "certificates/orphan-signer.json: signed_by 'root-of-nothing'"
        " matches no certificate vector",
        "certificates: signing references form a cycle: loop-a, loop-b",
        "circuits/bad-json.json: Expecting value: line 1 column 1 (char 0)",
        "circuits/bad-schema.json: rejected by schema: 'system' is a required property",
        "circuits/dir-named.json: not a regular file",
        "circuits/good.proof: suffix is not .circuit",
        "circuits/hash-mismatch.circuit: sha256"
        " c3f9de1321d3643b3cb1646f7359f493b60fa4e5b70d0e1e0ba0916bdc67eb6c does not match computed"
        " d4456ce41b10ecd37420cc4c4477ed25e2d0133686e8b627a1b57ab8c4ad103e",
        "circuits/missing-blob.json: missing blob missing-blob.circuit",
        "circuits/orphan.circuit: file has no governing sidecar",
        "credentials/dangling-ds-certificate.json: ds_certificate 'no-such-certificate'"
        " matches no certificate vector",
        "credentials/dangling-key.json: device_key 'no-such-key' matches no key vector",
        "keys/misplaced-schema.json: schema mdoc-circuits-v1.schema.json does not belong in keys",
        "notes/: unknown subtree",
        "presentations/bad-presentation.json:"
        " Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
        "presentations/dangling-credential.json: credential 'no-such-credential'"
        " matches no credential vector",
        "presentations/dir-named.json: not a regular file",
        "presentations/misplaced-schema.json: schema mdoc-proofs-v1.schema.json"
        " does not belong in presentations",
        "presentations/stray.txt: file has no governing sidecar",
        "proofs/badhash.proof: sha256"
        " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 does not match computed"
        " e3ac95c39a8de3a288029705a1cf4dde831c1f98f00e88fdfde149a8b0fe119d",
        "proofs/badref.json: circuit 'no-such-circuit' matches no circuit vector",
        "proofs/dangling-blob.proof: not a regular file",
        "proofs/dangling-presentation.json: presentation 'no-such-presentation'"
        " matches no presentation vector",
        "proofs/noblob.json: missing blob noblob.proof",
        "proofs/orphan.proof: file has no governing sidecar",
        "stray-root.txt: unknown file at the collection root",
    ]
