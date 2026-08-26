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

# Each fixture sidecar's own `comment` field says what that fixture is for. Four fixtures
# are not JSON objects and so carry no comment: invalid/not-an-object.json,
# trees/integrity-violations/circuits/bad-json.json,
# trees/integrity-violations/presentations/bad-presentation.json, and
# trees/malformed/circuits/broken.json.

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
    """Copy the valid collection into tmp_path so a test can edit its sidecars."""
    copy = tmp_path / "corpus"
    shutil.copytree(VALID_COLLECTION, copy)
    return copy


def edit_sidecar(root: Path, rel: str, **changes: object) -> None:
    """Rewrite one sidecar under root with the given fields set."""
    path = root / rel
    doc = json.loads(path.read_text())
    doc.update(changes)
    path.write_text(json.dumps(doc))


def test_keys_returns_vectors_sorted_by_name() -> None:
    """keys() returns vectors sorted by name."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.keys()] == [
        "bare-device",
        "full-key",
        "p256-device",
    ]


def test_key_carries_the_fields_its_sidecar_records() -> None:
    """A key vector holds the PEM bytes, role, sha256, fingerprint, and provenance recorded."""
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


def test_key_omits_the_fields_its_sidecar_lacks() -> None:
    """A key vector whose sidecar omits fingerprint holds None for it."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("bare-device")
    assert key.pem == b""
    assert key.role == "device"
    assert key.sha256 == EMPTY_SHA256
    assert key.fingerprint is None
    assert key.provenance.type == "repository"
    assert key.provenance.repo == "github.com/example/fixtures"


def test_key_public_key_and_private_key_hold_the_recorded_values() -> None:
    """Key.public_key is a PublicKey and Key.private_key an int over the sidecar's hex."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("full-key")
    assert key.public_key == PublicKey(x=int("77" * 32, 16), y=int("88" * 32, 16))
    assert key.private_key == int("99" * 32, 16)


def test_key_public_key_and_private_key_are_none_when_the_sidecar_omits_them() -> None:
    """Key.public_key and Key.private_key are None when the sidecar records no key material."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("bare-device")
    assert key.public_key is None
    assert key.private_key is None


def test_key_der_returns_the_bytes_the_pem_encodes() -> None:
    """Key.der returns the DER body of a single-block PEM."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("p256-device")
    der = key.der
    assert len(der) == 138
    assert der[:16] == bytes.fromhex("308187020100301306072a8648ce3d02")


def test_key_der_raises_when_the_pem_holds_no_block() -> None:
    """Key.der raises ValueError naming the vector when the PEM is not a single block."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    key = vectors.mdoc.key("bare-device")
    with pytest.raises(ValueError, match="bare-device: not a single PEM block"):
        _ = key.der


def test_credentials_returns_vectors_sorted_by_name() -> None:
    """credentials() returns vectors sorted by name."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.credentials()] == [
        "bare-cred",
        "claims-cred",
        "ds-cred",
        "full-cred",
    ]


def test_credential_carries_the_fields_its_sidecar_records() -> None:
    """A credential vector holds the CBOR bytes, sha256, doctype, and provenance recorded for it."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("full-cred")
    assert credential.bytes == FULL_CRED_CBOR
    assert credential.sha256 == "0a43b22d89fa2499be5c7704c9bf273260b0ca9588e4cd1897cd80f9c96cd97a"
    assert credential.doctype == "org.iso.18013.5.1.mDL"
    assert credential.provenance.type == "constructed"


def test_credential_omits_the_fields_its_sidecar_lacks() -> None:
    """A credential vector whose sidecar omits doctype and both references holds None for them."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("bare-cred")
    assert credential.bytes == b""
    assert credential.sha256 == EMPTY_SHA256
    assert credential.doctype is None
    assert credential.device_key is None
    assert credential.ds_certificate is None
    assert credential.provenance.type == "repository"


def test_credential_device_key_resolves_to_the_key_vector() -> None:
    """Credential.device_key holds the key vector its sidecar names."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("full-cred")
    assert credential.device_key is not None
    assert credential.device_key.name == "full-key"
    assert credential.ds_certificate is None


def test_credential_ds_certificate_resolves_to_the_certificate_vector() -> None:
    """Credential.ds_certificate holds the certificate vector its sidecar names."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("ds-cred")
    assert credential.ds_certificate is not None
    assert credential.ds_certificate.name == "signer"
    assert credential.device_key is None


def test_credential_device_key_naming_no_vector_fails_the_load(tmp_path: Path) -> None:
    """Loading credentials raises CorpusError when device_key names no key vector."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "credentials/full-cred.json", device_key="no-such-key")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="device_key 'no-such-key' matches no key vector"):
        vectors.mdoc.credentials()


def test_credential_ds_certificate_naming_no_vector_fails_the_load(tmp_path: Path) -> None:
    """Loading credentials raises CorpusError when ds_certificate names no certificate vector."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "credentials/ds-cred.json", ds_certificate="no-such-cert")
    vectors = LongfellowVectors(root)
    with pytest.raises(
        CorpusError, match="ds_certificate 'no-such-cert' matches no certificate vector"
    ):
        vectors.mdoc.credentials()


def test_credential_claims_returns_the_issuer_signed_items() -> None:
    """Credential.claims() returns one Claim per issuer-signed item, in document order."""
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


def test_credential_claims_raises_when_the_bytes_are_not_cbor() -> None:
    """Credential.claims() raises CBORDecodeError when the credential bytes are not CBOR."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    credential = vectors.mdoc.credential("bare-cred")
    with pytest.raises(cbor2.CBORDecodeError):
        credential.claims()


def test_presentations_returns_vectors_sorted_by_name() -> None:
    """presentations() returns vectors sorted by name."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.presentations()] == [
        "bare",
        "claims",
        "full",
        "minimal",
    ]


def test_presentation_carries_the_fields_its_sidecar_records() -> None:
    """A presentation vector holds the doctype, mdoc, device_namespaces, and transcript recorded."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.doctype == "org.iso.18013.5.1.mDL"
    assert presentation.mdoc == b"\xa0"
    assert presentation.device_namespaces == b"\xa0"
    assert presentation.transcript == b"\x83"
    assert presentation.comment is not None


def test_presentation_constructed_provenance_carries_generator_created_and_ref() -> None:
    """Constructed provenance holds generator, created, and ref, and no repository fields."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.provenance.type == "constructed"
    assert presentation.provenance.generator == "tools/generation/generate.py presentation"
    assert presentation.provenance.created == "2026-08-21"
    assert presentation.provenance.ref == "dd" * 20
    assert presentation.provenance.repo is None
    assert presentation.provenance.path is None
    assert presentation.provenance.captured is None


def test_presentation_repository_provenance_carries_repo_ref_path_and_captured() -> None:
    """Repository provenance holds repo, ref, path, and captured, and no constructed fields."""
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


def test_presentation_omits_the_content_fields_its_sidecar_lacks() -> None:
    """A presentation vector holds None for every content field its sidecar omits."""
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


def test_presentation_issuer_public_key_holds_the_recorded_coordinates() -> None:
    """Presentation.issuer_public_key is a PublicKey over the sidecar's coordinate hex."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.issuer_public_key == PublicKey(x=int("11" * 32, 16), y=int("22" * 32, 16))


def test_presentation_issuer_public_key_is_none_when_the_sidecar_omits_it() -> None:
    """Presentation.issuer_public_key is None when the sidecar records no coordinates."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("minimal")
    assert presentation.issuer_public_key is None


def test_presentation_credential_resolves_to_the_credential_vector() -> None:
    """Presentation.credential holds the credential vector its sidecar names."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("full")
    assert presentation.credential is not None
    assert presentation.credential.name == "full-cred"


def test_presentation_credential_naming_no_vector_fails_the_load(tmp_path: Path) -> None:
    """Loading presentations raises CorpusError when credential names no credential vector."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "presentations/full.json", credential="no-such-cred")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="credential 'no-such-cred' matches no credential vector"):
        vectors.mdoc.presentations()


def test_presentation_claims_returns_the_issuer_signed_items() -> None:
    """Presentation.claims() returns one Claim per issuer-signed item, in document order."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("claims")
    claims = presentation.claims()
    assert len(claims) == 2
    assert claims[0].namespace == "org.iso.18013.5.1"
    assert claims[0].id == "age_over_18"
    assert claims[0].cbor_value == b"\xf5"
    assert claims[1].namespace == "org.iso.18013.5.1"
    assert claims[1].id == "issue_date"


def test_presentation_claims_raises_when_the_mdoc_holds_no_documents() -> None:
    """Presentation.claims() raises ValueError when the mdoc decodes to a map with no documents."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    presentation = vectors.mdoc.presentation("minimal")
    with pytest.raises(ValueError, match="payload has no documents array"):
        presentation.claims()


def test_circuits_returns_vectors_sorted_by_name() -> None:
    """circuits() returns vectors sorted by name."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.circuits()] == ["other", "tiny"]


def test_circuit_carries_the_fields_its_sidecar_records() -> None:
    """A circuit vector holds the compressed bytes, system, sha256, version, and attribute count."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    circuit = vectors.mdoc.circuit("tiny")
    assert circuit.bytes == b""
    assert circuit.system == "longfellow-libzk-v1"
    assert circuit.sha256 == EMPTY_SHA256
    assert circuit.version == 6
    assert circuit.num_attributes == 1
    assert circuit.provenance.index == "circuits[0]"
    assert circuit.provenance.via == "an intermediate export"


def test_circuit_provenance_omits_index_and_via_when_the_sidecar_lacks_them() -> None:
    """Provenance holds None for index and via when the sidecar records neither."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    circuit = vectors.mdoc.circuit("other")
    assert circuit.sha256 == "8349d0fe15cb2c176df2f7007df8f7e8651bfdca6836bcfcd7029398c28a1797"
    assert circuit.version == 7
    assert circuit.num_attributes == 1
    assert circuit.provenance.index is None
    assert circuit.provenance.via is None


def test_circuit_fractional_version_fails_the_load(tmp_path: Path) -> None:
    """Loading circuits raises ValueError when version is a JSON number carrying a fraction."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "circuits/tiny.json", version=6.0)
    vectors = LongfellowVectors(root)
    with pytest.raises(ValueError, match="circuits/tiny.json: version is not an integer: 6.0"):
        vectors.mdoc.circuits()


def test_circuit_fractional_num_attributes_fails_the_load(tmp_path: Path) -> None:
    """Loading circuits raises ValueError when num_attributes carries a fraction."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "circuits/tiny.json", num_attributes=1.0)
    vectors = LongfellowVectors(root)
    with pytest.raises(
        ValueError, match="circuits/tiny.json: num_attributes is not an integer: 1.0"
    ):
        vectors.mdoc.circuits()


def test_proofs_returns_vectors_sorted_by_name() -> None:
    """proofs() returns vectors sorted by name."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.proofs()] == [
        "bare",
        "synthetic-v1",
        "synthetic-v2",
    ]


def test_proof_carries_the_fields_its_sidecar_records() -> None:
    """A proof vector holds the proof bytes, sha256, prover, statement fields, and provenance."""
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


def test_proof_omits_device_namespaces_and_presentation_when_the_sidecar_lacks_them() -> None:
    """A proof vector holds None for the device_namespaces and presentation its sidecar omits."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("synthetic-v2")
    assert proof.device_namespaces is None
    assert proof.presentation is None


def test_proof_omits_the_statement_fields_its_sidecar_lacks() -> None:
    """A proof vector holding sha256 and provenance alone holds None for every statement field."""
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


def test_proof_issuer_public_key_holds_the_recorded_coordinates() -> None:
    """Proof.issuer_public_key is a PublicKey over the sidecar's coordinate hex."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("synthetic-v1")
    assert proof.issuer_public_key == PublicKey(x=int("11" * 32, 16), y=int("22" * 32, 16))


def test_proof_issuer_public_key_is_none_when_the_sidecar_omits_it() -> None:
    """Proof.issuer_public_key is None when the sidecar records no coordinates."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("bare")
    assert proof.issuer_public_key is None


def test_proof_circuit_and_presentation_resolve_to_their_vectors() -> None:
    """Proof.circuit and Proof.presentation hold the vectors the sidecar names."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = vectors.mdoc.proof("synthetic-v1")
    assert proof.circuit is not None
    assert proof.circuit.name == "tiny"
    assert proof.presentation is not None
    assert proof.presentation.name == "full"


def test_proof_circuit_naming_no_vector_fails_the_load(tmp_path: Path) -> None:
    """Loading proofs raises CorpusError when circuit names no circuit vector."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "proofs/synthetic-v1.json", circuit="no-such-circuit")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="circuit 'no-such-circuit' matches no circuit vector"):
        vectors.mdoc.proofs()


def test_proof_presentation_naming_no_vector_fails_the_load(tmp_path: Path) -> None:
    """Loading proofs raises CorpusError when presentation names no presentation vector."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "proofs/synthetic-v1.json", presentation="no-such-presentation")
    vectors = LongfellowVectors(root)
    with pytest.raises(
        CorpusError, match="presentation 'no-such-presentation' matches no presentation vector"
    ):
        vectors.mdoc.proofs()


def test_proof_statement_returns_every_statement_field() -> None:
    """Proof.statement() returns a Statement holding every statement field the vector carries."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    statement = vectors.mdoc.proof("synthetic-v1").statement()
    assert statement.doctype == "org.iso.18013.5.1.mDL"
    assert statement.transcript == b"\x83"
    assert statement.issuer_public_key == PublicKey(x=int("11" * 32, 16), y=int("22" * 32, 16))
    assert [claim.id for claim in statement.claims] == ["age_over_18", "issue_date"]
    assert statement.timestamp.isoformat() == "2026-08-21T12:00:00+00:00"
    assert statement.device_namespaces == b"\xa0"


@pytest.mark.parametrize(("changes", "message"), MISSING_STATEMENT_FIELDS)
def test_proof_statement_raises_naming_the_field_the_vector_does_not_carry(
    changes: dict[str, Any], message: str
) -> None:
    """Proof.statement() raises CorpusError naming the statement field the vector does not carry."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    proof = dataclasses.replace(vectors.mdoc.proof("synthetic-v1"), **changes)
    with pytest.raises(CorpusError, match=message):
        proof.statement()


def test_certificates_returns_vectors_sorted_by_name() -> None:
    """certificates() returns vectors sorted by name."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert [record.name for record in vectors.mdoc.certificates()] == [
        "keyed",
        "root-ca",
        "signer",
    ]


def test_certificate_carries_the_fields_its_sidecar_records() -> None:
    """A certificate vector holds the PEM bytes, role, sha256, and provenance recorded for it."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("signer")
    assert certificate.pem == SIGNER_PEM
    assert certificate.role == "document-signer"
    assert certificate.sha256 == "40caffb079b6e5380923bcd4f0565f4b80e1aaca45d13005f140d54cecd680fd"
    assert certificate.provenance.type == "repository"
    assert certificate.provenance.path == "certificates/signer.pem"


def test_certificate_omits_the_fields_its_sidecar_lacks() -> None:
    """A certificate vector whose sidecar names no signer or key holds None for both."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("root-ca")
    assert certificate.pem == ROOT_CA_PEM
    assert certificate.role == "iaca"
    assert certificate.sha256 == "9d03e8eb237bc5212dde611f2014956e2aefcd39c827431f18365cfdd41e8181"
    assert certificate.signed_by is None
    assert certificate.key is None


def test_certificate_public_key_holds_the_recorded_coordinates() -> None:
    """Certificate.public_key is a PublicKey over the sidecar's coordinate hex."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("keyed")
    assert certificate.public_key == PublicKey(
        x=0x460C9D6E9D60AA81CDEEB7020998AE2F41B6100FB40FB341927189D3A7CD2692,
        y=0x52D68CFE920979229EA1BBF2B6759F84BAEA8C49BF52397BB95F1C79A1397D18,
    )


def test_certificate_public_key_is_none_when_the_sidecar_omits_it() -> None:
    """Certificate.public_key is None when the sidecar records no coordinates."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("root-ca")
    assert certificate.public_key is None


def test_certificate_signed_by_and_key_resolve_to_their_vectors() -> None:
    """Certificate.signed_by and Certificate.key hold the vectors the sidecar names."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("keyed")
    assert certificate.signed_by is not None
    assert certificate.signed_by.name == "root-ca"
    assert certificate.key is not None
    assert certificate.key.name == "full-key"


def test_certificate_signer_is_built_before_the_vector_that_names_it(tmp_path: Path) -> None:
    """A certificate resolves its signer even when the signer sorts after it by name."""
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


def test_certificate_signed_by_naming_no_vector_fails_the_load(tmp_path: Path) -> None:
    """Loading certificates raises CorpusError when signed_by names no certificate vector."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "certificates/signer.json", signed_by="no-such-cert")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="signed_by 'no-such-cert' matches no certificate vector"):
        vectors.mdoc.certificates()


def test_certificate_key_naming_no_vector_fails_the_load(tmp_path: Path) -> None:
    """Loading certificates raises CorpusError when key names no key vector."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "certificates/keyed.json", key="no-such-key")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="key 'no-such-key' matches no key vector"):
        vectors.mdoc.certificates()


def test_certificate_signing_cycle_fails_the_load(tmp_path: Path) -> None:
    """Loading certificates raises CorpusError naming every vector a signing cycle runs through."""
    root = corpus_copy(tmp_path)
    edit_sidecar(root, "certificates/root-ca.json", signed_by="signer")
    vectors = LongfellowVectors(root)
    with pytest.raises(
        CorpusError, match="signing references form a cycle: keyed, root-ca, signer"
    ):
        vectors.mdoc.certificates()


def test_certificate_der_returns_the_bytes_the_pem_encodes() -> None:
    """Certificate.der returns the DER body of a single-block PEM."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = vectors.mdoc.certificate("keyed")
    der = certificate.der
    assert len(der) == 312
    assert der[:16] == bytes.fromhex("308201343081dba00302010202010130")


def test_certificate_der_raises_when_the_pem_holds_no_block() -> None:
    """Certificate.der raises ValueError naming the vector when the PEM is not a single block."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    certificate = dataclasses.replace(vectors.mdoc.certificate("root-ca"), pem=b"")
    with pytest.raises(ValueError, match="root-ca: not a single PEM block"):
        _ = certificate.der


@pytest.mark.parametrize(("payload", "match"), MALFORMED_CLAIM_PAYLOADS)
def test_parse_claims_raises_naming_the_structure_the_payload_lacks(
    payload: bytes, match: str
) -> None:
    """Parsing claims raises ValueError naming the DeviceResponse structure the payload lacks."""
    with pytest.raises(ValueError, match=match):
        mdoc_module._parse_claims(payload)


def test_lookup_by_name_returns_the_named_vector() -> None:
    """Each by-name lookup returns the vector carrying that name."""
    vectors = LongfellowVectors(VALID_COLLECTION)
    assert vectors.mdoc.key("full-key").name == "full-key"
    assert vectors.mdoc.credential("full-cred").name == "full-cred"
    assert vectors.mdoc.presentation("full").name == "full"
    assert vectors.mdoc.proof("synthetic-v1").name == "synthetic-v1"
    assert vectors.mdoc.circuit("tiny").name == "tiny"
    assert vectors.mdoc.certificate("signer").name == "signer"


def test_lookup_by_unknown_name_raises_key_error() -> None:
    """Each by-name lookup raises KeyError when no vector carries that name."""
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


def test_vectors_are_loaded_once_per_instance() -> None:
    """Each accessor returns the same tuple on every call, and a fresh loader loads its own."""
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


def test_packaged_collection_passes_the_integrity_check() -> None:
    """check() reports no findings against the collection shipped with the package."""
    LongfellowVectors().check()


def test_check_ignores_a_dotfile_at_the_root(tmp_path: Path) -> None:
    """A dotfile at the collection root is not a finding."""
    (tmp_path / ".gitkeep").write_bytes(b"")
    LongfellowVectors(tmp_path).check()


def test_check_ignores_a_dotfile_in_a_vector_directory(tmp_path: Path) -> None:
    """A dotfile in a blob-carrying or sidecar-only vector directory is not a finding."""
    (tmp_path / "circuits").mkdir()
    (tmp_path / "circuits" / ".gitkeep").write_bytes(b"")
    (tmp_path / "presentations").mkdir()
    (tmp_path / "presentations" / ".gitkeep").write_bytes(b"")
    LongfellowVectors(tmp_path).check()


def test_load_ignores_a_dotfile_in_a_vector_directory(tmp_path: Path) -> None:
    """A vector directory holding only a dotfile loads as an empty tuple."""
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / ".gitkeep").write_bytes(b"")
    assert LongfellowVectors(tmp_path).mdoc.keys() == ()


def test_missing_subtrees_load_as_empty_tuples(tmp_path: Path) -> None:
    """Every vector type loads empty from a root holding none of the six subtrees."""
    vectors = LongfellowVectors(tmp_path)
    assert vectors.mdoc.keys() == ()
    assert vectors.mdoc.credentials() == ()
    assert vectors.mdoc.presentations() == ()
    assert vectors.mdoc.proofs() == ()
    assert vectors.mdoc.circuits() == ()
    assert vectors.mdoc.certificates() == ()


def test_load_raises_when_the_root_does_not_exist(tmp_path: Path) -> None:
    """Loading a vector type raises CorpusError when the collection root does not exist."""
    vectors = LongfellowVectors(tmp_path / "no-such-collection")
    with pytest.raises(CorpusError, match="no-such-collection: collection root is not a directory"):
        vectors.mdoc.circuits()


def test_load_raises_when_the_root_is_a_file(tmp_path: Path) -> None:
    """Loading a vector type raises CorpusError when the collection root is a file."""
    root = tmp_path / "collection"
    root.write_text("a file, not a directory")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="collection: collection root is not a directory"):
        vectors.mdoc.keys()


def test_load_raises_when_a_blob_is_absent() -> None:
    """Loading proofs raises FileNotFoundError when a sidecar's blob file is absent."""
    vectors = LongfellowVectors(BROKEN_TREES / "missing-blob")
    with pytest.raises(FileNotFoundError):
        vectors.mdoc.proofs()


def test_load_skips_files_that_are_not_sidecars() -> None:
    """Loading a subtree reads its .json files and passes over every other file."""
    vectors = LongfellowVectors(BROKEN_TREES / "missing-blob")
    assert [record.name for record in vectors.mdoc.presentations()] == ["lone"]


def test_load_raises_on_a_sidecar_that_is_not_json() -> None:
    """Loading a subtree raises ValueError naming the sidecar that does not parse as JSON."""
    vectors = LongfellowVectors(BROKEN_TREES / "malformed")
    with pytest.raises(ValueError, match=r"^circuits/broken\.json: Expecting value"):
        vectors.mdoc.circuits()


def test_load_raises_on_a_sidecar_the_schema_rejects() -> None:
    """Loading a subtree raises ValueError when a sidecar breaks the schema it names."""
    vectors = LongfellowVectors(BROKEN_TREES / "rejected")
    with pytest.raises(ValueError, match=r"circuits/bad\.json: rejected by schema"):
        vectors.mdoc.circuits()


def test_load_raises_on_a_sidecar_naming_another_subtrees_schema() -> None:
    """Loading a subtree raises ValueError when a sidecar names a schema from another subtree."""
    vectors = LongfellowVectors(BROKEN_TREES / "integrity-violations")
    with pytest.raises(
        ValueError,
        match="keys/misplaced-schema.json: schema mdoc-circuits-v1.schema.json"
        " does not belong in keys",
    ):
        vectors.mdoc.keys()


@pytest.mark.parametrize(("filename", "match"), REJECTED_SIDECAR_MESSAGES)
def test_sidecar_the_schema_rejects_raises_naming_the_violation(filename: str, match: str) -> None:
    """Reading a sidecar raises ValueError naming the schema rule the sidecar breaks."""
    text = (REJECTED_SIDECARS / filename).read_text()
    with pytest.raises(ValueError, match=match):
        mdoc_module._load_sidecar(text, filename)


def test_check_accepts_a_clean_collection() -> None:
    """check() reports no findings against a tree whose vectors and references all hold."""
    LongfellowVectors(VALID_COLLECTION).check()


def test_check_accepts_an_empty_root(tmp_path: Path) -> None:
    """check() reports no findings against a root holding no entries."""
    LongfellowVectors(tmp_path).check()


def test_check_raises_when_the_root_does_not_exist(tmp_path: Path) -> None:
    """check() raises CorpusError when the collection root does not exist."""
    vectors = LongfellowVectors(tmp_path / "no-such-collection")
    with pytest.raises(CorpusError, match="no-such-collection: collection root is not a directory"):
        vectors.check()


def test_check_raises_when_the_root_is_a_file(tmp_path: Path) -> None:
    """check() raises CorpusError when the collection root is a file."""
    root = tmp_path / "collection"
    root.write_text("a file, not a directory")
    vectors = LongfellowVectors(root)
    with pytest.raises(CorpusError, match="collection: collection root is not a directory"):
        vectors.check()


def test_check_reports_every_finding() -> None:
    """check() raises CorpusError holding one line per file that breaks a rule."""
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
