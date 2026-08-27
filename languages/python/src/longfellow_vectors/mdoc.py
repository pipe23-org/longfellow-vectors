"""mdoc test vectors: keys, credentials, presentations, circuits, certificates, and proofs.

Vectors are JSON sidecars, some beside byte files, shipped as package data.
Every sidecar names its vector schema in its `schema` field and is validated
at load against that file as packaged with the installed `longfellow_vectors`;
a `schemas/` directory under a caller-supplied root is never read. A sidecar
naming a schema other than the one its subtree takes fails the load. Every
vector carries structured provenance citing where its bytes came from.

References between vectors are vector names; the loader resolves them while
building, so `Proof.circuit`, `Proof.presentation`, `Credential.device_key`,
`Credential.ds_certificate`, `Certificate.signed_by`, and `Certificate.key`
hold the referenced vectors themselves. A reference that names no vector in
the collection fails the load with `CorpusError`. A reference field records a
relation verified at admission. Role consistency between referenced vectors is
checked by neither the schema nor the loader: a certificate's `signed_by`
role, a credential's `ds_certificate` role, and a proof's claim count against
its circuit's `num_attributes` are all unconstrained.

A vector's `sha256` is the value its sidecar records, not a digest computed at
load. `LongfellowVectors.check()` compares it against the blob's bytes.

A credential vector's bytes are CBOR `IssuerSigned`, `{nameSpaces,
issuerAuth}`, the structure an issuer delivers. A presentation vector's `mdoc`
is a CBOR `DeviceResponse`, which carries an `IssuerSigned` per document
alongside the device signature.
"""

from __future__ import annotations

import base64
import builtins
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from functools import cache
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Any

import cbor2
from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

_VECTORS = files("longfellow_vectors") / "vectors"
_DATA = _VECTORS / "mdoc"
_SCHEMAS = _VECTORS / "schemas"

_SUBTREE_SCHEMAS = {
    "keys": "mdoc-keys-v1.schema.json",
    "credentials": "mdoc-credentials-v1.schema.json",
    "presentations": "mdoc-presentations-v1.schema.json",
    "circuits": "mdoc-circuits-v1.schema.json",
    "proofs": "mdoc-proofs-v1.schema.json",
    "certificates": "mdoc-certificates-v1.schema.json",
}

_PEM_BEGIN = re.compile(rb"^-----BEGIN .+-----$", re.MULTILINE)
_PEM_END = re.compile(rb"^-----END .+-----$", re.MULTILINE)


@cache
def _validators() -> dict[str, Draft202012Validator]:
    contents = {
        entry.name: json.loads(entry.read_text())
        for entry in _SCHEMAS.iterdir()
        if entry.name.endswith(".schema.json")
    }
    registry = Registry().with_resources(
        (name, Resource.from_contents(doc, DRAFT202012)) for name, doc in contents.items()
    )
    return {
        name: Draft202012Validator(
            doc, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER
        )
        for name, doc in contents.items()
        if "schema" in doc.get("properties", {})
    }


def _load_sidecar(text: str, where: str) -> dict[str, Any]:
    try:
        doc: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{where}: {exc}") from exc
    name = doc.get("schema") if isinstance(doc, dict) else None
    validator = _validators().get(name) if isinstance(name, str) else None
    if validator is None:
        raise ValueError(f"{where}: names no known vector schema: {name!r}")
    error = best_match(validator.iter_errors(doc))
    if error is not None:
        raise ValueError(f"{where}: rejected by schema: {error.message}") from error
    return doc


def _pem_der(pem: builtins.bytes, where: str) -> builtins.bytes:
    begins = list(_PEM_BEGIN.finditer(pem))
    ends = list(_PEM_END.finditer(pem))
    if len(begins) != 1 or len(ends) != 1:
        raise ValueError(f"{where}: not a single PEM block")
    return base64.b64decode(pem[begins[0].end() : ends[0].start()])


class CorpusError(Exception):
    """Raised for a malformed vector or an unresolved reference."""


@dataclass(frozen=True)
class Provenance:
    """Where a vector's bytes came from."""

    type: str
    repo: str | None = None
    ref: str | None = None
    path: str | None = None
    index: str | None = None
    via: str | None = None
    captured: str | None = None
    generator: str | None = None
    created: str | None = None
    license: str | None = None
    copyright: str | None = None


@dataclass(frozen=True)
class PublicKey:
    """A P-256 public key as affine coordinates."""

    x: int
    y: int


def _public_key(doc: dict[str, Any], field: str) -> PublicKey | None:
    x = doc.get(f"{field}_x")
    if x is None:
        return None
    return PublicKey(int(x, 16), int(doc[f"{field}_y"], 16))


@dataclass(frozen=True)
class Claim:
    """An issuer-signed attribute: namespace, id, and CBOR value."""

    namespace: str
    id: str
    cbor_value: bytes


def _issuer_signed_claims(issuer_signed: dict[Any, Any]) -> tuple[Claim, ...]:
    namespaces = issuer_signed.get("nameSpaces")
    if not isinstance(namespaces, dict):
        raise ValueError("issuerSigned has no nameSpaces map")
    result: list[Claim] = []
    for ns, items in namespaces.items():
        if not isinstance(items, list):
            raise ValueError(f"nameSpaces[{ns!r}] is not an array")
        for item in items:
            if not isinstance(item, cbor2.CBORTag) or item.tag != 24:
                raise ValueError("nameSpaces item is not tag-24 wrapped")
            inner = cbor2.loads(item.value)
            if not isinstance(inner, dict):
                raise ValueError("tag-24 content is not a map")
            elem_id = inner.get("elementIdentifier")
            if not isinstance(elem_id, str):
                raise ValueError("missing or non-string elementIdentifier")
            result.append(Claim(ns, elem_id, cbor2.dumps(inner["elementValue"])))
    return tuple(result)


def _credential_claims(payload: builtins.bytes) -> tuple[Claim, ...]:
    decoded = cbor2.loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("payload is not a CBOR map")
    return _issuer_signed_claims(decoded)


def _presentation_claims(payload: builtins.bytes) -> tuple[Claim, ...]:
    decoded = cbor2.loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("payload is not a CBOR map")
    docs = decoded.get("documents")
    if not isinstance(docs, list) or not docs:
        raise ValueError("payload has no documents array")
    doc = docs[0]
    if not isinstance(doc, dict):
        raise ValueError("document is not a CBOR map")
    issuer_signed = doc.get("issuerSigned")
    if not isinstance(issuer_signed, dict):
        raise ValueError("document has no issuerSigned map")
    return _issuer_signed_claims(issuer_signed)


@dataclass(frozen=True)
class Key:
    """A key vector: PEM bytes and role."""

    name: str
    pem: builtins.bytes
    role: str
    sha256: str
    provenance: Provenance
    fingerprint: str | None = None
    public_key: PublicKey | None = None
    private_key: int | None = None
    comment: str | None = None

    @property
    def der(self) -> builtins.bytes:
        """DER bytes of the PEM."""
        return _pem_der(self.pem, self.name)


@dataclass(frozen=True)
class Credential:
    """A credential vector: IssuerSigned CBOR."""

    name: str
    bytes: builtins.bytes
    sha256: str
    provenance: Provenance
    doctype: str | None = None
    device_key: Key | None = None
    ds_certificate: Certificate | None = None
    comment: str | None = None

    def claims(self) -> tuple[Claim, ...]:
        """Return the issuer-signed claims."""
        return _credential_claims(self.bytes)


@dataclass(frozen=True)
class Presentation:
    """A presentation vector: a DeviceResponse and its transcript."""

    name: str
    mdoc: bytes
    provenance: Provenance
    doctype: str | None = None
    device_namespaces: bytes | None = None
    transcript: bytes | None = None
    issuer_public_key: PublicKey | None = None
    credential: Credential | None = None
    comment: str | None = None

    def claims(self) -> tuple[Claim, ...]:
        """Return the issuer-signed claims."""
        return _presentation_claims(self.mdoc)


@dataclass(frozen=True)
class Circuit:
    """A circuit vector."""

    name: str
    bytes: builtins.bytes
    system: str
    sha256: str
    provenance: Provenance
    version: int
    num_attributes: int
    comment: str | None = None


@dataclass(frozen=True)
class Statement:
    """A proof's public inputs: doctype, transcript, issuer key, claims, and timestamp."""

    doctype: str
    transcript: builtins.bytes
    issuer_public_key: PublicKey
    claims: tuple[Claim, ...]
    timestamp: datetime
    device_namespaces: builtins.bytes | None = None


@dataclass(frozen=True)
class Proof:
    """A proof vector: proof bytes and their public inputs."""

    name: str
    bytes: builtins.bytes
    sha256: str
    provenance: Provenance
    prover: str | None = None
    circuit: Circuit | None = None
    doctype: str | None = None
    claims: tuple[Claim, ...] | None = None
    transcript: builtins.bytes | None = None
    issuer_public_key: PublicKey | None = None
    timestamp: datetime | None = None
    device_namespaces: builtins.bytes | None = None
    presentation: Presentation | None = None
    comment: str | None = None

    def statement(self) -> Statement:
        """Return the proof's public inputs."""
        if self.doctype is None:
            raise CorpusError(f"proof {self.name}: statement field doctype not recorded")
        if self.transcript is None:
            raise CorpusError(f"proof {self.name}: statement field transcript not recorded")
        if self.issuer_public_key is None:
            raise CorpusError(f"proof {self.name}: statement field issuer_public_key not recorded")
        if not self.claims:
            raise CorpusError(f"proof {self.name}: statement field claims not recorded")
        if self.timestamp is None:
            raise CorpusError(f"proof {self.name}: statement field timestamp not recorded")
        return Statement(
            doctype=self.doctype,
            transcript=self.transcript,
            issuer_public_key=self.issuer_public_key,
            claims=self.claims,
            timestamp=self.timestamp,
            device_namespaces=self.device_namespaces,
        )


@dataclass(frozen=True)
class Certificate:
    """A certificate vector: PEM bytes and role."""

    name: str
    pem: bytes
    role: str
    sha256: str
    provenance: Provenance
    public_key: PublicKey | None = None
    signed_by: Certificate | None = None
    key: Key | None = None
    comment: str | None = None

    @property
    def der(self) -> bytes:
        """DER bytes of the PEM."""
        return _pem_der(self.pem, self.name)


class _MdocCollection:
    def __init__(self, root: Traversable) -> None:
        """Initialize the mdoc view of the collection at root."""
        self.root = root
        self._keys: tuple[Key, ...] | None = None
        self._credentials: tuple[Credential, ...] | None = None
        self._presentations: tuple[Presentation, ...] | None = None
        self._proofs: tuple[Proof, ...] | None = None
        self._circuits: tuple[Circuit, ...] | None = None
        self._certificates: tuple[Certificate, ...] | None = None

    def keys(self) -> tuple[Key, ...]:
        """All key vectors, sorted by name."""
        if self._keys is None:
            self._keys = self._load_keys()
        return self._keys

    def credentials(self) -> tuple[Credential, ...]:
        """All credential vectors, sorted by name."""
        if self._credentials is None:
            self._credentials = self._load_credentials()
        return self._credentials

    def presentations(self) -> tuple[Presentation, ...]:
        """All presentation vectors, sorted by name."""
        if self._presentations is None:
            self._presentations = self._load_presentations()
        return self._presentations

    def proofs(self) -> tuple[Proof, ...]:
        """All proof vectors, sorted by name."""
        if self._proofs is None:
            self._proofs = self._load_proofs()
        return self._proofs

    def circuits(self) -> tuple[Circuit, ...]:
        """All circuit vectors, sorted by name."""
        if self._circuits is None:
            self._circuits = self._load_circuits()
        return self._circuits

    def certificates(self) -> tuple[Certificate, ...]:
        """All certificate vectors, sorted by name."""
        if self._certificates is None:
            self._certificates = self._load_certificates()
        return self._certificates

    def key(self, name: str) -> Key:
        """Return the key vector named `name`."""
        for record in self.keys():
            if record.name == name:
                return record
        raise KeyError(f"no key vector named {name!r}")

    def credential(self, name: str) -> Credential:
        """Return the credential vector named `name`."""
        for record in self.credentials():
            if record.name == name:
                return record
        raise KeyError(f"no credential vector named {name!r}")

    def presentation(self, name: str) -> Presentation:
        """Return the presentation vector named `name`."""
        for record in self.presentations():
            if record.name == name:
                return record
        raise KeyError(f"no presentation vector named {name!r}")

    def proof(self, name: str) -> Proof:
        """Return the proof vector named `name`."""
        for record in self.proofs():
            if record.name == name:
                return record
        raise KeyError(f"no proof vector named {name!r}")

    def circuit(self, name: str) -> Circuit:
        """Return the circuit vector named `name`."""
        for record in self.circuits():
            if record.name == name:
                return record
        raise KeyError(f"no circuit vector named {name!r}")

    def certificate(self, name: str) -> Certificate:
        """Return the certificate vector named `name`."""
        for record in self.certificates():
            if record.name == name:
                return record
        raise KeyError(f"no certificate vector named {name!r}")

    def _docs(self, subtree: str) -> list[tuple[str, dict[str, Any], Traversable]]:
        if not self.root.is_dir():
            raise CorpusError(f"{self.root}: collection root is not a directory")
        base = self.root / subtree
        if not base.is_dir():
            return []
        docs = []
        for entry in sorted(base.iterdir(), key=lambda t: t.name):
            if entry.name.startswith("."):
                continue
            if not entry.name.endswith(".json"):
                continue
            doc = _load_sidecar(entry.read_text(), f"{subtree}/{entry.name}")
            if doc["schema"] != _SUBTREE_SCHEMAS[subtree]:
                raise ValueError(
                    f"{subtree}/{entry.name}: schema {doc['schema']} does not belong in {subtree}"
                )
            docs.append((entry.name.removesuffix(".json"), doc, base))
        return docs

    def _load_keys(self) -> tuple[Key, ...]:
        return tuple(
            Key(
                name=name,
                pem=(base / f"{name}.pem").read_bytes(),
                role=doc["role"],
                sha256=doc["sha256"],
                provenance=Provenance(**doc["provenance"]),
                fingerprint=doc.get("fingerprint"),
                public_key=_public_key(doc, "public_key"),
                private_key=(
                    None if doc.get("private_key") is None else int(doc["private_key"], 16)
                ),
                comment=doc.get("comment"),
            )
            for name, doc, base in self._docs("keys")
        )

    def _load_credentials(self) -> tuple[Credential, ...]:
        records = []
        for name, doc, base in self._docs("credentials"):
            blob = (base / f"{name}.cbor").read_bytes()
            key_name = doc.get("device_key")
            key_ref: Key | None = None
            if key_name is not None:
                try:
                    key_ref = self.key(key_name)
                except KeyError:
                    raise CorpusError(
                        f"{name}.json: device_key {key_name!r} matches no key vector"
                    ) from None
            cert_name = doc.get("ds_certificate")
            cert_ref: Certificate | None = None
            if cert_name is not None:
                try:
                    cert_ref = self.certificate(cert_name)
                except KeyError:
                    raise CorpusError(
                        f"{name}.json: ds_certificate {cert_name!r} matches no certificate vector"
                    ) from None
            records.append(
                Credential(
                    name=name,
                    bytes=blob,
                    sha256=doc["sha256"],
                    provenance=Provenance(**doc["provenance"]),
                    doctype=doc.get("doctype"),
                    device_key=key_ref,
                    ds_certificate=cert_ref,
                    comment=doc.get("comment"),
                )
            )
        return tuple(records)

    def _load_presentations(self) -> tuple[Presentation, ...]:
        records = []
        for name, doc, _ in self._docs("presentations"):
            credential_name = doc.get("credential")
            credential_ref: Credential | None = None
            if credential_name is not None:
                try:
                    credential_ref = self.credential(credential_name)
                except KeyError:
                    raise CorpusError(
                        f"{name}.json: credential {credential_name!r} matches no credential vector"
                    ) from None
            device_namespaces = doc.get("device_namespaces")
            transcript = doc.get("transcript")
            records.append(
                Presentation(
                    name=name,
                    mdoc=bytes.fromhex(doc["mdoc"]),
                    provenance=Provenance(**doc["provenance"]),
                    doctype=doc.get("doctype"),
                    device_namespaces=(
                        None if device_namespaces is None else bytes.fromhex(device_namespaces)
                    ),
                    transcript=None if transcript is None else bytes.fromhex(transcript),
                    issuer_public_key=_public_key(doc, "issuer_public_key"),
                    credential=credential_ref,
                    comment=doc.get("comment"),
                )
            )
        return tuple(records)

    def _load_circuits(self) -> tuple[Circuit, ...]:
        records = []
        for name, doc, base in self._docs("circuits"):
            if not isinstance(doc["version"], int):
                raise ValueError(
                    f"circuits/{name}.json: version is not an integer: {doc['version']!r}"
                )
            if not isinstance(doc["num_attributes"], int):
                raise ValueError(
                    f"circuits/{name}.json: num_attributes is not an integer: "
                    f"{doc['num_attributes']!r}"
                )
            records.append(
                Circuit(
                    name=name,
                    bytes=(base / f"{name}.circuit").read_bytes(),
                    system=doc["system"],
                    sha256=doc["sha256"],
                    provenance=Provenance(**doc["provenance"]),
                    version=doc["version"],
                    num_attributes=doc["num_attributes"],
                    comment=doc.get("comment"),
                )
            )
        return tuple(records)

    def _load_proofs(self) -> tuple[Proof, ...]:
        records = []
        for name, doc, base in self._docs("proofs"):
            blob = (base / f"{name}.proof").read_bytes()
            circuit_name = doc.get("circuit")
            circuit_ref: Circuit | None = None
            if circuit_name is not None:
                try:
                    circuit_ref = self.circuit(circuit_name)
                except KeyError:
                    raise CorpusError(
                        f"{name}.json: circuit {circuit_name!r} matches no circuit vector"
                    ) from None
            presentation_name = doc.get("presentation")
            presentation_ref: Presentation | None = None
            if presentation_name is not None:
                try:
                    presentation_ref = self.presentation(presentation_name)
                except KeyError:
                    raise CorpusError(
                        f"{name}.json: presentation {presentation_name!r}"
                        " matches no presentation vector"
                    ) from None
            claims_raw = doc.get("claims")
            transcript = doc.get("transcript")
            timestamp = doc.get("timestamp")
            device_namespaces = doc.get("device_namespaces")
            records.append(
                Proof(
                    name=name,
                    bytes=blob,
                    sha256=doc["sha256"],
                    provenance=Provenance(**doc["provenance"]),
                    prover=doc.get("prover"),
                    circuit=circuit_ref,
                    doctype=doc.get("doctype"),
                    claims=(
                        None
                        if claims_raw is None
                        else tuple(
                            Claim(c["namespace"], c["id"], bytes.fromhex(c["cbor_value"]))
                            for c in claims_raw
                        )
                    ),
                    transcript=None if transcript is None else bytes.fromhex(transcript),
                    issuer_public_key=_public_key(doc, "issuer_public_key"),
                    timestamp=(None if timestamp is None else datetime.fromisoformat(timestamp)),
                    device_namespaces=(
                        None if device_namespaces is None else bytes.fromhex(device_namespaces)
                    ),
                    presentation=presentation_ref,
                    comment=doc.get("comment"),
                )
            )
        return tuple(records)

    def _load_certificates(self) -> tuple[Certificate, ...]:
        raw = {name: (doc, base) for name, doc, base in self._docs("certificates")}
        for name, (doc, _) in raw.items():
            signer = doc.get("signed_by")
            if signer is not None and signer not in raw:
                raise CorpusError(
                    f"{name}.json: signed_by {signer!r} matches no certificate vector"
                )
        built: dict[str, Certificate] = {}
        while len(built) < len(raw):
            progressed = False
            for name, (doc, base) in raw.items():
                if name in built:
                    continue
                signer = doc.get("signed_by")
                if signer is not None and signer not in built:
                    continue
                key_name = doc.get("key")
                key_ref: Key | None = None
                if key_name is not None:
                    try:
                        key_ref = self.key(key_name)
                    except KeyError:
                        raise CorpusError(
                            f"{name}.json: key {key_name!r} matches no key vector"
                        ) from None
                built[name] = Certificate(
                    name=name,
                    pem=(base / f"{name}.pem").read_bytes(),
                    role=doc["role"],
                    sha256=doc["sha256"],
                    provenance=Provenance(**doc["provenance"]),
                    public_key=_public_key(doc, "public_key"),
                    signed_by=None if signer is None else built[signer],
                    key=key_ref,
                    comment=doc.get("comment"),
                )
                progressed = True
            if not progressed:
                cycle = ", ".join(sorted(set(raw) - set(built)))
                raise CorpusError(f"certificates: signing references form a cycle: {cycle}")
        return tuple(built[name] for name in sorted(built))


def _check_root(root: Traversable) -> list[str]:
    findings: list[str] = []
    for entry in sorted(root.iterdir(), key=lambda t: t.name):
        if entry.name.startswith("."):
            continue
        if entry.is_dir():
            if entry.name not in _SUBTREE_SCHEMAS:
                findings.append(f"{entry.name}/: unknown subtree")
        else:
            findings.append(f"{entry.name}: unknown file at the collection root")
    return findings


def _check_flat_subtree(
    root: Traversable, subtree: str, suffix: str
) -> tuple[list[str], set[str], list[tuple[str, dict[str, Any], bytes]]]:
    findings: list[str] = []
    records: list[tuple[str, dict[str, Any], bytes]] = []
    base = root / subtree
    if not base.is_dir():
        return findings, set(), records
    entries = {entry.name: entry for entry in base.iterdir() if not entry.name.startswith(".")}
    names = {n.removesuffix(".json") for n in entries if n.endswith(".json")}
    for name in sorted(n for n in entries if n.endswith(".json")):
        if not entries[name].is_file():
            findings.append(f"{subtree}/{name}: not a regular file")
            continue
        try:
            doc = _load_sidecar(entries[name].read_text(), f"{subtree}/{name}")
        except ValueError as exc:
            findings.append(str(exc))
            continue
        if doc["schema"] != _SUBTREE_SCHEMAS[subtree]:
            findings.append(
                f"{subtree}/{name}: schema {doc['schema']} does not belong in {subtree}"
            )
            continue
        blob_name = name.removesuffix(".json") + suffix
        if blob_name not in entries:
            findings.append(f"{subtree}/{name}: missing blob {blob_name}")
            continue
        if not entries[blob_name].is_file():
            findings.append(f"{subtree}/{blob_name}: not a regular file")
            continue
        blob = entries[blob_name].read_bytes()
        want = str(doc["sha256"])
        got = hashlib.sha256(blob).hexdigest()
        if got != want:
            findings.append(f"{subtree}/{blob_name}: sha256 {want} does not match computed {got}")
        records.append((name.removesuffix(".json"), doc, blob))
    for name in sorted(n for n in entries if not n.endswith(".json")):
        stem = name.rsplit(".", 1)[0] if "." in name else name
        if f"{stem}.json" not in entries:
            findings.append(f"{subtree}/{name}: file has no governing sidecar")
        elif not name.endswith(suffix):
            findings.append(f"{subtree}/{name}: suffix is not {suffix}")
    return findings, names, records


def _check_sidecar_subtree(
    root: Traversable, subtree: str
) -> tuple[list[str], set[str], list[tuple[str, dict[str, Any]]]]:
    findings: list[str] = []
    records: list[tuple[str, dict[str, Any]]] = []
    base = root / subtree
    if not base.is_dir():
        return findings, set(), records
    entries = sorted(
        (entry for entry in base.iterdir() if not entry.name.startswith(".")),
        key=lambda t: t.name,
    )
    names = {e.name.removesuffix(".json") for e in entries if e.name.endswith(".json")}
    for entry in entries:
        if not entry.name.endswith(".json"):
            findings.append(f"{subtree}/{entry.name}: file has no governing sidecar")
            continue
        if not entry.is_file():
            findings.append(f"{subtree}/{entry.name}: not a regular file")
            continue
        try:
            doc = _load_sidecar(entry.read_text(), f"{subtree}/{entry.name}")
        except ValueError as exc:
            findings.append(str(exc))
            continue
        if doc["schema"] != _SUBTREE_SCHEMAS[subtree]:
            findings.append(
                f"{subtree}/{entry.name}: schema {doc['schema']} does not belong in {subtree}"
            )
            continue
        records.append((entry.name.removesuffix(".json"), doc))
    return findings, names, records


def _check_references(
    names: dict[str, set[str]],
    credential_records: list[tuple[str, dict[str, Any], bytes]],
    presentation_records: list[tuple[str, dict[str, Any]]],
    proof_records: list[tuple[str, dict[str, Any], bytes]],
    certificate_records: list[tuple[str, dict[str, Any], bytes]],
) -> list[str]:
    findings: list[str] = []
    for name, doc, _ in credential_records:
        key_name = doc.get("device_key")
        if key_name is not None and key_name not in names["keys"]:
            findings.append(
                f"credentials/{name}.json: device_key {key_name!r} matches no key vector"
            )
        cert_name = doc.get("ds_certificate")
        if cert_name is not None and cert_name not in names["certificates"]:
            findings.append(
                f"credentials/{name}.json: ds_certificate {cert_name!r}"
                " matches no certificate vector"
            )
    for name, doc in presentation_records:
        credential_name = doc.get("credential")
        if credential_name is not None and credential_name not in names["credentials"]:
            findings.append(
                f"presentations/{name}.json: credential {credential_name!r}"
                " matches no credential vector"
            )
    for name, doc, _ in proof_records:
        circuit = doc.get("circuit")
        if circuit is not None and circuit not in names["circuits"]:
            findings.append(f"proofs/{name}.json: circuit {circuit!r} matches no circuit vector")
        presentation_name = doc.get("presentation")
        if presentation_name is not None and presentation_name not in names["presentations"]:
            findings.append(
                f"proofs/{name}.json: presentation {presentation_name!r}"
                " matches no presentation vector"
            )
    signers = {name: doc.get("signed_by") for name, doc, _ in certificate_records}
    for name, doc, _ in certificate_records:
        signer = doc.get("signed_by")
        if signer is not None and signer not in names["certificates"]:
            findings.append(
                f"certificates/{name}.json: signed_by {signer!r} matches no certificate vector"
            )
        key_name = doc.get("key")
        if key_name is not None and key_name not in names["keys"]:
            findings.append(f"certificates/{name}.json: key {key_name!r} matches no key vector")
    resolved = {name for name, signer in signers.items() if signer is None or signer not in signers}
    while True:
        additions = {
            name for name, signer in signers.items() if name not in resolved and signer in resolved
        }
        if not additions:
            break
        resolved |= additions
    cycle = sorted(set(signers) - resolved)
    if cycle:
        findings.append(f"certificates: signing references form a cycle: {', '.join(cycle)}")
    return findings


def _collect_findings(root: Traversable) -> list[str]:
    if not root.is_dir():
        return [f"{root}: collection root is not a directory"]
    key_findings, key_names, _ = _check_flat_subtree(root, "keys", ".pem")
    circuit_findings, circuit_names, _ = _check_flat_subtree(root, "circuits", ".circuit")
    credential_findings, credential_names, credential_records = _check_flat_subtree(
        root, "credentials", ".cbor"
    )
    presentation_findings, presentation_names, presentation_records = _check_sidecar_subtree(
        root, "presentations"
    )
    proof_findings, proof_names, proof_records = _check_flat_subtree(root, "proofs", ".proof")
    certificate_findings, certificate_names, certificate_records = _check_flat_subtree(
        root, "certificates", ".pem"
    )
    findings = [
        *_check_root(root),
        *key_findings,
        *circuit_findings,
        *credential_findings,
        *presentation_findings,
        *proof_findings,
        *certificate_findings,
    ]
    findings += _check_references(
        {
            "keys": key_names,
            "circuits": circuit_names,
            "credentials": credential_names,
            "presentations": presentation_names,
            "proofs": proof_names,
            "certificates": certificate_names,
        },
        credential_records,
        presentation_records,
        proof_records,
        certificate_records,
    )
    return findings


class LongfellowVectors:
    """Loader and integrity checker for a collection."""

    def __init__(self, root: Traversable | None = None) -> None:
        """Initialize the collection at root, or the packaged collection when None."""
        self._root = root if root is not None else _DATA
        self.mdoc = _MdocCollection(self._root)

    def check(self) -> None:
        """Raise CorpusError for any malformed vector or unresolved reference."""
        findings = _collect_findings(self._root)
        if findings:
            raise CorpusError("\n".join(findings))
