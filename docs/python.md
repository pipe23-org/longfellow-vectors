# Python package

`longfellow_vectors` loads the collection as typed vectors and checks its
integrity. The top-level package exports `LongfellowVectors`, `CorpusError`,
`PublicKey`, `Statement`, and `__version__`.

## Installation

```
pip install longfellow-vectors
```

## Usage

```pycon
>>> from longfellow_vectors import LongfellowVectors
>>> vectors = LongfellowVectors()
>>> vectors.check()
>>> proof = vectors.mdoc.proof("google-cpp-mdl-mustermann-v7-1attr")
>>> proof.circuit.version, proof.circuit.num_attributes
(7, 1)
>>> proof.statement().claims[0]
Claim(namespace='org.iso.18013.5.1', id='issue_date', cbor_value=b'\xd9\x03\xecj2024-03-15')
>>> proof.provenance.repo
'github.com/abetterinternet/zk-cred-longfellow'
```

## Vector types

`LongfellowVectors.mdoc` holds one view per vector type. Each type has an
accessor returning every vector sorted by name, and an accessor taking one
vector name.

| Type | Class | All vectors | By name | Bytes attribute |
| --- | --- | --- | --- | --- |
| Keys | `Key` | `keys()` | `key(name)` | `pem` |
| Credentials | `Credential` | `credentials()` | `credential(name)` | `bytes` |
| Presentations | `Presentation` | `presentations()` | `presentation(name)` | `mdoc` |
| Circuits | `Circuit` | `circuits()` | `circuit(name)` | `bytes` |
| Certificates | `Certificate` | `certificates()` | `certificate(name)` | `pem` |
| Proofs | `Proof` | `proofs()` | `proof(name)` | `bytes` |

Every vector carries `name`, `provenance`, and `comment`. Blob-carrying vectors
carry `sha256`, the value the sidecar records rather than a digest computed at
load.

A reference field holds the referenced vector itself. `Proof.circuit` is a
`Circuit`, `Proof.presentation` a `Presentation`, `Credential.device_key` a
`Key`, `Credential.ds_certificate` a `Certificate`, `Certificate.signed_by` a
`Certificate`, and `Certificate.key` a `Key`. Each is `None` when the sidecar
records no such reference.

Sidecars are validated and references resolved on the first access to each
vector type, and the loaded vectors are cached on the `LongfellowVectors`
instance.

## Accessors

`Credential.claims()` parses the vector's IssuerSigned and
`Presentation.claims()` the vector's DeviceResponse; both return the
issuer-signed claims in document order, as a tuple of `Claim`. Each call
re-parses the bytes.

`Proof.statement()` returns the `Statement` the vector's `doctype`,
`transcript`, `issuer_public_key`, `claims`, `timestamp`, and
`device_namespaces` hold.

`Key.public_key`, `Certificate.public_key`, `Presentation.issuer_public_key`,
and `Proof.issuer_public_key` hold a `PublicKey` with the affine coordinates as
ints. Each is `None` when the sidecar omits the coordinates.

`Key.der` and `Certificate.der` return the DER bytes the vector's PEM encodes.

## check()

`LongfellowVectors.check()` walks the whole collection and raises `CorpusError`
holding one line per file that breaks a rule. The rules it checks:

- A blob's SHA-256 equals its sidecar's `sha256`.
- A sidecar parses as JSON and validates against the schema it names.
- A sidecar names the schema of the directory it sits in.
- A sidecar has its blob beside it, and a blob has its sidecar.
- A blob's suffix is the one its directory takes.
- Every entry at the collection root is one of the six vector directories.
- Every reference names a vector in the collection.
- The certificate signing references hold no cycle.

## Exceptions

| Exception | Raised by |
| --- | --- |
| `CorpusError` | `check()` for any finding. A loader for a root that is not a directory, for a reference naming no vector, and for a cycle in the certificate signing references. `Proof.statement()` for a vector that carries no statement. |
| `ValueError` | A loader for a sidecar that is not JSON, one the schema rejects, one naming a schema that does not belong in its directory, and a circuit whose `version` or `num_attributes` is a JSON number carrying a fraction. `Key.der` and `Certificate.der` for a PEM that is not a single block. `Credential.claims()` for a payload that is not IssuerSigned, and `Presentation.claims()` for one that is not a DeviceResponse. |
| `KeyError` | A by-name accessor for a name no vector has. |
| `FileNotFoundError` | A loader for a sidecar whose blob file is absent. |
| `cbor2.CBORDecodeError` | `claims()` for a payload that is not valid CBOR. |

## Packaged collection

The wheel embeds a snapshot of `vectors/` taken when the wheel was built.
`LongfellowVectors()` with no argument reads that snapshot. `LongfellowVectors`
also takes a root, any `importlib.resources.abc.Traversable`, and reads the
collection there.

Sidecars are validated against the schemas packaged with the installed
`longfellow_vectors`. A `schemas/` directory under a caller-supplied root is
never read.

## API

::: longfellow_vectors.mdoc
