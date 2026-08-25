# longfellow-vectors

longfellow-vectors is a collection of test vectors for Longfellow
zero-knowledge proof implementations (draft-google-cfrg-libzk). The vector
types are keys, credentials, presentations, circuits, certificates, and proofs.
Every vector carries structured provenance citing where its bytes came from.

## Collection layout

The collection is the repository's `vectors/` directory. `vectors/schemas/`
holds one schema per vector type, plus `common-v1.schema.json`, the shared
value shapes the vector schemas reference. `vectors/mdoc/<type>/` holds the
vectors of one type; the type directories are flat.

Every vector has a JSON sidecar. Keys, credentials, circuits, certificates, and
proofs keep their bytes in a blob file beside the sidecar, under the same stem
with the type's suffix. A presentation vector is the sidecar alone and carries
its DeviceResponse bytes as hex in the sidecar's `mdoc` field. Every sidecar
names the schema it validates against in its own `schema` field.

| Type | Directory | Blob suffix | Schema |
| --- | --- | --- | --- |
| Keys | `vectors/mdoc/keys/` | `.pem` | `mdoc-keys-v1.schema.json` |
| Credentials | `vectors/mdoc/credentials/` | `.cbor` | `mdoc-credentials-v1.schema.json` |
| Presentations | `vectors/mdoc/presentations/` | none | `mdoc-presentations-v1.schema.json` |
| Circuits | `vectors/mdoc/circuits/` | `.circuit` | `mdoc-circuits-v1.schema.json` |
| Certificates | `vectors/mdoc/certificates/` | `.pem` | `mdoc-certificates-v1.schema.json` |
| Proofs | `vectors/mdoc/proofs/` | `.proof` | `mdoc-proofs-v1.schema.json` |

`vectors/mdoc/circuits/google-v7-1attr.json`, the sidecar governing
`google-v7-1attr.circuit`:

```json
{
  "schema": "mdoc-circuits-v1.schema.json",
  "system": "longfellow-libzk-v1",
  "sha256": "9016d173d8a579a104591b85826798bfbb03eafa7b376ad18c5344eab3a92769",
  "version": 7,
  "num_attributes": 1,
  "provenance": {
    "type": "repository",
    "repo": "github.com/pipe23-org/pylongfellow",
    "ref": "28345228f01626ac1a84602f829efe81bd591fcd",
    "path": "tests/differential/circuits/v7-1attr.circuit",
    "captured": "2026-08-25"
  }
}
```

[Vectors](vectors.md) has the fields of every vector type.
[Admission](admission.md) has the tool that writes them. [Naming](naming.md)
has what a name says about the bytes.

## Guarantees

Every sidecar validates against the schema it names, at admission and again at
load. A sidecar naming a schema that does not belong in the directory it sits
in fails the load. A sidecar carrying a field its schema does not list is
rejected.

Every reference field records a relation that held when the vector was
written. `LongfellowVectors.check()` recomputes each blob's SHA-256 and
compares it against the sidecar's `sha256`, and resolves every reference
against the collection.

## Unchecked relations

Role consistency between referenced vectors is checked by neither the schema
nor the loader. A certificate's `signed_by` may name a certificate of either
role. A credential's `ds_certificate` may name a certificate of either role. A
proof's claim count is unconstrained by its circuit's `num_attributes`.

The Python package validates sidecars against the schemas packaged with the
installed `longfellow_vectors`. A `schemas/` directory under a root passed to
`LongfellowVectors` is never read.
