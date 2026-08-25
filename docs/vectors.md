# Vectors

A vector is a JSON sidecar under `vectors/mdoc/<type>/` and, for every type but
presentations, the byte file beside it. The sidecar is validated against the
schema it names in its `schema` field. A sidecar carrying a field its schema
does not list is rejected. Blob-carrying types keep the bytes in a sibling file
under the vector's stem.

## Value shapes

`common-v1.schema.json` defines the value shapes the vector schemas reference.
No sidecar names that file in its `schema` field.

| Shape | Holds |
| --- | --- |
| `hex` | Byte string as an even, positive number of lowercase hex digits. |
| `sha256hex` | SHA-256 digest as 64 lowercase hex digits. |
| `p256coordinate` | P-256 affine coordinate as 64 lowercase hex digits, left-padded with zeros. |
| `p256scalar` | P-256 private scalar as 64 lowercase hex digits, left-padded with zeros. |

## Provenance

`provenance` takes one of two shapes, distinguished by its `type` field.

`type: "repository"` records bytes copied out of a repository at a commit.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `type` | `"repository"` | yes | The shape this provenance takes. |
| `repo` | string | yes | Source repository as host/owner/name, e.g. `github.com/google/longfellow-zk`. |
| `ref` | 40 lowercase hex digits | yes | Full commit hash the bytes were captured at. |
| `path` | string | yes | Path of the source artifact within the repository at `ref`. |
| `index` | string | no | Position within the source artifact when the bytes are one of several it holds, e.g. `mdoc_tests[15]`. |
| `via` | string | no | Intermediate artifact the bytes passed through, when not captured directly. |
| `captured` | `YYYY-MM-DD` | yes | Date the bytes were copied out of the source. |
| `license` | string | no | SPDX identifier of the source's license, recorded when that license requires copied bytes to carry its terms, e.g. `MPL-2.0`. |
| `copyright` | string | no | Copyright notice retained from the source, e.g. `Copyright 2025 ISRG`. |

`type: "constructed"` records bytes that a tool produced outside any
repository.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `type` | `"constructed"` | yes | The shape this provenance takes. |
| `generator` | string | yes | The generating command as run, e.g. `generate_vectors.py flip-bit --proof <name> --byte 3`. The command line states what was run; it reproduces the bytes only for a deterministic mode. |
| `ref` | 40 lowercase hex digits | no | Full commit hash of the generator at generation time. |
| `created` | `YYYY-MM-DD` | yes | Date the bytes were generated. |

## Keys

`mdoc-keys-v1.schema.json`, sidecar for a PEM private key under
`vectors/mdoc/keys/`.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `schema` | `"mdoc-keys-v1.schema.json"` | yes | The schema this sidecar validates against. |
| `role` | `iaca`, `document-signer`, or `device` | yes | Position in the ISO 18013-5 trust chain. |
| `sha256` | `sha256hex` | yes | SHA-256 of the sibling `.pem` file's bytes. |
| `fingerprint` | `sha256hex` | no | SHA-256 of the public key as DER-encoded SubjectPublicKeyInfo. |
| `public_key_x` | `p256coordinate` | no | Affine coordinate x of the key's public half. |
| `public_key_y` | `p256coordinate` | no | Affine coordinate y of the key's public half. |
| `private_key` | `p256scalar` | no | The key's private scalar. |
| `provenance` | provenance | yes | Where the bytes came from. |
| `comment` | string | no | Construction facts about the vector. |

`public_key_x` and `public_key_y` are present together. `private_key` is
present only alongside both coordinates.

## Credentials

`mdoc-credentials-v1.schema.json`, sidecar for a CBOR credential under
`vectors/mdoc/credentials/`.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `schema` | `"mdoc-credentials-v1.schema.json"` | yes | The schema this sidecar validates against. |
| `doctype` | string | no | DocType read from the credential. |
| `device_key` | vector name | no | The credential's device key. |
| `ds_certificate` | vector name | no | The credential's document-signer certificate. |
| `sha256` | `sha256hex` | yes | SHA-256 of the sibling `.cbor` file's bytes. |
| `provenance` | provenance | yes | Where the bytes came from. |
| `comment` | string | no | Construction facts about the vector. |

## Presentations

`mdoc-presentations-v1.schema.json`, sidecar under
`vectors/mdoc/presentations/`. The vector carries the DeviceResponse bytes
itself and has no blob file. `deviceAuth` binds the response to the transcript,
so the response is unusable with any other transcript.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `schema` | `"mdoc-presentations-v1.schema.json"` | yes | The schema this sidecar validates against. |
| `doctype` | string | no | DocType of the response's document. |
| `mdoc` | `hex` | yes | CBOR DeviceResponse bytes, byte-true to the source. |
| `device_namespaces` | `hex` | no | Inner bytes of the tag-24 DeviceNameSpacesBytes, a copy of a value inside `mdoc`. |
| `transcript` | `hex` | no | SessionTranscript bytes the response's `deviceAuth` signs. |
| `issuer_public_key_x` | `p256coordinate` | no | Issuer (document signer) public key coordinate x, a copy of the SPKI point inside the x5chain of `mdoc`. |
| `issuer_public_key_y` | `p256coordinate` | no | Issuer public key coordinate y. |
| `credential` | vector name | no | The credential the DeviceResponse presents. |
| `provenance` | provenance | yes | Where the bytes came from. |
| `comment` | string | no | Construction facts about the vector. |

## Circuits

`mdoc-circuits-v1.schema.json`, sidecar for a compressed circuit blob under
`vectors/mdoc/circuits/`.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `schema` | `"mdoc-circuits-v1.schema.json"` | yes | The schema this sidecar validates against. |
| `system` | `longfellow-libzk-v1` | yes | ZK system name and version the circuit belongs to. |
| `sha256` | `sha256hex` | yes | SHA-256 of the sibling `.circuit` file's bytes. |
| `version` | integer, 1 to 2147483647 | yes | Circuit version the blob was exported at. |
| `num_attributes` | integer, 1 to 2147483647 | yes | Number of attributes the circuit proves over. |
| `provenance` | provenance | yes | Where the bytes came from. |
| `comment` | string | no | Construction facts about the vector. |

## Certificates

`mdoc-certificates-v1.schema.json`, sidecar for a PEM certificate under
`vectors/mdoc/certificates/`.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `schema` | `"mdoc-certificates-v1.schema.json"` | yes | The schema this sidecar validates against. |
| `role` | `iaca` or `document-signer` | yes | Position in the ISO 18013-5 trust chain. |
| `sha256` | `sha256hex` | yes | SHA-256 of the sibling `.pem` file's bytes. |
| `public_key_x` | `p256coordinate` | no | Affine coordinate x of the certificate's SubjectPublicKeyInfo P-256 key. |
| `public_key_y` | `p256coordinate` | no | Affine coordinate y of the certificate's SubjectPublicKeyInfo P-256 key. |
| `signed_by` | vector name | no | The certificate whose key signed this one. |
| `key` | vector name | no | The key vector this certificate certifies. |
| `provenance` | provenance | yes | Where the bytes came from. |
| `comment` | string | no | Construction facts about the vector. |

`public_key_x` and `public_key_y` are present together.

## Proofs

`mdoc-proofs-v1.schema.json`, sidecar for a proof blob under
`vectors/mdoc/proofs/`. The statement fields hold the public statement the
bytes verify against. A vector whose source supplied no recoverable statement
omits them and holds the bytes alone. Statement values are equal across proofs
made from one session.

| Field | Type | Required | Holds |
| --- | --- | --- | --- |
| `schema` | `"mdoc-proofs-v1.schema.json"` | yes | The schema this sidecar validates against. |
| `prover` | string | no | Implementation that produced the proof bytes, by backend registry name, e.g. `google-cpp`. |
| `circuit` | vector name | no | The circuit the proof was made with. |
| `sha256` | `sha256hex` | yes | SHA-256 of the sibling `.proof` file's bytes. |
| `doctype` | string | no | Mdoc doctype the proof is scoped to. |
| `claims` | array of claim objects, at least one | no | Attribute values the proof discloses. |
| `transcript` | `hex` | no | SessionTranscript bytes the proof is bound to. |
| `issuer_public_key_x` | `p256coordinate` | no | Issuer (document signer) public key coordinate x. |
| `issuer_public_key_y` | `p256coordinate` | no | Issuer public key coordinate y. |
| `timestamp` | RFC 3339 date-time with a UTC offset | no | Verification time the proof was made with. |
| `device_namespaces` | `hex` | no | Inner bytes of the tag-24 DeviceNameSpacesBytes, a verify input of some implementations. |
| `presentation` | vector name | no | The presentation the proof was made from. |
| `provenance` | provenance | yes | Where the bytes came from. |
| `comment` | string | no | Construction facts about the vector. |

Every field of a claim object is required.

| Field | Type | Holds |
| --- | --- | --- |
| `namespace` | string | Mdoc namespace of the attribute. |
| `id` | string | Attribute identifier within the namespace. |
| `cbor_value` | `hex` | CBOR encoding of the attribute's value. |

## Derived fields

The admission tool derives these fields from the vector's bytes. A field it
cannot derive is omitted from the sidecar and the omission is printed.

| Type | Field | Derived from |
| --- | --- | --- |
| Keys | `sha256` | The PEM bytes. |
| Keys | `fingerprint` | The public key the PEM encodes, when the PEM parses. |
| Keys | `public_key_x`, `public_key_y` | The PEM, when it holds an EC P-256 key. |
| Keys | `private_key` | The PEM, when it holds an EC P-256 private key. |
| Credentials | `sha256` | The CBOR bytes. |
| Credentials | `doctype` | The CBOR, when it parses as a DeviceResponse. |
| Presentations | `doctype` | The `mdoc` bytes, when they parse as a DeviceResponse. |
| Presentations | `issuer_public_key_x`, `issuer_public_key_y` | The leaf certificate in the `mdoc` bytes' x5chain. |
| Presentations | `device_namespaces` | The `deviceSigned` nameSpaces in the `mdoc` bytes. |
| Circuits | `sha256` | The circuit blob's bytes. |
| Certificates | `sha256` | The PEM bytes. |
| Certificates | `public_key_x`, `public_key_y` | The SubjectPublicKeyInfo, when the PEM parses and holds an EC P-256 key. |
| Proofs | `sha256` | The proof blob's bytes. |

A certificate whose PEM does not parse as X.509 is admitted with `public_key_x`
and `public_key_y` absent; `--signed-by` and `--key` are refused for it.

A proof's statement fields are not derived from the proof bytes. They are
copied from the presentation vector the proof names, or supplied on the
command line.

## References

A reference field holds the name of a vector. Names are unique within a type
directory, and references are type-scoped.

| Field | On | Names a | Held at admission |
| --- | --- | --- | --- |
| `device_key` | Credentials | key | The key vector's public half matched the credential's `deviceKeyInfo`. |
| `ds_certificate` | Credentials | certificate | The certificate vector's DER bytes matched the credential's x5chain leaf. |
| `credential` | Presentations | credential | The named credential vector was in the collection. |
| `signed_by` | Certificates | certificate | The named certificate's key verified this certificate's signature. |
| `key` | Certificates | key | The certificate's SubjectPublicKeyInfo fingerprint equalled the key vector's `fingerprint`. |
| `circuit` | Proofs | circuit | The named circuit vector was in the collection. |
| `presentation` | Proofs | presentation | The proof's statement fields were copied from that presentation vector. |
