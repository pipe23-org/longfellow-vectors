# Admission

`tools/admission/admit.py` writes vectors into the collection. It is a uv
project of its own under `tools/admission/`. Its paths resolve relative to the
script, so it finds the collection wherever the repository sits.

```
cd tools/admission
uv run admit.py <command> --help
```

One command admits each vector type: `key`, `credential`, `presentation`,
`circuit`, `certificate`, and `proof`. New artifacts are constructed by
`tools/generation/generate.py`. [Generation](generation.md) has its commands.

## Names

Every command takes `--name`, the vector's file stem. A name matches
`^[a-z0-9][a-z0-9-]*$`. [Naming](naming.md) states what a name says about the
bytes.

## Bytes

Every command copies its source bytes byte-identically into the vector's blob
file, and derives `sha256` from them. `presentation` writes no blob file. It
copies the source's `mdoc` and `transcript` hex into the sidecar.

## Provenance

`--repo` names the source repository as host/owner/name. The commit and the
in-repo path are read from the source file's own git checkout, so the file
passed on the command line has to sit inside a checkout of the repository
`--repo` names. `captured` holds the day of admission.

`--generator` holds the command line that produced staged bytes and `--ref` the
generator's commit; the two are required together. Provenance then records
`type: "constructed"` with both and `created` holding the day of admission.

`circuit` takes `--repo` only. `key`, `certificate`, `credential`,
`presentation`, and `proof` take exactly one of `--repo` and `--generator`.

## Derived fields

Each command derives the fields its vector type takes from the bytes.
[Vectors](vectors.md#derived-fields) lists them per type. A field the bytes do
not yield is omitted from the sidecar, and the omission is printed. Bytes that
do not parse are admitted with those fields absent.

A command that cannot derive a field it needs for a verification exits without
writing. `credential --device-key` on a credential whose CBOR does not parse is
refused, as are `certificate --signed-by` and `--key` on a PEM that does not
parse.

## Reference fields

A reference field is written only when its relation was verified, and a
verification that fails exits without writing anything. The named vector has to
be in the collection already. A command given a name the collection does not
hold exits and names the missing vector.

## Schema validation

Every sidecar is validated against its vector type's schema in
`vectors/schemas/` before any file is written. A sidecar the schema rejects is
not admitted, and one line per schema error is printed.

## Comments

Every command takes `--comment`, written to the sidecar's `comment` field when
given. A field the operator chose to leave out has its reason in the comment.

## key

| Flag | Effect |
| --- | --- |
| `pem_path` | PEM file to admit, copied to `vectors/mdoc/keys/<name>.pem`. |
| `--role` | `iaca`, `document-signer`, or `device`, recorded as given. |
| `--repo`, `--generator`, `--ref` | Provenance, as above. |
| `--name` | Vector name. |
| `--comment` | Sidecar comment. |

## credential

| Flag | Effect |
| --- | --- |
| `cbor_path` | IssuerSigned CBOR file to admit, copied to `vectors/mdoc/credentials/<name>.cbor`. |
| `--device-key` | Key vector whose public half must equal the `deviceKeyInfo` coordinates of the MSO inside the top-level `issuerAuth`. Refused on mismatch. |
| `--ds-certificate` | Certificate vector whose DER bytes must equal the x5chain leaf of the top-level `issuerAuth`. Refused on mismatch. |
| `--repo`, `--generator`, `--ref` | Provenance, as above. |
| `--name` | Vector name. |
| `--comment` | Sidecar comment. |

## presentation

| Flag | Effect |
| --- | --- |
| `vector_path` | JSON file with an `mdoc` field and a `transcript` field, each holding hex. |
| `--credential` | Credential vector the DeviceResponse presents. Refused when the collection holds no credential of that name, when the presented `issuerAuth` does not equal the credential's, or when a presented item is not one of the credential's. |
| `--repo`, `--generator`, `--ref` | Provenance, as above. |
| `--name` | Vector name. |
| `--comment` | Sidecar comment. |

A response that carries no issuer-signed item is admitted with `--credential`. The
presented `issuerAuth` still has to equal the credential's.

## circuit

| Flag | Effect |
| --- | --- |
| `blob_path` | Circuit blob to admit, copied to `vectors/mdoc/circuits/<name>.circuit`. |
| `--version` | Circuit version, recorded as given. The blob is not parsed. |
| `--num-attributes` | Attribute count, recorded as given. The blob is not parsed. |
| `--repo` | Provenance, as above. |
| `--name` | Vector name. |
| `--comment` | Sidecar comment. |

`system` is written as `longfellow-libzk-v1` and the schema admits no other
value.

## certificate

| Flag | Effect |
| --- | --- |
| `pem_path` | PEM file to admit, copied to `vectors/mdoc/certificates/<name>.pem`. |
| `--role` | `iaca` or `document-signer`, recorded as given. |
| `--signed-by` | Certificate vector whose key must verify this certificate's signature. Refused when the signature does not verify. |
| `--key` | Key vector whose `fingerprint` must equal the certificate's SubjectPublicKeyInfo fingerprint. Refused on mismatch, and refused when the key vector carries no `fingerprint`. |
| `--repo`, `--generator`, `--ref` | Provenance, as above. |
| `--name` | Vector name. |
| `--comment` | Sidecar comment. |

A `--signed-by` certificate whose own key is not an EC key is refused, as is a
certificate that carries no signature hash algorithm.

## proof

| Flag | Effect |
| --- | --- |
| `proof_path` | Proof blob to admit, copied to `vectors/mdoc/proofs/<name>.proof`. |
| `--prover` | Backend registry name, recorded as given. |
| `--circuit` | Circuit vector the proof was made with. Refused when the collection holds no circuit of that name. |
| `--timestamp` | Verification time, recorded as given. The schema rejects anything other than an RFC 3339 date-time with a UTC offset. |
| `--presentation` | Presentation vector the statement is copied from. |
| `--attr` | Attribute id the proof discloses. Repeatable, and requires `--presentation`. |
| `--doctype`, `--transcript`, `--issuer-public-key-x`, `--issuer-public-key-y`, `--claim`, `--device-namespaces` | The statement, supplied on the command line. |
| `--repo`, `--generator`, `--ref` | Provenance, as above. |
| `--name` | Vector name. |
| `--comment` | Sidecar comment. |

A proof takes its statement from one of two sources, and the two are mutually
exclusive.

With `--presentation`, `doctype`, `transcript`, `issuer_public_key_x`,
`issuer_public_key_y`, and `device_namespaces` are copied from the presentation
vector, each of them that the vector carries. Each `--attr` names an
attribute id, and
the claim's namespace and CBOR value are read from that presentation's
`issuerSigned` map. At least one `--attr` is required, and an id the map does
not hold is refused.

With the statement flags, the values are written as given, with hex
lowercased. `--doctype`, `--transcript`, `--issuer-public-key-x`,
`--issuer-public-key-y`, and at least one `--claim` are required together.
`--device-namespaces` is optional. `--attr` alongside them is refused.

Given neither, the vector holds the proof bytes and the provenance alone.

## Readmission from source

A vector whose provenance is `type: "repository"` carries what a re-run needs.

1. Clone the repository `provenance.repo` names, and check out
   `provenance.ref`.
2. Run the command for the vector's type against the file at `provenance.path`
   inside that checkout, passing the recorded `repo` as `--repo` and the
   vector's stem as `--name`.
3. Pass again every value the sidecar holds that the tool does not derive:
   `--role`, `--version`, `--num-attributes`, `--prover`, `--timestamp`, the
   reference names, the statement flags, and `--comment`.

The new sidecar's `ref` and `path` come from the checkout, so they equal the
recorded values. `captured` holds the day of the re-run.
