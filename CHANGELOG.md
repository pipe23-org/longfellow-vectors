# Changelog

## Unreleased

- **BACKWARDS INCOMPATIBLE:** `admit.py proof --attr` now takes a namespace and an attribute id; previously it took an id alone and refused the whole credential when any id appeared under more than one namespace. (#12)
- **BACKWARDS INCOMPATIBLE:** `admit.py proof` now requires `--timestamp` whenever a statement is written, with `--presentation` and alongside the statement flags; previously a proof could be admitted whose recorded statement could never be read back. (#12)
- **BACKWARDS INCOMPATIBLE:** Removed `index`, `via`, `license`, and `copyright` from repository provenance. No flag wrote any of them. (#12)
- `admit.py` now refuses a name the collection already holds; previously a second admission replaced the vector, leaving references verified against the replaced bytes. (#12)
- `admit.py` now refuses a source checkout carrying uncommitted changes; previously it recorded HEAD as the ref whether or not that commit held the bytes being admitted. (#11)
- **BACKWARDS INCOMPATIBLE:** Removed `captured` from repository provenance and `ref` and `created` from constructed provenance; `captured` and `created` were required. A sidecar carrying any of the three is rejected. Repository provenance keeps `ref`, derived from the source checkout. (#10)
- **BACKWARDS INCOMPATIBLE:** Credential vectors now hold `IssuerSigned` CBOR, `{nameSpaces, issuerAuth}`; previously they held a `DeviceResponse`. `Credential.claims()` reads the top-level `nameSpaces` instead of `documents[0].issuerSigned.nameSpaces`. (#8)
- `tools/add_vector.py` is now `tools/admission/admit.py`, a uv project under `tools/admission/`, and its commands are named by vector type: `circuit`, `presentation`, `proof`, `key`, `credential`, and `certificate`, previously `import-circuit`, `import-presentation`, `import-proof`, `import-key`, `import-credential`, and `import-certificate`. Flags are unchanged. (#8)
- Added `tools/generation/generate.py`, a uv project under `tools/generation/` pinned to pylongfellow 0.5.2, with one construction command per vector type, `key`, `certificate`, `credential`, `presentation`, and `proof`, and `flip-bit`, which derives a proof from an admitted proof. Each command reads the vectors it builds on from the collection by name and prints the `admit.py` command that admits its output. (#8)
- The `generator` field of constructed provenance now holds the generating command line with every value the command generated filled in, and re-running it reproduces the bytes for every `generate.py` command but `proof`; previously it named a tool and mode. Signatures use the RFC 6979 nonce, key scalars and `IssuerSignedItem` salts derive from a seed, and a seed or certificate serial the command generated is filled into the recorded command line. (#8)
- `admit.py presentation --credential` now verifies that the presented `issuerAuth` equals the credential's and that every presented item is one of the credential's; previously the field was recorded unverified. (#8)
- `admit.py certificate` now takes `--generator` alongside `--repo`, so a constructed certificate is admitted with constructed provenance; previously `--repo` was required. (#8)
- The package metadata now carries Python 3.11 through 3.14 classifiers. (#8)

## 0.0.1 - 2026-08-25

- Removed every vector from the collection ahead of the first public release; vectors are readmitted from their original sources as the consumers' tests come to need them. `check()` and the loaders ignore a dotfile anywhere in the collection.
- `tools/add_vector.py import-certificate` now admits a PEM that does not parse as X.509, omitting `public_key_x` and `public_key_y`; previously it refused the vector. `--signed-by` and `--key` are refused for such a PEM.
- Initial project scaffold.
- Renamed the `Proof.proof` and `Circuit.circuit` payload attributes to `bytes`.
- `version` and `num_attributes` are now required on circuit records.
- Removed `block_enc_hash` and `block_enc_sig` from circuit records.
- Hex-valued fields now reject the empty string and any trailing whitespace; previously `""` was a valid `hex` value and a trailing newline was accepted after every fixed-length hex value, the commit ref, and the repository.
- Free-text string fields (`computed_by`, `comment`, `generator`, provenance `path`, `index`, `via`, `license`, `copyright`, `doctype`, `prover`, and claim `namespace` and `id`) now reject the empty string.
- `captured` and `created` now require the `YYYY-MM-DD` form, and proof `timestamp` now requires an RFC 3339 date-time carrying `Z` or a numeric offset; previously any string `date.fromisoformat` or `datetime.fromisoformat` accepted was valid, including the basic form `20260825`, a bare date, and a naive timestamp.
- Added the `p256coordinate` definition to `common-v1.schema.json`; `issuer_public_key_x` and `issuer_public_key_y` on presentation and proof records reference it in place of `sha256hex`.
- `tools/add_vector.py` now rejects a `--name` that does not match `^[a-z0-9][a-z0-9-]*$`.
- The wrapper and `tools/add_vector.py` depend on `jsonschema[format]`; `format: date` and `format: date-time` are checked by jsonschema's format checkers.
- `LongfellowVectors.check()` now reports a root that is not a directory, an unknown subtree or file at the collection root, a sidecar whose schema does not belong in its subtree, a blob file whose suffix is not the subtree's, and a sidecar or blob that is not a regular file; a directory named like a sidecar and a dangling blob symlink previously raised `IsADirectoryError` and `FileNotFoundError` out of `check()`.
- `check()` findings and loader errors now name the subtree along with the file, as `circuits/good.json: ...`; previously they named the file alone. A sidecar that is not JSON now raises `ValueError` from the loaders; previously `json.JSONDecodeError`.
- Loading a collection whose root does not exist or is not a directory now raises `CorpusError`; previously every record type loaded empty.
- Loading a circuit record whose `version` or `num_attributes` is a JSON number carrying a fraction now raises `ValueError`; previously the value reached the dataclass as a float.
- Loading a sidecar whose `schema` does not belong in the subtree it sits in now raises `ValueError`; previously the record loaded.
- Added the optional `public_key_x` and `public_key_y` fields to certificate records, required together, holding the affine coordinates of the certificate's SubjectPublicKeyInfo P-256 key.
- Added `Certificate.public_key`, a `PublicKey` holding the coordinates the sidecar records, and `None` when the sidecar omits them.
- Removed `circuit_id` and `computed_by` from circuit records, `Circuit.circuit_id` and `Circuit.computed_by` from the wrapper, and `--circuit-id` and `--computed-by` from `tools/add_vector.py import-circuit`.
- Added the `p256scalar` definition to `common-v1.schema.json` and the optional `public_key_x`, `public_key_y`, and `private_key` fields to key records, holding the affine coordinates and the private scalar of an EC P-256 key. `import-key` derives them from the PEM, and `Key.public_key` and `Key.private_key` hold what the sidecar records.
- `Presentation.issuer_public_key` and `Proof.issuer_public_key` now hold a `PublicKey`, replacing the `issuer_public_key_x` and `issuer_public_key_y` integer pairs; the sidecar fields are unchanged.
- Added `Statement` and `Proof.statement()`, which returns the public statement the proof verifies against and raises `CorpusError` naming the first statement field the record does not carry.
- Added `Certificate.der` and `Key.der`, the DER bytes the PEM encodes; both raise `ValueError` when the PEM is not a single block.
- Added `py.typed` to the wrapper package.
- `tools/add_vector.py import-proof` now takes `--doctype`, `--transcript`, `--issuer-public-key-x`, `--issuer-public-key-y`, `--claim`, and `--device-namespaces`, which record a statement for a proof whose source shelves no presentation. They are mutually exclusive with `--presentation`.
- Moved the record naming convention from `vectors/mdoc/NAMING_CONVENTION.md` to `docs/naming.md`, and `check()` now reports every file directly under the collection root; previously `NAMING_CONVENTION.md` was accepted there.
- `check()` findings, loader errors, by-name lookup errors, and `tools/add_vector.py` help and error text now name a collection entry a vector, as `device_key 'k' matches no key vector` and `no key vector named 'k'`; previously they named it a record.
