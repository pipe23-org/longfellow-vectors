# Vector naming

A vector's name is its file stem. Reference fields (`circuit`,
`credential`, `presentation`, `signed_by`, `key`, `device_key`,
`ds_certificate`) hold these names; a name is unique within its type's
directory, and references are type-scoped.
Names are lowercase words joined by hyphens.

- A name states what the bytes are and where they came from.
- A name describes the artifact's content, never an intended use. A
  credential is named for what it contains, not for what someone plans
  to prove from it.
- Expected outcomes are consumer knowledge. Accept/reject vocabulary
  never appears in a name; which vectors verify and which fail is
  recorded in downstream test ledgers.
- A vector derived by modifying another vector's bytes takes the source
  vector's name followed by the operation performed.
- A vector constructed to stand in for another artifact says so in its
  name.
- Related vectors share a stem.
- Two unrelated artifacts of different types do not share a name.
- Classification (a certificate or key role) is a sidecar field, never a
  subdirectory; type directories stay flat.

## circuits/

`{origin}-v{version}-{attributes}attr`. The origin names the
implementation whose export produced the bytes; the attribute count is
the number of attributes the circuit proves under.

- `google-v7-1attr` — google/longfellow-zk export, circuit version 7,
  one attribute.
- `google-v6-1attr-sha256-circuit-id-zeroed` — derived from
  `google-v6-1attr`: the sha256 circuit's serialized id zeroed.

## credentials/

A credential (CBOR IssuerSigned) is named for its doctype and
what distinguishes its content: the test persona, or the semantic
property that sets it apart. Attribute counts are not name material. A
credential may reference its device-key vector (`device_key`) and its
document-signer certificate vector (`ds_certificate`).

- `mdl-mustermann` — an mDL for the Mustermann test persona.
- `mdl-under-18` — an mDL whose holder is under 18.
- `mdl-over-18` — an mDL whose holder is over 18.

## presentations/

`{credential-content}[-{distinguisher}]`. A presentation
(DeviceResponse plus the session transcript its deviceAuth signs) is
named for its credential content, plus whatever honestly distinguishes
the session when more than one exists: the mint date when known, a
notable session property, an ordinal otherwise. A minted presentation
references its credential vector; a captured presentation stands alone,
its credential embedded in the DeviceResponse and not separately
shelved.

- `mdl-mustermann-20260824` — the Mustermann mDL over a session minted
  2026-08-24.
- `mdl-mustermann-device-namespaces-nonempty` — a session whose device
  signed a non-empty DeviceNameSpaces map.

## keys/

A key is named for its role and the identity behind it, numbered when
several share both. Keys carry no validity window; windows belong to
certificates, and one key may be certified more than once. The key's
fingerprint is a sidecar fact, not name material.

- `iaca-vectors` — this collection's minted IACA key.
- `ds-vectors` — a minted document-signer key.
- `device-vectors-01` — a minted device key.
- `iaca-ec` — a found key: the European Commission's test IACA,
  captured from its published test material.

## proofs/

`{prover}-{presentation}-v{version}-{attributes}attr`: the sidecar's
`prover` field, the referenced presentation's name, and the referenced
circuit's version and attribute count, in that order.

- `google-cpp-mdl-mustermann-20260824-v7-1attr` — proved by google-cpp
  from the `mdl-mustermann-20260824` presentation under the version-7
  one-attribute circuit.
- `google-cpp-mdl-mustermann-20260824-v7-1attr-bit-flipped` — derived
  from `google-cpp-mdl-mustermann-20260824-v7-1attr`: the low bit of
  one proof byte flipped.

## certificates/

A certificate is named for its role, the identity behind it, and its
validity window. The `key` field references the key vector it certifies.

- `iaca-vectors-2026-2036` — a certificate over the key `iaca-vectors`.
- `ds-vectors-2026-2031` — a document-signer certificate over
  `ds-vectors`, `signed_by` naming its IACA.
