# Generation

`tools/generation/generate.py` constructs new vectors and stages them for
admission. It is a uv project of its own under `tools/generation/`. It depends
on a released `pylongfellow`. Each command writes the
bytes it constructs under `tools/generation/staging/<name>/`, a directory
`.gitignore` lists. The command prints the `admit.py` command that admits them.

```
cd tools/generation
uv run generate.py <command> --help
```

One command builds each vector type: `key`, `certificate`, `credential`,
`presentation`, and `proof`. `flip-bit` derives a proof from an admitted proof.
`tools/generation/README.md` lists the known gaps.

## Inputs

Each command reads the vectors it builds on from the collection by name. A
command given a name the collection does not hold exits and names the missing
vector.

## Admission commands

The printed command admits the staged bytes with constructed provenance. It
runs from `tools/admission`. The staged path it carries is written relative to
that directory. Its reference flags are filled in from the generating
command's inputs. `--generator` holds the `generate.py` command line with every
value the command generated filled in. `--ref` holds the commit
`tools/generation` runs from. A command refuses to run from an uncommitted
tree. [Admission](admission.md) has the rules the printed
commands follow.

## Reproduction

Re-running the command line an admitted vector's `generator` records
reproduces the bytes for every command but `proof`. Every signature is ECDSA
over SHA-256 with the nonce derived per RFC 6979. `key` derives the private
scalar from `--seed`. `credential` derives the IssuerSignedItem salts from
`--seed`. `certificate` carries `--serial`. A seed or serial the command
generates is written into the recorded command line. The `proof` command's bytes
come from the prover's own randomness.

## key

Stages `<name>.pem`, a PKCS#8 PEM holding a P-256 private key. The private
scalar is SHA-256 of the seed reduced into [1, n-1].

| Flag | Effect |
| --- | --- |
| `--name` | Vector name, and the name of the staging directory. |
| `--role` | `iaca`, `document-signer`, or `device`, recorded as given. |
| `--seed` | Seed the private scalar is derived from, hex. 32 random bytes when absent. |

## certificate

Stages `<name>.pem`, a PEM X.509 certificate over the key vector `--key`
names.

| Flag | Effect |
| --- | --- |
| `--name` | Vector name, and the name of the staging directory. |
| `--key` | Key vector the certificate certifies. A public key alone suffices. A self-signed certificate needs the private key. |
| `--signed-by` | Certificate vector whose key signs this one, resolved through that vector's `key` reference. The certificate is self-signed under `--key` when absent. |
| `--subject` | Subject common name. |
| `--issuer` | Issuer common name. The signer certificate's subject common name when absent, and `--subject` on a self-signed certificate. |
| `--ca` | Builds a CA certificate, basicConstraints CA and keyUsage keyCertSign, admitted with role `iaca`. A leaf carries keyUsage digitalSignature and role `document-signer`. |
| `--valid-from`, `--valid-until` | Validity window, each an ISO 8601 date-time carrying a UTC offset. |
| `--serial` | Serial number to carry. A random serial number when absent. |

## credential

Stages `<name>.cbor`, IssuerSigned CBOR, `{nameSpaces, issuerAuth}`.

| Flag | Effect |
| --- | --- |
| `--name` | Vector name, and the name of the staging directory. |
| `--ds-certificate` | Certificate vector the `issuerAuth` x5chain carries. Its `key` reference resolves the key that signs the MSO. |
| `--device-key` | Key vector the MSO's `deviceKeyInfo` binds, the only key that can present the credential. |
| `--doctype` | Doctype the MSO carries. `eu.europa.ec.av.1` when absent. |
| `--claim` | Issuer-signed claim, as namespace, id, and the value as JSON. Repeatable. |
| `--valid-from` | MSO `signed` and `validFrom` timestamp, an ISO 8601 date-time carrying a UTC offset. |
| `--valid-until` | MSO `validUntil` timestamp, an ISO 8601 date-time carrying a UTC offset. |
| `--seed` | Seed the IssuerSignedItem salts are derived from, hex. 32 random bytes when absent. |

## presentation

Stages `presentation.json`, holding the DeviceResponse and the transcript as
hex. The `issuerAuth` and the MSO are carried through unchanged.

| Flag | Effect |
| --- | --- |
| `--name` | Vector name, and the name of the staging directory. |
| `--credential` | Credential vector to present. Its `device_key` reference resolves the key that signs the transcript. |
| `--transcript` | CBOR SessionTranscript the device signature is bound to, hex. |
| `--device-namespace` | Device-signed item, as namespace, id, and the value as JSON. Repeatable. The empty map is signed when none is given. |
| `--disclose` | Issuer-signed item of the credential to carry, as namespace and id. Repeatable. Every item the credential holds is carried when none is given. A pair the credential does not hold exits without staging. |

## proof

Stages `<name>.proof`.

| Flag | Effect |
| --- | --- |
| `--name` | Vector name, and the name of the staging directory. |
| `--presentation` | Presentation vector to prove over. It supplies the mdoc, the transcript, the issuer public key, and the namespace and CBOR value of every attribute. |
| `--circuit` | Circuit vector to prove with. |
| `--backend` | `google-cpp` or `isrg-rust`, the implementation that produces the proof bytes. |
| `--attr` | Attribute id to disclose. Repeatable, and the claims are proved in the order given. |
| `--timestamp` | Verification time to prove at, an ISO 8601 date-time carrying a UTC offset. |

## flip-bit

Stages `<name>.proof`, the source proof's bytes with one bit flipped. The
printed command admits the derived proof with the source proof's prover,
circuit, statement, and timestamp, and a comment naming the derivation.

| Flag | Effect |
| --- | --- |
| `--proof` | Proof vector to derive from. |
| `--name` | Vector name, and the name of the staging directory. The source name plus `-bit-flipped` when absent. |
| `--byte` | Index of the byte to flip a bit of. The middle byte when absent. |
| `--bit` | Bit of the byte to flip, 0 to 7. 0 when absent. |

## Example

This run builds a document-signer key, a device key, a self-signed
document-signer certificate, a credential, a presentation, and a proof over
that presentation. The circuit vector `google-v7-1attr` is in the collection
already. The `generate.py` commands run from `tools/generation`. The
`admit.py` commands run from `tools/admission`. Each `admit.py` command is the
one the `generate.py` command above it printed.

```
uv run generate.py key --name ds-vectors --role document-signer --seed 01
uv run admit.py key ../generation/staging/ds-vectors/ds-vectors.pem --generator 'generate.py key --name ds-vectors --role document-signer --seed 01' --ref 39aa5d8cb9d4dceb60558743bbf06d39117cdd43 --name ds-vectors --role document-signer
uv run generate.py key --name device-vectors-01 --role device --seed 02
uv run admit.py key ../generation/staging/device-vectors-01/device-vectors-01.pem --generator 'generate.py key --name device-vectors-01 --role device --seed 02' --ref 39aa5d8cb9d4dceb60558743bbf06d39117cdd43 --name device-vectors-01 --role device
uv run generate.py certificate --name ds-vectors-2026-2031 --key ds-vectors --subject pipe23-vectors-ds --valid-from 2026-01-01T00:00:00Z --valid-until 2031-01-01T00:00:00Z --serial 1
uv run admit.py certificate ../generation/staging/ds-vectors-2026-2031/ds-vectors-2026-2031.pem --generator 'generate.py certificate --name ds-vectors-2026-2031 --key ds-vectors --subject pipe23-vectors-ds --valid-from 2026-01-01T00:00:00Z --valid-until 2031-01-01T00:00:00Z --serial 1' --ref 39aa5d8cb9d4dceb60558743bbf06d39117cdd43 --name ds-vectors-2026-2031 --role document-signer --key ds-vectors
uv run generate.py credential --name av-over-18 --ds-certificate ds-vectors-2026-2031 --device-key device-vectors-01 --claim eu.europa.ec.av.1 age_over_18 true --valid-from 2026-01-01T00:00:00Z --valid-until 2027-01-01T00:00:00Z --seed 03
uv run admit.py credential ../generation/staging/av-over-18/av-over-18.cbor --generator 'generate.py credential --name av-over-18 --ds-certificate ds-vectors-2026-2031 --device-key device-vectors-01 --claim eu.europa.ec.av.1 age_over_18 true --valid-from 2026-01-01T00:00:00Z --valid-until 2027-01-01T00:00:00Z --seed 03' --ref 39aa5d8cb9d4dceb60558743bbf06d39117cdd43 --name av-over-18 --device-key device-vectors-01 --ds-certificate ds-vectors-2026-2031
uv run generate.py presentation --name av-over-18-20260826 --credential av-over-18 --transcript 83f6f68265646361706958200000000000000000000000000000000000000000000000000000000000000000
uv run admit.py presentation ../generation/staging/av-over-18-20260826/presentation.json --generator 'generate.py presentation --name av-over-18-20260826 --credential av-over-18 --transcript 83f6f68265646361706958200000000000000000000000000000000000000000000000000000000000000000' --ref 39aa5d8cb9d4dceb60558743bbf06d39117cdd43 --name av-over-18-20260826 --credential av-over-18
uv run generate.py proof --name google-cpp-av-over-18-20260826-v7-1attr --presentation av-over-18-20260826 --circuit google-v7-1attr --backend google-cpp --attr age_over_18 --timestamp 2026-08-26T00:00:00Z
uv run admit.py proof ../generation/staging/google-cpp-av-over-18-20260826-v7-1attr/google-cpp-av-over-18-20260826-v7-1attr.proof --generator 'generate.py proof --name google-cpp-av-over-18-20260826-v7-1attr --presentation av-over-18-20260826 --circuit google-v7-1attr --backend google-cpp --attr age_over_18 --timestamp 2026-08-26T00:00:00Z' --ref 39aa5d8cb9d4dceb60558743bbf06d39117cdd43 --name google-cpp-av-over-18-20260826-v7-1attr --prover google-cpp --circuit google-v7-1attr --presentation av-over-18-20260826 --attr age_over_18 --timestamp 2026-08-26T00:00:00+00:00
```
