# generation

`generate.py` constructs vectors for the longfellow-vectors collection and stages them for
admission by `tools/admission/admit.py`. It generates the vectors pylongfellow and
zk-age-verifier need. It is untested beyond that. It is experimental and unstable.

## Usage

```
cd tools/generation
uv run generate.py <command> --help
```

One command per vector type: `key`, `certificate`, `credential`, `presentation`, and `proof`.
`flip-bit` derives a proof from an admitted proof. Each command reads the vectors it builds on
from the collection by name, writes under `staging/<name>/`, and prints the `admit.py` command
that admits the result:

```
$ uv run generate.py key --name device-vectors-01 --role device --seed 02
wrote staging/device-vectors-01/device-vectors-01.pem

admit from tools/admission:
uv run admit.py key ../generation/staging/device-vectors-01/device-vectors-01.pem --generator 'generate.py key --name device-vectors-01 --role device --seed 02' --ref f4e345b2b2915f8315af0debd11fe93a93677139 --name device-vectors-01 --role device
```

Re-running the command line a vector's `generator` records reproduces its bytes for every
command but `proof`. The Generation page of the documentation lists every command's flags.

## Documentation

Full documentation: https://longfellow-vectors.readthedocs.io/

## Development

```
cd tools/generation
uv sync
uv run pytest
uv run ruff check
uv run ruff format --check
```

## Status

You should not rely on this code.

- `--claim` and `--device-namespace` values are JSON. A tagged CBOR value (tag 1004
  `full-date`, tag 0 `tdate`), a byte string, and a non-text map key cannot be expressed. A
  JSON number with a fraction encodes as a CBOR float. The claim shapes exercised are a boolean
  (`age_over_18`) and a text string (`nym`).
- `credential` writes one `IssuerSigned` with digest IDs sequential from 0 within each
  namespace, 16-byte salts derived from `--seed`, `signed` equal to `--valid-from`,
  `digestAlgorithm` SHA-256, and no `status` or `keyAuthorizations`.
- `presentation` writes a `DeviceResponse` holding one document, with `status` 0.
  `--transcript` is opaque hex. Nothing builds a SessionTranscript or a DC-API handover.
- `certificate` names subject and issuer by common name only and emits keyUsage and, with
  `--ca`, basicConstraints. No subject key identifier, authority key identifier, subject
  alternative name, CRL distribution point, or other ISO 18013-5 Annex B extension is emitted.
  `--key` has to name a key vector holding a private key.
- `key` derives P-256 keys only. Every signature is ES256.
- `proof` bytes are not reproducible from the recorded command line. The attribute count has
  to equal the circuit's `num_attributes`. google-cpp neither proves nor verifies over a
  non-empty device namespace map, and the prover fails with
  `MDOC_PROVER_DEVICE_SIGNATURE_FAILURE`. isrg-rust does both.
- No command constructs or derives a circuit, and `admit.py circuit` takes `--repo` only.
- Circuit versions 6 and 7 only. The pin is pylongfellow 0.5.2. `proof` loads circuits through
  `CircuitSpec` and `google_cpp.find_zk_spec`, which pylongfellow 0.6 removes. The pin bump
  rewrites `generation/prove.py` and `tests/test_prove.py`.
- The fixtures under `tests/data` do not record the seeds they were built from.

## License

Apache-2.0.
