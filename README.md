# longfellow-vectors

longfellow-vectors is a collection of test vectors for Longfellow zero-knowledge proof
implementations (draft-google-cfrg-libzk). The vector types are keys, credentials,
presentations, circuits, certificates, and proofs. A vector is an example of its type, with
its metadata stored in a `.json` sidecar. Presentation vectors (proof inputs) are bundled
with their metadata in a `.json` file. Every vector carries provenance. The documentation
describes each type's fields. `languages/python/` is a Python package, `longfellow-vectors`
on PyPI, whose wheel embeds a snapshot of the collection.

[![CI](https://github.com/pipe23-org/longfellow-vectors/actions/workflows/ci.yml/badge.svg)](https://github.com/pipe23-org/longfellow-vectors/actions/workflows/ci.yml)
[![Docs](https://app.readthedocs.org/projects/longfellow-vectors/badge/?version=latest)](https://longfellow-vectors.readthedocs.io/en/latest/)
[![PyPI](https://img.shields.io/pypi/v/longfellow-vectors)](https://pypi.org/project/longfellow-vectors/)
[![Python](https://img.shields.io/pypi/pyversions/longfellow-vectors)](https://pypi.org/project/longfellow-vectors/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Installation

```
pip install longfellow-vectors
```

Requires Python 3.11 or later.

## Usage

```
>>> from longfellow_vectors import LongfellowVectors
>>> vectors = LongfellowVectors()
>>> vectors.check()
>>> sorted(circuit.name for circuit in vectors.mdoc.circuits())
['google-v6-1attr', 'google-v6-1attr-sha256-circuit-id-zeroed', 'google-v6-2attr', 'google-v6-3attr', 'google-v6-4attr', 'google-v7-1attr', 'google-v7-2attr', 'google-v7-3attr', 'google-v7-4attr']
>>> proof = vectors.mdoc.proof("google-cpp-mdl-mustermann-v7-1attr")
>>> proof.circuit.name, proof.circuit.version, proof.circuit.num_attributes
('google-v7-1attr', 7, 1)
>>> statement = proof.statement()
>>> statement.doctype
'org.iso.18013.5.1.mDL'
>>> [(claim.namespace, claim.id, claim.cbor_value.hex()) for claim in statement.claims]
[('org.iso.18013.5.1', 'issue_date', 'd903ec6a323032342d30332d3135')]
>>> statement.timestamp.isoformat()
'2024-10-01T09:00:00+00:00'
>>> proof.presentation.name, len(proof.presentation.mdoc)
('mdl-mustermann', 3173)
>>> proof.provenance.repo, proof.provenance.path
('github.com/abetterinternet/zk-cred-longfellow', 'test-vectors/mdoc_zk/v7_1attr_issue_date.proof')
```

`LongfellowVectors()` with no argument loads the packaged snapshot. `LongfellowVectors(root)`
loads a collection directory. `check()` returns `None` on a clean collection and raises
`CorpusError` listing every schema, hash, and reference finding.

## Documentation

Full documentation: https://longfellow-vectors.readthedocs.io/

## Development

```
cd languages/python
uv sync
uv run pytest --cov
uv run ruff check
uv run ruff format --check
uv run mypy
uv run interrogate src/longfellow_vectors
```

The docs build runs from the repository root:

```
uv run --project languages/python mkdocs build --strict
```

Vectors enter the collection through `tools/add_vector.py`, a separate uv project under
`tools/`. `uv run add_vector.py <mode> --help` in `tools/` lists each mode's flags; the
Admission page of the documentation holds the rules.

## Status

This project is pre-release and subject to change, including metadata schemas and corpus membership.

## License

Apache-2.0.
