# longfellow-vectors

longfellow-vectors is a collection of test vectors for Longfellow zero-knowledge proof
implementations (draft-google-cfrg-libzk). 

The repository contains keys, credentials, presentations, circuits, certificates, and proofs. 

Each vector has accompanying JSON metadata. Presentation vectors (proof inputs) are bundled
with their metadata. 

`languages/python/` is a Python package, `longfellow-vectors` on PyPI, which includes a snapshot of the collection.

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
