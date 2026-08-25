"""Top-level package for longfellow-vectors."""

from importlib.metadata import PackageNotFoundError, version

from .mdoc import CorpusError, LongfellowVectors, PublicKey, Statement

try:
    __version__ = version("longfellow-vectors")
except PackageNotFoundError:  # pragma: no cover - not installed (editable source tree)
    __version__ = "0.0.0"

__all__ = ["CorpusError", "LongfellowVectors", "PublicKey", "Statement", "__version__"]
