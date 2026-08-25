"""Collection paths, provenance, and the validated write path every mode uses."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent.parent
CIRCUITS = ROOT / "vectors" / "mdoc" / "circuits"
PRESENTATIONS = ROOT / "vectors" / "mdoc" / "presentations"
PROOFS = ROOT / "vectors" / "mdoc" / "proofs"
KEYS = ROOT / "vectors" / "mdoc" / "keys"
CREDENTIALS = ROOT / "vectors" / "mdoc" / "credentials"
CERTIFICATES = ROOT / "vectors" / "mdoc" / "certificates"
SCHEMAS = ROOT / "vectors" / "schemas"
SYSTEM = "longfellow-libzk-v1"
GIT = shutil.which("git") or "git"
RECORD_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
NAME_HELP = (
    "vector name, matching ^[a-z0-9][a-z0-9-]*$: lowercase words joined by hyphens, "
    "per docs/naming.md"
)
REPO_HELP = (
    "source repository as host/owner/name; provenance records it with the commit and the "
    "in-repo path read from the source file's own checkout"
)
GENERATOR_HELP = (
    "what produced staged constructed bytes, as a tool and mode; provenance records type "
    "constructed with it in place of the repository, commit, and path"
)
COMMENT_HELP = "free-text comment to record on the sidecar"


def record_name(value: str) -> str:
    """Argparse type for --name: the vector naming convention's lowercase-hyphen form."""
    if not RECORD_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a vector name; names match ^[a-z0-9][a-z0-9-]*$"
        )
    return value


def _git(source_dir: Path, *args: str) -> str:
    result = subprocess.run(
        [GIT, "-C", str(source_dir), *args], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def provenance(source: Path, repo: str, index: str | None = None) -> dict[str, Any]:
    """Repository provenance for a source file inside a git checkout."""
    toplevel = Path(_git(source.parent, "rev-parse", "--show-toplevel"))
    record: dict[str, Any] = {
        "type": "repository",
        "repo": repo,
        "ref": _git(source.parent, "rev-parse", "HEAD"),
        "path": str(source.resolve().relative_to(toplevel)),
        "captured": date.today().isoformat(),
    }
    if index is not None:
        record["index"] = index
    return record


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _registry() -> Registry:
    return Registry().with_resources(
        (f.name, Resource.from_contents(json.loads(f.read_text()), DRAFT202012))
        for f in SCHEMAS.glob("*.schema.json")
    )


def _validate(sidecar: dict[str, Any]) -> None:
    schema_path = SCHEMAS / sidecar["schema"]
    validator = Draft202012Validator(
        json.loads(schema_path.read_text()),
        registry=_registry(),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    errors = sorted(validator.iter_errors(sidecar), key=lambda e: list(e.absolute_path))
    if errors:
        for error in errors:
            print(f"schema: {'/'.join(str(p) for p in error.absolute_path)}: {error.message}")
        sys.exit("error: sidecar rejected by schema; nothing written")


def write_record(blob_path: Path, blob: bytes, sidecar: dict[str, Any]) -> None:
    _validate(sidecar)
    blob_path.parent.mkdir(parents=True, exist_ok=True)
    blob_path.write_bytes(blob)
    sidecar_path = blob_path.with_suffix(".json")
    sidecar_path.write_text(json.dumps(sidecar, indent=2) + "\n")
    print(f"wrote {blob_path.relative_to(ROOT)} + {sidecar_path.name}")


def write_presentation(name: str, sidecar: dict[str, Any]) -> None:
    _validate(sidecar)
    PRESENTATIONS.mkdir(parents=True, exist_ok=True)
    sidecar_path = PRESENTATIONS / f"{name}.json"
    sidecar_path.write_text(json.dumps(sidecar, indent=2) + "\n")
    print(f"wrote {sidecar_path.relative_to(ROOT)}")


def load_presentation(name: str) -> dict[str, Any]:
    sidecar_path = PRESENTATIONS / f"{name}.json"
    if not sidecar_path.is_file():
        sys.exit(f"error: presentation {name!r} not in the corpus; import it first")
    doc: dict[str, Any] = json.loads(sidecar_path.read_text())
    return doc


def require_circuit(name: str) -> None:
    if not (CIRCUITS / f"{name}.json").is_file():
        sys.exit(f"error: circuit {name!r} not in the corpus; import it first")


def require_key(name: str) -> None:
    if not (KEYS / f"{name}.json").is_file():
        sys.exit(f"error: key {name!r} not in the corpus; import it first")


def require_credential(name: str) -> None:
    if not (CREDENTIALS / f"{name}.json").is_file():
        sys.exit(f"error: credential {name!r} not in the corpus; import it first")


def require_certificate(name: str) -> None:
    if not (CERTIFICATES / f"{name}.json").is_file():
        sys.exit(f"error: certificate {name!r} not in the corpus; import it first")
