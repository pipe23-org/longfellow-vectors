"""Collection paths, the staging tree, and the admission commands the modes print."""

import argparse
import os.path
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from longfellow_vectors import LongfellowVectors

ROOT = Path(__file__).resolve().parent.parent.parent.parent
VECTORS = ROOT / "vectors" / "mdoc"
STAGING = ROOT / "tools" / "generation" / "staging"
ADMISSION = ROOT / "tools" / "admission"
VECTOR_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
NAME_HELP = (
    "vector name, matching ^[a-z0-9][a-z0-9-]*$: lowercase words joined by hyphens, "
    "per docs/naming.md; also the name of the staging directory"
)


def vector_name(value: str) -> str:
    """Argparse type for --name: the vector naming convention's lowercase-hyphen form."""
    if not VECTOR_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a vector name; names match ^[a-z0-9][a-z0-9-]*$"
        )
    return value


def iso_datetime(value: str) -> datetime:
    """Argparse type for a date-time flag: an ISO 8601 string carrying a UTC offset."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"{value!r} is not an ISO 8601 date-time") from e
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError(f"{value!r} carries no UTC offset")
    return parsed


def rfc3339(value: datetime) -> str:
    """Render a timezone-aware datetime in the form the vector schemas take."""
    return value.isoformat()


def collection() -> LongfellowVectors:
    """The collection in this checkout, which the modes read named vectors from."""
    return LongfellowVectors(root=VECTORS)


def missing(vector_type: str, name: str) -> NoReturn:
    """Exit naming a vector the collection does not hold."""
    sys.exit(f"error: {vector_type} {name!r} not in the collection; admit it first")


def stage(name: str) -> Path:
    """Create and return the staging directory a mode writes its files into."""
    directory = STAGING / name
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write(path: Path, data: bytes) -> Path:
    """Write a staged file and print where it went.

    Args:
        path: Staged file to write.
        data: Bytes to write.

    Returns:
        The path written.
    """
    path.write_bytes(data)
    print(f"wrote {os.path.relpath(path)}")
    return path


def generator_ref() -> str | None:
    """The commit tools/generation runs from, or None when the directory has uncommitted changes."""
    here = Path(__file__).resolve().parent.parent
    status = subprocess.run(
        ["git", "-C", str(here), "status", "--porcelain", "."], capture_output=True, text=True
    )
    if status.returncode != 0 or status.stdout.strip():
        return None
    head = subprocess.run(
        ["git", "-C", str(here), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    )
    return head.stdout.strip()


def admit(mode: str, path: Path, name: str, command: str, *flags: str) -> list[str]:
    """The add_vector.py command that admits a staged file, as an argument list.

    Args:
        mode: add_vector.py mode, e.g. `import-proof`.
        path: Staged file to admit.
        name: Vector name to admit it under.
        command: The generate_vectors.py command that produced the file, as run;
            recorded as the vector's `generator`.
        flags: Further flags and values, appended in the order given.

    Returns:
        The command's words, with the staged path written relative to
        tools/admission, the directory the command runs from, and `--ref`
        present only when tools/generation is committed clean.
    """
    ref = generator_ref()
    return [
        "uv",
        "run",
        "add_vector.py",
        mode,
        os.path.relpath(path, ADMISSION),
        "--generator",
        command,
        *(["--ref", ref] if ref is not None else []),
        "--name",
        name,
        *flags,
    ]


def print_commands(commands: list[list[str]]) -> None:
    """Print the admission commands for a mode's staged files, one per line."""
    if generator_ref() is None:
        print("\ntools/generation has uncommitted changes; --ref is omitted")
    print("\nadmit from tools/admission:")
    for command in commands:
        print(" ".join(shlex.quote(word) for word in command))
