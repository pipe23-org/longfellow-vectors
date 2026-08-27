"""Argparse types, collection lookups, the staging tree, and the admission commands."""

import argparse
import json
import os.path
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from longfellow_vectors import LongfellowVectors
from longfellow_vectors.mdoc import Key

ROOT = Path(__file__).resolve().parent.parent.parent.parent
VECTORS = ROOT / "vectors" / "mdoc"
STAGING = ROOT / "tools" / "generation" / "staging"
ADMISSION = ROOT / "tools" / "admission"
VECTOR_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
HEX = re.compile(r"([0-9a-fA-F]{2})+")
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


def hex_string(value: str) -> str:
    """Argparse type for a hex flag: an even, positive number of hex digits, lowercased."""
    if not HEX.fullmatch(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not an even-length hex string")
    return value.lower()


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
    """The collection in this checkout, which the commands read named vectors from."""
    return LongfellowVectors(root=VECTORS)


def namespaces(triples: list[list[str]]) -> dict[str, dict[str, object]]:
    """Group namespace, id, and JSON value triples into the nested map the builder takes.

    Args:
        triples: Repeated `--claim` or `--device-namespace` values.

    Returns:
        Namespace to element identifier to decoded value, in the order given.
    """
    grouped: dict[str, dict[str, object]] = {}
    for namespace, identifier, value in triples:
        try:
            grouped.setdefault(namespace, {})[identifier] = json.loads(value)
        except json.JSONDecodeError as e:
            sys.exit(f"error: value for {identifier!r} is not JSON: {e}")
    return grouped


def private_key(vector: Key) -> ec.EllipticCurvePrivateKey:
    """The EC private key a key vector's PEM holds.

    Args:
        vector: Key vector to read.

    Returns:
        The private key the PEM encodes.
    """
    try:
        loaded = load_pem_private_key(vector.pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        sys.exit(f"error: key {vector.name!r} does not hold a private key")
    if not isinstance(loaded, ec.EllipticCurvePrivateKey):
        sys.exit(f"error: key {vector.name!r} does not hold an EC private key")
    return loaded


def missing(vector_type: str, name: str) -> NoReturn:
    """Exit naming a vector the collection does not hold."""
    sys.exit(f"error: {vector_type} {name!r} not in the collection; admit it first")


def stage(name: str) -> Path:
    """Create and return the staging directory a command writes its files into."""
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


def admit(vector_type: str, path: Path, name: str, command: str, *flags: str) -> list[str]:
    """The admit.py command that admits a staged file, as an argument list.

    Args:
        vector_type: admit.py command, e.g. `proof`.
        path: Staged file to admit.
        name: Vector name to admit it under.
        command: The generate.py command that produced the file, as run;
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
        "admit.py",
        vector_type,
        os.path.relpath(path, ADMISSION),
        "--generator",
        command,
        *(["--ref", ref] if ref is not None else []),
        "--name",
        name,
        *flags,
    ]


def command_with(command: str, *flags: str) -> str:
    """The generate.py command line with values it generated appended as flags.

    Args:
        command: The command line as run.
        flags: Flag and value words to append, in the order given.

    Returns:
        The effective command line, which `--generator` records so a re-run
        reproduces the bytes.
    """
    return shlex.join([*shlex.split(command), *flags])


def print_commands(commands: list[list[str]]) -> None:
    """Print the admission commands for one command's staged files, one per line."""
    if generator_ref() is None:
        print("\ntools/generation has uncommitted changes; --ref is omitted")
    print("\nadmit from tools/admission:")
    for command in commands:
        print(" ".join(shlex.quote(word) for word in command))
