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
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from longfellow_vectors import LongfellowVectors
from longfellow_vectors.mdoc import Key

ROOT = Path(__file__).resolve().parent.parent.parent.parent
VECTORS = ROOT / "vectors" / "mdoc"
STAGING = ROOT / "tools" / "generation" / "staging"
ADMISSION = ROOT / "tools" / "admission"
VECTOR_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
HEX = re.compile(r"([0-9a-fA-F]{2})+")
NAME_HELP = "vector name"


def vector_name(value: str) -> str:
    if not VECTOR_NAME.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a vector name; names match ^[a-z0-9][a-z0-9-]*$"
        )
    return value


def hex_string(value: str) -> str:
    if not HEX.fullmatch(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not an even-length hex string")
    return value.lower()


def iso_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"{value!r} is not an ISO 8601 date-time") from e
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError(f"{value!r} carries no UTC offset")
    return parsed


def rfc3339(value: datetime) -> str:
    return value.isoformat()


def collection() -> LongfellowVectors:
    return LongfellowVectors(root=VECTORS)


def namespaces(triples: list[list[str]]) -> dict[str, dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for namespace, identifier, value in triples:
        try:
            grouped.setdefault(namespace, {})[identifier] = json.loads(value)
        except json.JSONDecodeError as e:
            sys.exit(f"error: value for {identifier!r} is not JSON: {e}")
    return grouped


def private_key(vector: Key) -> ec.EllipticCurvePrivateKey:
    try:
        loaded = load_pem_private_key(vector.pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        sys.exit(f"error: key {vector.name!r} does not hold a private key")
    if not isinstance(loaded, ec.EllipticCurvePrivateKey):
        sys.exit(f"error: key {vector.name!r} does not hold an EC private key")
    return loaded


def public_key(vector: Key) -> ec.EllipticCurvePublicKey:
    try:
        loaded: object = load_pem_private_key(vector.pem, password=None).public_key()
    except (ValueError, TypeError, UnsupportedAlgorithm):
        try:
            loaded = load_pem_public_key(vector.pem)
        except (ValueError, UnsupportedAlgorithm):
            sys.exit(f"error: key {vector.name!r} does not hold a key")
    if not isinstance(loaded, ec.EllipticCurvePublicKey):
        sys.exit(f"error: key {vector.name!r} does not hold an EC key")
    return loaded


def missing(vector_type: str, name: str) -> NoReturn:
    sys.exit(f"error: {vector_type} {name!r} not in the collection; admit it first")


def stage(name: str) -> Path:
    directory = STAGING / name
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    print(f"wrote {os.path.relpath(path)}")
    return path


def generator_ref() -> str | None:
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


def committed_ref() -> str:
    ref = generator_ref()
    if ref is None:
        sys.exit("error: tools/generation has uncommitted changes; commit them first")
    return ref


def admit(vector_type: str, path: Path, name: str, command: str, *flags: str) -> list[str]:
    return [
        "uv",
        "run",
        "admit.py",
        vector_type,
        os.path.relpath(path, ADMISSION),
        "--generator",
        command,
        "--ref",
        committed_ref(),
        "--name",
        name,
        *flags,
    ]


def command_with(command: str, *flags: str) -> str:
    return shlex.join([*shlex.split(command), *flags])


def print_commands(commands: list[list[str]]) -> None:
    print("\nadmit from tools/admission:")
    for command in commands:
        print(" ".join(shlex.quote(word) for word in command))
