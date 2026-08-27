import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from . import staging

DESCRIPTION = "Derive a P-256 key from a seed and stage <name>.pem."

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _scalar(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % (_P256_ORDER - 1) + 1


def key(command: str, name: str, role: str, seed: str | None) -> None:
    if seed is None:
        seed = secrets.token_hex(32)
        command = staging.command_with(command, "--seed", seed)
    private = ec.derive_private_key(_scalar(bytes.fromhex(seed)), ec.SECP256R1())
    path = staging.write(
        staging.stage(name) / f"{name}.pem",
        private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    staging.print_commands([staging.admit("key", path, name, command, "--role", role)])
