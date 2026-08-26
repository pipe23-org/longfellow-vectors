"""key: derive a P-256 private key from a seed and stage its PEM."""

import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from . import staging

DESCRIPTION = """\
Derive a P-256 private key from a seed and stage <name>.pem, a PKCS#8 PEM,
under tools/generation/staging/<name>/.
The private scalar is SHA-256 of the seed reduced into [1, n-1], so one seed
always gives one key.
The printed command admits the key with its role, and carries the seed whether
it was given or generated.
"""

# Order of the P-256 group, SEC 2 secp256r1 n.
_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _scalar(seed: bytes) -> int:
    """The private scalar a seed fixes: SHA-256 of the seed reduced into [1, n-1]."""
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % (_ORDER - 1) + 1


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
