import sys

from longfellow_vectors.mdoc import Proof

from . import staging

DESCRIPTION = "Flip one bit of a proof and stage <name>.proof."


def _statement_flags(source: Proof) -> list[str]:
    flags = []
    if source.doctype is not None:
        flags += ["--doctype", source.doctype]
    if source.transcript is not None:
        flags += ["--transcript", source.transcript.hex()]
    if source.issuer_public_key is not None:
        flags += [
            "--issuer-public-key-x",
            f"{source.issuer_public_key.x:064x}",
            "--issuer-public-key-y",
            f"{source.issuer_public_key.y:064x}",
        ]
    for claim in source.claims or ():
        flags += ["--claim", claim.namespace, claim.id, claim.cbor_value.hex()]
    if source.device_namespaces is not None:
        flags += ["--device-namespaces", source.device_namespaces.hex()]
    return flags


def flip_bit(
    command: str, proof_name: str, name: str | None, byte_index: int | None, bit: int
) -> None:
    vectors = staging.collection()
    try:
        source = vectors.mdoc.proof(proof_name)
    except KeyError:
        staging.missing("proof", proof_name)
    data = bytearray(source.bytes)
    if byte_index is None:
        byte_index = len(data) // 2
    if not 0 <= byte_index < len(data):
        sys.exit(f"error: byte {byte_index} is outside the {len(data)}-byte proof {proof_name!r}")
    data[byte_index] ^= 1 << bit
    name = name if name is not None else f"{proof_name}-bit-flipped"
    path = staging.write(staging.stage(name) / f"{name}.proof", bytes(data))
    flags = []
    if source.prover is not None:
        flags += ["--prover", source.prover]
    if source.circuit is not None:
        flags += ["--circuit", source.circuit.name]
    if source.presentation is not None:
        flags += ["--presentation", source.presentation.name]
        for claim in source.claims or ():
            flags += ["--attr", claim.id]
    else:
        flags += _statement_flags(source)
    if source.timestamp is not None:
        flags += ["--timestamp", staging.rfc3339(source.timestamp)]
    flags += ["--comment", f"{proof_name} with bit {bit} of byte {byte_index} flipped"]
    staging.print_commands([staging.admit("proof", path, name, command, *flags)])
