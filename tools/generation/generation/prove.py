import sys
from datetime import datetime

from longfellow_vectors.mdoc import Circuit, Presentation
from pylongfellow import Pylongfellow
from pylongfellow.backends import BackendUnavailableError, google_cpp
from pylongfellow.mdoc import CircuitSpec, Error, PublicKey, RequestedAttribute

from . import staging

DESCRIPTION = "Generate a proof."


def _claims(presentation: Presentation, attr_ids: list[str]) -> list[RequestedAttribute]:
    by_id = {claim.id: claim for claim in presentation.claims()}
    selected = []
    for attr_id in attr_ids:
        claim = by_id.get(attr_id)
        if claim is None:
            sys.exit(
                f"error: attribute id {attr_id!r} is not in presentation {presentation.name!r}"
            )
        selected.append(RequestedAttribute(claim.namespace, claim.id, claim.cbor_value))
    return selected


def _spec(backend: str, circuit: Circuit) -> CircuitSpec:
    if backend == "google-cpp":
        spec = google_cpp.find_zk_spec(circuit.system, google_cpp.circuit_id(circuit.bytes))
        if spec is None:
            sys.exit(f"error: the linked library has no spec for circuit {circuit.name!r}")
        return spec
    return CircuitSpec("", "0" * 64, circuit.num_attributes, circuit.version, 0, 0)


def prove(
    command: str,
    name: str,
    presentation_name: str,
    circuit_name: str,
    backend: str,
    attr_ids: list[str],
    timestamp: datetime,
) -> None:
    vectors = staging.collection()
    try:
        presentation = vectors.mdoc.presentation(presentation_name)
    except KeyError:
        staging.missing("presentation", presentation_name)
    try:
        circuit = vectors.mdoc.circuit(circuit_name)
    except KeyError:
        staging.missing("circuit", circuit_name)
    if presentation.transcript is None:
        sys.exit(f"error: presentation {presentation_name!r} records no transcript")
    if presentation.issuer_public_key is None:
        sys.exit(f"error: presentation {presentation_name!r} records no issuer public key")
    if len(attr_ids) != circuit.num_attributes:
        sys.exit(
            f"error: {len(attr_ids)} attributes given, and circuit {circuit_name!r} proves over "
            f"{circuit.num_attributes}"
        )
    claims = _claims(presentation, attr_ids)
    try:
        longfellow = Pylongfellow(backend=backend)
    except BackendUnavailableError as e:
        sys.exit(f"error: backend {backend!r} is not available: {e}")
    try:
        longfellow.load_circuit(_spec(backend, circuit), circuit.bytes)
        proof = longfellow.prove(
            presentation.mdoc,
            PublicKey(presentation.issuer_public_key.x, presentation.issuer_public_key.y),
            presentation.transcript,
            claims,
            timestamp,
        )
    except (Error, ValueError) as e:
        sys.exit(f"error: {backend} did not prove: {e}")
    path = staging.write(staging.stage(name) / f"{name}.proof", proof)
    flags = ["--prover", backend, "--circuit", circuit_name, "--presentation", presentation_name]
    for attr_id in attr_ids:
        flags += ["--attr", attr_id]
    flags += ["--timestamp", staging.rfc3339(timestamp)]
    staging.print_commands([staging.admit("proof", path, name, command, *flags)])
