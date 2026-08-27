import argparse
import sys
from pathlib import Path
from typing import Any

from . import mdoc, records

DESCRIPTION = "Admit a proof."


def statement_from_flags(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> dict[str, Any] | None:
    required = {
        "doctype": args.doctype,
        "transcript": args.transcript,
        "issuer_public_key_x": args.issuer_public_key_x,
        "issuer_public_key_y": args.issuer_public_key_y,
    }
    if (
        all(value is None for value in required.values())
        and not args.claims
        and args.device_namespaces is None
    ):
        return None
    if args.presentation_name is not None:
        parser.error("the statement flags and --presentation are mutually exclusive")
    if args.attr_ids:
        parser.error("--attr requires --presentation; the statement flags take --claim")
    missing = [f"--{key.replace('_', '-')}" for key, value in required.items() if value is None]
    if not args.claims:
        missing.append("--claim")
    if missing:
        parser.error(f"the statement flags are required together; missing {', '.join(missing)}")
    statement: dict[str, Any] = {
        "doctype": args.doctype,
        "claims": [
            {"namespace": namespace, "id": claim_id, "cbor_value": cbor_hex.lower()}
            for namespace, claim_id, cbor_hex in args.claims
        ],
        "transcript": args.transcript.lower(),
        "issuer_public_key_x": args.issuer_public_key_x.lower(),
        "issuer_public_key_y": args.issuer_public_key_y.lower(),
    }
    if args.device_namespaces is not None:
        statement["device_namespaces"] = args.device_namespaces.lower()
    return statement


def import_proof(
    proof_path: str,
    repo: str | None,
    generator: str | None,
    ref: str | None,
    name: str,
    presentation_name: str | None,
    prover: str | None,
    circuit: str | None,
    timestamp: str | None,
    attr_ids: list[str],
    statement: dict[str, Any] | None,
    comment: str | None,
) -> None:
    source = Path(proof_path)
    proof = source.read_bytes()
    if presentation_name is None and attr_ids:
        sys.exit("error: --attr requires --presentation; claims derive from the presentation")
    if circuit is not None:
        records.require_circuit(circuit)
    if repo is not None:
        provenance: dict[str, Any] = records.provenance(source, repo)
    else:
        provenance = records.constructed(generator, ref)
    sidecar: dict[str, Any] = {"schema": "mdoc-proofs-v1.schema.json"}
    if prover is not None:
        sidecar["prover"] = prover
    if circuit is not None:
        sidecar["circuit"] = circuit
    sidecar["sha256"] = records.sha256(proof)
    if presentation_name is not None:
        if not attr_ids:
            sys.exit("error: at least one --attr is required")
        presentation_doc = records.load_presentation(presentation_name)
        mdoc_bytes = bytes.fromhex(presentation_doc["mdoc"])
        if "doctype" in presentation_doc:
            sidecar["doctype"] = presentation_doc["doctype"]
        sidecar["claims"] = mdoc.claims_from_ids(attr_ids, mdoc_bytes)
        if "transcript" in presentation_doc:
            sidecar["transcript"] = presentation_doc["transcript"]
        if "issuer_public_key_x" in presentation_doc:
            sidecar["issuer_public_key_x"] = presentation_doc["issuer_public_key_x"]
        if "issuer_public_key_y" in presentation_doc:
            sidecar["issuer_public_key_y"] = presentation_doc["issuer_public_key_y"]
        if "device_namespaces" in presentation_doc:
            sidecar["device_namespaces"] = presentation_doc["device_namespaces"]
        sidecar["presentation"] = presentation_name
    elif statement is not None:
        sidecar["doctype"] = statement["doctype"]
        sidecar["claims"] = statement["claims"]
        sidecar["transcript"] = statement["transcript"]
        sidecar["issuer_public_key_x"] = statement["issuer_public_key_x"]
        sidecar["issuer_public_key_y"] = statement["issuer_public_key_y"]
        if "device_namespaces" in statement:
            sidecar["device_namespaces"] = statement["device_namespaces"]
    if timestamp is not None:
        sidecar["timestamp"] = timestamp
    sidecar["provenance"] = provenance
    if comment is not None:
        sidecar["comment"] = comment
    records.write_record(records.PROOFS / f"{name}.proof", proof, sidecar)
