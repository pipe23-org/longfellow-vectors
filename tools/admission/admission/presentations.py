import json
import sys
from pathlib import Path
from typing import Any

import cbor2

from . import mdoc, records

DESCRIPTION = "Admit a presentation under vectors/mdoc/presentations/."


def _presentation_sidecar(
    mdoc_hex: str, transcript_hex: str, provenance: dict[str, Any]
) -> dict[str, Any]:
    """Build a presentation sidecar from mdoc and transcript hex."""
    sidecar: dict[str, Any] = {
        "schema": "mdoc-presentations-v1.schema.json",
        "mdoc": mdoc_hex,
        "transcript": transcript_hex,
        "provenance": provenance,
    }
    mdoc_bytes = bytes.fromhex(mdoc_hex)
    try:
        response = cbor2.loads(mdoc_bytes)
    except Exception:
        print("mdoc does not parse; doctype, issuer key, and device namespaces are not recorded")
        return sidecar
    try:
        sidecar["doctype"] = response["documents"][0]["docType"]
    except Exception:
        print("doctype does not extract; doctype is not recorded")
    try:
        pk_x, pk_y = mdoc.issuer_public_key(mdoc_bytes)
        sidecar["issuer_public_key_x"] = pk_x
        sidecar["issuer_public_key_y"] = pk_y
    except Exception:
        print("issuer public key does not extract; issuer_public_key_x/_y are not recorded")
    try:
        sidecar["device_namespaces"] = mdoc.device_namespaces_hex(mdoc_bytes)
    except Exception:
        print("device namespaces do not extract; device_namespaces is not recorded")
    return sidecar


def _verify_credential(mdoc_hex: str, credential_name: str) -> None:
    """Check that the response presents the named credential, and exit when it does not."""
    try:
        credential = cbor2.loads((records.CREDENTIALS / f"{credential_name}.cbor").read_bytes())
        issuer_signed = cbor2.loads(bytes.fromhex(mdoc_hex))["documents"][0]["issuerSigned"]
        held = {
            (namespace, item.value)
            for namespace, items in credential["nameSpaces"].items()
            for item in items
        }
        presented = {
            (namespace, item.value)
            for namespace, items in issuer_signed["nameSpaces"].items()
            for item in items
        }
    except Exception:
        sys.exit(
            f"error: the response or credential {credential_name!r} does not parse; "
            "cannot verify --credential"
        )
    if issuer_signed["issuerAuth"] != credential["issuerAuth"]:
        sys.exit(f"error: the presented issuerAuth does not equal credential {credential_name!r}'s")
    for namespace, item in sorted(presented - held):
        identifier = cbor2.loads(item)["elementIdentifier"]
        sys.exit(
            f"error: presented item {identifier!r} in namespace {namespace!r} is not one of "
            f"credential {credential_name!r}'s"
        )


def import_presentation(
    vector_path: str,
    repo: str | None,
    generator: str | None,
    ref: str | None,
    name: str,
    credential_name: str | None,
    comment: str | None,
) -> None:
    source = Path(vector_path)
    vector = json.loads(source.read_text())
    if repo is not None:
        provenance: dict[str, Any] = records.provenance(source, repo)
    else:
        provenance = records.constructed(generator, ref)
    sidecar = _presentation_sidecar(vector["mdoc"], vector["transcript"], provenance)
    if credential_name is not None:
        records.require_credential(credential_name)
        _verify_credential(vector["mdoc"], credential_name)
        sidecar["credential"] = credential_name
    if comment is not None:
        sidecar["comment"] = comment
    records.write_presentation(name, sidecar)
