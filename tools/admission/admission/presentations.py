"""presentation: admit a presentation as a sidecar with no blob."""

import json
from pathlib import Path
from typing import Any

import cbor2

from . import mdoc, records

DESCRIPTION = """\
Admit a presentation as a vector under vectors/mdoc/presentations/, which
carries no blob file.
The source is a JSON file with an mdoc field and a transcript field, each
holding hex.
The vector derives doctype, issuer_public_key_x, issuer_public_key_y, and
device_namespaces from the mdoc bytes.
docs/admission.md holds the rules that span the commands.
"""


def _presentation_sidecar(
    mdoc_hex: str, transcript_hex: str, provenance: dict[str, Any]
) -> dict[str, Any]:
    """Build a presentation sidecar from mdoc and transcript hex.

    Derived fields are omitted with a printed note when the mdoc does not parse.
    """
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
        sidecar["credential"] = credential_name
    if comment is not None:
        sidecar["comment"] = comment
    records.write_presentation(name, sidecar)
