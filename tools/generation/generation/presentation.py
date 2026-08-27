import json
import sys
from typing import Any

import cbor2

from . import mdoc, staging

DESCRIPTION = "Present a credential over a transcript and stage presentation.json."


def _issuer_signed(credential_name: str, blob: bytes) -> dict[Any, Any]:
    """The decoded IssuerSigned a credential vector's bytes hold."""
    try:
        issuer_signed = cbor2.loads(blob)
    except Exception:
        sys.exit(f"error: credential {credential_name!r} is not CBOR")
    if (
        not isinstance(issuer_signed, dict)
        or not isinstance(issuer_signed.get("nameSpaces"), dict)
        or not isinstance(issuer_signed.get("issuerAuth"), list)
    ):
        sys.exit(f"error: credential {credential_name!r} does not hold IssuerSigned")
    return issuer_signed


def _disclosed(
    namespaces: dict[Any, Any], disclose: list[list[str]], credential_name: str
) -> dict[Any, Any]:
    """The issuer-signed items the response carries, keyed by namespace."""
    if not disclose:
        return namespaces
    requested = {(namespace, identifier) for namespace, identifier in disclose}
    selected: dict[Any, Any] = {}
    for namespace, items in namespaces.items():
        for item in items:
            identifier = cbor2.loads(item.value)["elementIdentifier"]
            if (namespace, identifier) in requested:
                selected.setdefault(namespace, []).append(item)
                requested.discard((namespace, identifier))
    if requested:
        namespace, identifier = sorted(requested)[0]
        sys.exit(
            f"error: credential {credential_name!r} holds no item {identifier!r} "
            f"in namespace {namespace!r}"
        )
    return selected


def presentation(
    command: str,
    name: str,
    credential_name: str,
    transcript: str,
    device_namespaces: list[list[str]],
    disclose: list[list[str]],
) -> None:
    vectors = staging.collection()
    try:
        credential = vectors.mdoc.credential(credential_name)
    except KeyError:
        staging.missing("credential", credential_name)
    if credential.device_key is None:
        sys.exit(f"error: credential {credential_name!r} records no device key vector")
    issuer_signed = _issuer_signed(credential_name, credential.bytes)
    doctype = cbor2.loads(cbor2.loads(issuer_signed["issuerAuth"][2]).value)["docType"]
    issuer_signed["nameSpaces"] = _disclosed(issuer_signed["nameSpaces"], disclose, credential_name)
    device_items = cbor2.CBORTag(24, cbor2.dumps(staging.namespaces(device_namespaces)))
    transcript_bytes = bytes.fromhex(transcript)
    response = mdoc.create_device_response(
        doctype,
        issuer_signed,
        device_items,
        mdoc.sign_device_authentication(
            staging.private_key(credential.device_key), transcript_bytes, doctype, device_items
        ),
    )
    mdoc.verify_device_authentication(response, transcript_bytes)
    document = {"mdoc": response.hex(), "transcript": transcript}
    path = staging.write(
        staging.stage(name) / "presentation.json", (json.dumps(document, indent=2) + "\n").encode()
    )
    staging.print_commands(
        [staging.admit("presentation", path, name, command, "--credential", credential_name)]
    )
