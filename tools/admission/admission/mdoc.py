"""Readers for the DeviceResponse CBOR a presentation or credential carries."""

import sys
from typing import Any

import cbor2
from cryptography import x509


def _issuer_signed_elements(mdoc_bytes: bytes) -> dict[str, tuple[str, bytes]]:
    """Map attribute id to (namespace, elementValue CBOR) from the mdoc's issuerSigned."""
    response = cbor2.loads(mdoc_bytes)
    elements: dict[str, tuple[str, bytes]] = {}
    for namespace, items in response["documents"][0]["issuerSigned"]["nameSpaces"].items():
        for item in items:
            inner = cbor2.loads(item.value)
            identifier = inner["elementIdentifier"]
            if identifier in elements:
                sys.exit(f"error: attribute id {identifier!r} appears in multiple namespaces")
            elements[identifier] = (namespace, cbor2.dumps(inner["elementValue"]))
    return elements


def claims_from_ids(ids: list[str], mdoc_bytes: bytes) -> list[dict[str, Any]]:
    """Build claims for the given ids; namespace and value come from the credential."""
    elements = _issuer_signed_elements(mdoc_bytes)
    claims = []
    for claim_id in ids:
        if claim_id not in elements:
            sys.exit(f"error: attribute id {claim_id!r} not in the credential's issuerSigned")
        namespace, element_value = elements[claim_id]
        claims.append({"namespace": namespace, "id": claim_id, "cbor_value": element_value.hex()})
    return claims


def issuer_public_key(mdoc_bytes: bytes) -> tuple[str, str]:
    """Extract the issuer public key from the mdoc's IssuerAuth x5chain."""
    response = cbor2.loads(mdoc_bytes)
    issuer_auth = response["documents"][0]["issuerSigned"]["issuerAuth"]
    # COSE_Sign1: [protected, unprotected, payload, signature]; x5chain is header 33.
    chain = issuer_auth[1][33]
    cert_der = chain[0] if isinstance(chain, list) else chain
    nums = x509.load_der_x509_certificate(cert_der).public_key().public_numbers()
    return f"{nums.x:064x}", f"{nums.y:064x}"


def device_namespaces_hex(mdoc_bytes: bytes) -> str:
    response = cbor2.loads(mdoc_bytes)
    name_spaces = response["documents"][0]["deviceSigned"]["nameSpaces"]
    return name_spaces.value.hex()
