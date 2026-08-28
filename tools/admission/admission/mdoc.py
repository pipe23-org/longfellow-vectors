import sys
from typing import Any

import cbor2
from cryptography import x509

X5CHAIN = 33


def _issuer_signed_elements(mdoc_bytes: bytes) -> dict[tuple[str, str], bytes]:
    response = cbor2.loads(mdoc_bytes)
    elements: dict[tuple[str, str], bytes] = {}
    for namespace, items in response["documents"][0]["issuerSigned"]["nameSpaces"].items():
        for item in items:
            inner = cbor2.loads(item.value)
            elements[namespace, inner["elementIdentifier"]] = cbor2.dumps(inner["elementValue"])
    return elements


def claims_from_ids(ids: list[list[str]], mdoc_bytes: bytes) -> list[dict[str, Any]]:
    elements = _issuer_signed_elements(mdoc_bytes)
    claims = []
    for namespace, claim_id in ids:
        if (namespace, claim_id) not in elements:
            sys.exit(
                f"error: attribute {namespace}/{claim_id} not in the credential's issuerSigned"
            )
        element_value = elements[namespace, claim_id]
        claims.append({"namespace": namespace, "id": claim_id, "cbor_value": element_value.hex()})
    return claims


def issuer_public_key(mdoc_bytes: bytes) -> tuple[str, str]:
    response = cbor2.loads(mdoc_bytes)
    issuer_auth = response["documents"][0]["issuerSigned"]["issuerAuth"]
    chain = issuer_auth[1][X5CHAIN]
    cert_der = chain[0] if isinstance(chain, list) else chain
    nums = x509.load_der_x509_certificate(cert_der).public_key().public_numbers()
    return f"{nums.x:064x}", f"{nums.y:064x}"


def device_namespaces_hex(mdoc_bytes: bytes) -> str:
    response = cbor2.loads(mdoc_bytes)
    name_spaces = response["documents"][0]["deviceSigned"]["nameSpaces"]
    return name_spaces.value.hex()
