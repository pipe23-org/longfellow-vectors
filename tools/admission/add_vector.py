#!/usr/bin/env python3
"""Write captured artifacts into the vectors collection.

    uv run add_vector.py import-circuit <blob-path> --repo <host/owner/name> \\
        --name <name> --version <n> --num-attributes <n>

    uv run add_vector.py import-presentation <vector-json-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> [--credential <vector-name>]

    uv run add_vector.py import-proof <proof-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> [--prover <backend>] [--circuit <circuit-name>] \\
        [--timestamp <iso>] \\
        ( [--presentation <presentation-name>] [--attr <id>]... \\
        | --doctype <doctype> --transcript <hex> \\
          --issuer-public-key-x <hex> --issuer-public-key-y <hex> \\
          [--claim <namespace> <id> <cbor-hex>]... [--device-namespaces <hex>] )

    uv run add_vector.py import-key <pem-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> --role <iaca|document-signer|device>

    uv run add_vector.py import-credential <cbor-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> [--device-key <vector-name>] \\
        [--ds-certificate <vector-name>]

    uv run add_vector.py import-certificate <pem-path> --repo <host/owner/name> \\
        --name <name> --role <iaca|document-signer> [--signed-by <name>] \\
        [--key <vector-name>]

add_vector.py admits externally produced bytes into the collection. Each mode
copies its source bytes byte-identically into vectors/mdoc/ and writes the JSON
sidecar that governs them. New artifacts are constructed by standalone scripts
outside this tool.

docs/admission.md holds the rules every mode follows and the procedure for
readmitting a vector from its source.
"""

import argparse

from admission import certificates, circuits, credentials, keys, presentations, proofs, records


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_circuit = sub.add_parser(
        "import-circuit",
        description=circuits.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_circuit.add_argument("blob_path", help="circuit blob to admit")
    p_circuit.add_argument("--repo", required=True, help=records.REPO_HELP)
    p_circuit.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_circuit.add_argument(
        "--version",
        type=int,
        required=True,
        help="circuit version the blob was exported at, recorded as given",
    )
    p_circuit.add_argument(
        "--num-attributes",
        type=int,
        required=True,
        help="number of attributes the circuit proves over, recorded as given",
    )

    p_presentation = sub.add_parser(
        "import-presentation",
        description=presentations.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_presentation.add_argument(
        "vector_path", help="JSON file holding the presentation's mdoc and transcript hex"
    )
    p_presentation_source = p_presentation.add_mutually_exclusive_group(required=True)
    p_presentation_source.add_argument("--repo", help=records.REPO_HELP)
    p_presentation_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_presentation.add_argument("--ref", help=records.REF_HELP)
    p_presentation.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_presentation.add_argument(
        "--credential",
        dest="credential_name",
        help="admitted credential vector the DeviceResponse presents; the vector is refused "
        "when the collection holds no credential of that name",
    )

    p_proof = sub.add_parser(
        "import-proof",
        description=proofs.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_proof.add_argument("proof_path", help="proof blob to admit")
    p_proof_source = p_proof.add_mutually_exclusive_group(required=True)
    p_proof_source.add_argument("--repo", help=records.REPO_HELP)
    p_proof_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_proof.add_argument("--ref", help=records.REF_HELP)
    p_proof.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_proof.add_argument(
        "--presentation",
        dest="presentation_name",
        help="admitted presentation vector the proof was made from; the statement fields are "
        "copied from it, and the statement flags are refused alongside it",
    )
    p_proof.add_argument(
        "--prover",
        help="implementation that produced the proof bytes, by backend registry name, "
        "e.g. google-cpp",
    )
    p_proof.add_argument(
        "--circuit",
        help="admitted circuit vector the proof was made with; the vector is refused when the "
        "collection holds no circuit of that name",
    )
    p_proof.add_argument(
        "--timestamp",
        help="verification time the proof was made with, as an RFC 3339 date-time carrying a "
        "UTC offset; recorded as given, and the schema rejects any other form",
    )
    p_proof.add_argument(
        "--attr",
        action="append",
        default=[],
        dest="attr_ids",
        help="attribute id the proof discloses; its namespace and CBOR value are read from the "
        "presentation's issuerSigned map; repeatable, and at least one is required with "
        "--presentation",
    )
    p_proof.add_argument(
        "--doctype",
        help="mdoc doctype the proof is scoped to; a statement flag, recorded as given",
    )
    p_proof.add_argument(
        "--transcript",
        help="session transcript the proof is bound to, hex; a statement flag, recorded lowercased",
    )
    p_proof.add_argument(
        "--issuer-public-key-x",
        help="issuer public key coordinate x, 64 hex digits; a statement flag, recorded lowercased",
    )
    p_proof.add_argument(
        "--issuer-public-key-y",
        help="issuer public key coordinate y, 64 hex digits; a statement flag, recorded lowercased",
    )
    p_proof.add_argument(
        "--claim",
        action="append",
        default=[],
        dest="claims",
        nargs=3,
        metavar=("NAMESPACE", "ID", "CBOR_HEX"),
        help="attribute the proof discloses, as namespace, id, and the CBOR value in hex; "
        "a statement flag, repeatable, and at least one is required with the others",
    )
    p_proof.add_argument(
        "--device-namespaces",
        help="inner bytes of the tag-24 DeviceNameSpacesBytes, hex; the one statement flag "
        "the others do not require",
    )

    p_key = sub.add_parser(
        "import-key",
        description=keys.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_key.add_argument("pem_path", help="PEM key file to admit")
    p_key_source = p_key.add_mutually_exclusive_group(required=True)
    p_key_source.add_argument("--repo", help=records.REPO_HELP)
    p_key_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_key.add_argument("--ref", help=records.REF_HELP)
    p_key.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_key.add_argument(
        "--role",
        required=True,
        choices=["iaca", "document-signer", "device"],
        help="the key's position in the ISO 18013-5 trust chain, recorded as given",
    )

    p_credential = sub.add_parser(
        "import-credential",
        description=credentials.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_credential.add_argument("cbor_path", help="CBOR credential file to admit")
    p_cred_source = p_credential.add_mutually_exclusive_group(required=True)
    p_cred_source.add_argument("--repo", help=records.REPO_HELP)
    p_cred_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_credential.add_argument("--ref", help=records.REF_HELP)
    p_credential.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_credential.add_argument(
        "--device-key",
        dest="device_key_name",
        help="admitted key vector whose public half must match the credential's deviceKeyInfo; "
        "the vector is refused on mismatch",
    )
    p_credential.add_argument(
        "--ds-certificate",
        dest="ds_certificate_name",
        help="admitted certificate vector whose bytes must match the credential's x5chain leaf; "
        "the vector is refused on mismatch",
    )

    p_certificate = sub.add_parser(
        "import-certificate",
        description=certificates.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_certificate.add_argument("pem_path", help="PEM certificate file to admit")
    p_certificate.add_argument("--repo", required=True, help=records.REPO_HELP)
    p_certificate.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_certificate.add_argument(
        "--role",
        required=True,
        choices=["iaca", "document-signer"],
        help="the certificate's position in the ISO 18013-5 trust chain, recorded as given",
    )
    p_certificate.add_argument(
        "--signed-by",
        help="admitted certificate vector whose key must verify this certificate's signature; "
        "the vector is refused when the signature does not verify",
    )
    p_certificate.add_argument(
        "--key",
        dest="key_name",
        help="admitted key vector this certificate certifies; the certificate's "
        "SubjectPublicKeyInfo fingerprint must equal the key vector's fingerprint, and the "
        "vector is refused on mismatch",
    )
    for p_sidecar in (
        p_circuit,
        p_presentation,
        p_proof,
        p_key,
        p_credential,
        p_certificate,
    ):
        p_sidecar.add_argument("--comment", help=records.COMMENT_HELP)

    args = parser.parse_args()
    if getattr(args, "ref", None) is not None and args.generator is None:
        parser.error("--ref requires --generator")
    if args.command == "import-circuit":
        circuits.import_circuit(
            args.blob_path,
            args.repo,
            args.name,
            args.version,
            args.num_attributes,
            args.comment,
        )
    elif args.command == "import-presentation":
        presentations.import_presentation(
            args.vector_path,
            args.repo,
            args.generator,
            args.ref,
            args.name,
            args.credential_name,
            args.comment,
        )
    elif args.command == "import-proof":
        proofs.import_proof(
            args.proof_path,
            args.repo,
            args.generator,
            args.ref,
            args.name,
            args.presentation_name,
            args.prover,
            args.circuit,
            args.timestamp,
            args.attr_ids,
            proofs.statement_from_flags(parser, args),
            args.comment,
        )
    elif args.command == "import-key":
        keys.import_key(
            args.pem_path,
            args.repo,
            args.generator,
            args.ref,
            args.name,
            args.role,
            args.comment,
        )
    elif args.command == "import-credential":
        credentials.import_credential(
            args.cbor_path,
            args.repo,
            args.generator,
            args.ref,
            args.name,
            args.device_key_name,
            args.ds_certificate_name,
            args.comment,
        )
    elif args.command == "import-certificate":
        certificates.import_certificate(
            args.pem_path,
            args.repo,
            args.name,
            args.role,
            args.signed_by,
            args.key_name,
            args.comment,
        )


if __name__ == "__main__":
    main()
