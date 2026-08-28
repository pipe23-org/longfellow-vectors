#!/usr/bin/env python3
"""Admit vectors into the collection.

    uv run admit.py circuit <blob-path> --repo <host/owner/name> \\
        --name <name> --version <n> --num-attributes <n>

    uv run admit.py presentation <vector-json-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> [--credential <vector-name>]

    uv run admit.py proof <proof-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> [--prover <backend>] [--circuit <circuit-name>] \\
        [--timestamp <iso>] \\
        ( [--presentation <presentation-name>] [--attr <id>]... \\
        | --doctype <doctype> --transcript <hex> \\
          --issuer-public-key-x <hex> --issuer-public-key-y <hex> \\
          [--claim <namespace> <id> <cbor-hex>]... [--device-namespaces <hex>] )

    uv run admit.py key <pem-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> --role <iaca|document-signer|device>

    uv run admit.py credential <cbor-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> [--device-key <vector-name>] \\
        [--ds-certificate <vector-name>]

    uv run admit.py certificate <pem-path> \\
        (--repo <host/owner/name> | --generator <string>) \\
        --name <name> --role <iaca|document-signer> [--signed-by <name>] \\
        [--key <vector-name>]
"""

import argparse

from admission import certificates, circuits, credentials, keys, presentations, proofs, records


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_circuit = sub.add_parser(
        "circuit",
        description=circuits.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_circuit.add_argument("path", help="circuit file")
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
        help="circuit version",
    )
    p_circuit.add_argument(
        "--num-attributes",
        type=int,
        required=True,
        help="attribute count",
    )

    p_presentation = sub.add_parser(
        "presentation",
        description=presentations.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_presentation.add_argument("path", help="JSON file with mdoc and transcript, hex")
    p_presentation_source = p_presentation.add_mutually_exclusive_group(required=True)
    p_presentation_source.add_argument("--repo", help=records.REPO_HELP)
    p_presentation_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_presentation.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_presentation.add_argument(
        "--credential",
        dest="credential_name",
        help="presented credential vector",
    )

    p_proof = sub.add_parser(
        "proof",
        description=proofs.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_proof.add_argument("path", help="proof file")
    p_proof_source = p_proof.add_mutually_exclusive_group(required=True)
    p_proof_source.add_argument("--repo", help=records.REPO_HELP)
    p_proof_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_proof.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_proof.add_argument(
        "--presentation",
        dest="presentation_name",
        help="source presentation vector",
    )
    p_proof.add_argument(
        "--prover",
        help="prover backend, e.g. google-cpp",
    )
    p_proof.add_argument(
        "--circuit",
        help="circuit vector",
    )
    p_proof.add_argument(
        "--timestamp",
        help="verification time, RFC 3339 with UTC offset",
    )
    p_proof.add_argument(
        "--attr",
        action="append",
        default=[],
        dest="attr_ids",
        help="disclosed attribute id (repeatable)",
    )
    p_proof.add_argument(
        "--doctype",
        help="doctype",
    )
    p_proof.add_argument(
        "--transcript",
        help="session transcript, hex",
    )
    p_proof.add_argument(
        "--issuer-public-key-x",
        help="issuer public key x, 64 hex digits",
    )
    p_proof.add_argument(
        "--issuer-public-key-y",
        help="issuer public key y, 64 hex digits",
    )
    p_proof.add_argument(
        "--claim",
        action="append",
        default=[],
        dest="claims",
        nargs=3,
        metavar=("NAMESPACE", "ID", "CBOR_HEX"),
        help="claim: namespace, id, CBOR value hex (repeatable)",
    )
    p_proof.add_argument(
        "--device-namespaces",
        help="DeviceNameSpaces map, CBOR hex",
    )

    p_key = sub.add_parser(
        "key",
        description=keys.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_key.add_argument("path", help="PEM file")
    p_key_source = p_key.add_mutually_exclusive_group(required=True)
    p_key_source.add_argument("--repo", help=records.REPO_HELP)
    p_key_source.add_argument("--generator", help=records.GENERATOR_HELP)
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
        help="role in the ISO 18013-5 trust chain",
    )

    p_credential = sub.add_parser(
        "credential",
        description=credentials.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_credential.add_argument("path", help="IssuerSigned CBOR file")
    p_cred_source = p_credential.add_mutually_exclusive_group(required=True)
    p_cred_source.add_argument("--repo", help=records.REPO_HELP)
    p_cred_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_credential.add_argument(
        "--name",
        required=True,
        type=records.record_name,
        help=records.NAME_HELP,
    )
    p_credential.add_argument(
        "--device-key",
        dest="device_key_name",
        help="device key vector",
    )
    p_credential.add_argument(
        "--ds-certificate",
        dest="ds_certificate_name",
        help="certificate vector",
    )

    p_certificate = sub.add_parser(
        "certificate",
        description=certificates.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_certificate.add_argument("path", help="PEM file")
    p_certificate_source = p_certificate.add_mutually_exclusive_group(required=True)
    p_certificate_source.add_argument("--repo", help=records.REPO_HELP)
    p_certificate_source.add_argument("--generator", help=records.GENERATOR_HELP)
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
        help="role in the ISO 18013-5 trust chain",
    )
    p_certificate.add_argument(
        "--signed-by",
        help="issuer certificate vector",
    )
    p_certificate.add_argument(
        "--key",
        dest="key_name",
        help="subject key vector",
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
    if args.command == "circuit":
        circuits.import_circuit(
            args.path,
            args.repo,
            args.name,
            args.version,
            args.num_attributes,
            args.comment,
        )
    elif args.command == "presentation":
        presentations.import_presentation(
            args.path,
            args.repo,
            args.generator,
            args.name,
            args.credential_name,
            args.comment,
        )
    elif args.command == "proof":
        proofs.import_proof(
            args.path,
            args.repo,
            args.generator,
            args.name,
            args.presentation_name,
            args.prover,
            args.circuit,
            args.timestamp,
            args.attr_ids,
            proofs.statement_from_flags(parser, args),
            args.comment,
        )
    elif args.command == "key":
        keys.import_key(
            args.path,
            args.repo,
            args.generator,
            args.name,
            args.role,
            args.comment,
        )
    elif args.command == "credential":
        credentials.import_credential(
            args.path,
            args.repo,
            args.generator,
            args.name,
            args.device_key_name,
            args.ds_certificate_name,
            args.comment,
        )
    elif args.command == "certificate":
        certificates.import_certificate(
            args.path,
            args.repo,
            args.generator,
            args.name,
            args.role,
            args.signed_by,
            args.key_name,
            args.comment,
        )


if __name__ == "__main__":
    main()
