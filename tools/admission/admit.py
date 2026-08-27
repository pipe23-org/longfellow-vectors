#!/usr/bin/env python3
"""Admit vectors into the collection.

    uv run admit.py circuit <blob-path> --repo <host/owner/name> \\
        --name <name> --version <n> --num-attributes <n>

    uv run admit.py presentation <vector-json-path> \\
        (--repo <host/owner/name> | --generator <string> --ref <commit>) \\
        --name <name> [--credential <vector-name>]

    uv run admit.py proof <proof-path> \\
        (--repo <host/owner/name> | --generator <string> --ref <commit>) \\
        --name <name> [--prover <backend>] [--circuit <circuit-name>] \\
        [--timestamp <iso>] \\
        ( [--presentation <presentation-name>] [--attr <id>]... \\
        | --doctype <doctype> --transcript <hex> \\
          --issuer-public-key-x <hex> --issuer-public-key-y <hex> \\
          [--claim <namespace> <id> <cbor-hex>]... [--device-namespaces <hex>] )

    uv run admit.py key <pem-path> \\
        (--repo <host/owner/name> | --generator <string> --ref <commit>) \\
        --name <name> --role <iaca|document-signer|device>

    uv run admit.py credential <cbor-path> \\
        (--repo <host/owner/name> | --generator <string> --ref <commit>) \\
        --name <name> [--device-key <vector-name>] \\
        [--ds-certificate <vector-name>]

    uv run admit.py certificate <pem-path> \\
        (--repo <host/owner/name> | --generator <string> --ref <commit>) \\
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
        help="circuit version",
    )
    p_circuit.add_argument(
        "--num-attributes",
        type=int,
        required=True,
        help="number of attributes the circuit proves over",
    )

    p_presentation = sub.add_parser(
        "presentation",
        description=presentations.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_presentation.add_argument(
        "vector_path", help="JSON file with mdoc and transcript fields, hex"
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
        help="credential vector the response presents",
    )

    p_proof = sub.add_parser(
        "proof",
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
        help="presentation vector the proof was made from",
    )
    p_proof.add_argument(
        "--prover",
        help="backend that made the proof, e.g. google-cpp",
    )
    p_proof.add_argument(
        "--circuit",
        help="circuit vector the proof was made with",
    )
    p_proof.add_argument(
        "--timestamp",
        help="verification time, RFC 3339 with a UTC offset",
    )
    p_proof.add_argument(
        "--attr",
        action="append",
        default=[],
        dest="attr_ids",
        help="attribute id the proof discloses (repeatable)",
    )
    p_proof.add_argument(
        "--doctype",
        help="doctype of the statement",
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
        help="claim as namespace, id, and CBOR value hex (repeatable)",
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
        help="role in the ISO 18013-5 trust chain",
    )

    p_credential = sub.add_parser(
        "credential",
        description=credentials.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_credential.add_argument("cbor_path", help="IssuerSigned CBOR file to admit")
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
        help="key vector the MSO binds",
    )
    p_credential.add_argument(
        "--ds-certificate",
        dest="ds_certificate_name",
        help="certificate vector in the x5chain",
    )

    p_certificate = sub.add_parser(
        "certificate",
        description=certificates.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_certificate.add_argument("pem_path", help="PEM certificate file to admit")
    p_certificate_source = p_certificate.add_mutually_exclusive_group(required=True)
    p_certificate_source.add_argument("--repo", help=records.REPO_HELP)
    p_certificate_source.add_argument("--generator", help=records.GENERATOR_HELP)
    p_certificate.add_argument("--ref", help=records.REF_HELP)
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
        help="certificate vector whose key signed this one",
    )
    p_certificate.add_argument(
        "--key",
        dest="key_name",
        help="key vector the certificate certifies",
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
    if getattr(args, "generator", None) is not None and args.ref is None:
        parser.error("--generator requires --ref")
    if args.command == "circuit":
        circuits.import_circuit(
            args.blob_path,
            args.repo,
            args.name,
            args.version,
            args.num_attributes,
            args.comment,
        )
    elif args.command == "presentation":
        presentations.import_presentation(
            args.vector_path,
            args.repo,
            args.generator,
            args.ref,
            args.name,
            args.credential_name,
            args.comment,
        )
    elif args.command == "proof":
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
    elif args.command == "key":
        keys.import_key(
            args.pem_path,
            args.repo,
            args.generator,
            args.ref,
            args.name,
            args.role,
            args.comment,
        )
    elif args.command == "credential":
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
    elif args.command == "certificate":
        certificates.import_certificate(
            args.pem_path,
            args.repo,
            args.generator,
            args.ref,
            args.name,
            args.role,
            args.signed_by,
            args.key_name,
            args.comment,
        )


if __name__ == "__main__":
    main()
