#!/usr/bin/env python3
"""Generate vectors and stage them for admission.

    uv run generate.py key --name <name> \\
        --role <iaca|document-signer|device> [--seed <hex>]

    uv run generate.py certificate --name <name> --key <vector-name> \\
        --subject <cn> [--issuer <cn>] [--signed-by <vector-name>] [--ca] \\
        --valid-from <iso> --valid-until <iso> [--serial <n>]

    uv run generate.py credential --name <name> \\
        --ds-certificate <vector-name> --device-key <vector-name> \\
        [--doctype <doctype>] --claim <namespace> <id> <json>... \\
        --valid-from <iso> --valid-until <iso> [--seed <hex>]

    uv run generate.py presentation --name <name> \\
        --credential <vector-name> --transcript <hex> \\
        [--device-namespace <namespace> <id> <json>]... \\
        [--disclose <namespace> <id>]...

    uv run generate.py proof --name <name> \\
        --presentation <vector-name> --circuit <vector-name> \\
        --backend <google-cpp|isrg-rust> --attr <id>... --timestamp <iso>

    uv run generate.py flip-bit --proof <vector-name> \\
        [--name <name>] [--byte <index>] [--bit <0-7>]

Each command writes under tools/generation/staging/<name>/ and prints the
admit.py command that admits the result.
"""

import argparse
import shlex
import sys

from generation import certificate, credential, flip_bit, key, presentation, prove, staging


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_key = sub.add_parser(
        "key",
        description=key.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_key.add_argument("--name", required=True, type=staging.vector_name, help=staging.NAME_HELP)
    p_key.add_argument(
        "--role",
        required=True,
        choices=["iaca", "document-signer", "device"],
        help="role in the ISO 18013-5 trust chain",
    )
    p_key.add_argument(
        "--seed",
        type=staging.hex_string,
        help="seed, hex (random when absent)",
    )

    p_certificate = sub.add_parser(
        "certificate",
        description=certificate.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_certificate.add_argument(
        "--name", required=True, type=staging.vector_name, help=staging.NAME_HELP
    )
    p_certificate.add_argument(
        "--key",
        required=True,
        dest="key_name",
        help="subject key vector",
    )
    p_certificate.add_argument(
        "--signed-by",
        help="issuer certificate vector (self-signed when absent)",
    )
    p_certificate.add_argument("--subject", required=True, help="subject common name")
    p_certificate.add_argument(
        "--issuer",
        help="issuer common name (subject of --signed-by when absent)",
    )
    p_certificate.add_argument(
        "--ca",
        action="store_true",
        help="CA certificate (leaf when absent)",
    )
    p_certificate.add_argument(
        "--valid-from",
        required=True,
        type=staging.iso_datetime,
        help="validity start, ISO 8601 with UTC offset",
    )
    p_certificate.add_argument(
        "--valid-until",
        required=True,
        type=staging.iso_datetime,
        help="validity end, ISO 8601 with UTC offset",
    )
    p_certificate.add_argument(
        "--serial",
        type=int,
        help="serial number (random when absent)",
    )

    p_credential = sub.add_parser(
        "credential",
        description=credential.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_credential.add_argument(
        "--name", required=True, type=staging.vector_name, help=staging.NAME_HELP
    )
    p_credential.add_argument(
        "--ds-certificate",
        required=True,
        dest="ds_certificate_name",
        help="certificate vector",
    )
    p_credential.add_argument(
        "--device-key",
        required=True,
        dest="device_key_name",
        help="device key vector",
    )
    p_credential.add_argument(
        "--doctype",
        default="eu.europa.ec.av.1",
        help="doctype (eu.europa.ec.av.1 when absent)",
    )
    p_credential.add_argument(
        "--claim",
        action="append",
        required=True,
        dest="claims",
        nargs=3,
        metavar=("NAMESPACE", "ID", "VALUE"),
        help="claim: namespace, id, JSON value (repeatable)",
    )
    p_credential.add_argument(
        "--valid-from",
        required=True,
        type=staging.iso_datetime,
        help="MSO validFrom, ISO 8601 with UTC offset",
    )
    p_credential.add_argument(
        "--valid-until",
        required=True,
        type=staging.iso_datetime,
        help="MSO validUntil, ISO 8601 with UTC offset",
    )
    p_credential.add_argument(
        "--seed",
        type=staging.hex_string,
        help="seed, hex (random when absent)",
    )

    p_presentation = sub.add_parser(
        "presentation",
        description=presentation.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_presentation.add_argument(
        "--name", required=True, type=staging.vector_name, help=staging.NAME_HELP
    )
    p_presentation.add_argument(
        "--credential",
        required=True,
        dest="credential_name",
        help="credential vector",
    )
    p_presentation.add_argument(
        "--transcript",
        required=True,
        type=staging.hex_string,
        help="session transcript, CBOR hex",
    )
    p_presentation.add_argument(
        "--device-namespace",
        action="append",
        default=[],
        dest="device_namespaces",
        nargs=3,
        metavar=("NAMESPACE", "ID", "VALUE"),
        help="device-signed item: namespace, id, JSON value (repeatable)",
    )
    p_presentation.add_argument(
        "--disclose",
        action="append",
        default=[],
        nargs=2,
        metavar=("NAMESPACE", "ID"),
        help="disclosed item: namespace, id (repeatable, all when absent)",
    )

    p_proof = sub.add_parser(
        "proof",
        description=prove.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_proof.add_argument("--name", required=True, type=staging.vector_name, help=staging.NAME_HELP)
    p_proof.add_argument(
        "--presentation",
        required=True,
        dest="presentation_name",
        help="presentation vector",
    )
    p_proof.add_argument(
        "--circuit",
        required=True,
        dest="circuit_name",
        help="circuit vector",
    )
    p_proof.add_argument(
        "--backend",
        required=True,
        choices=["google-cpp", "isrg-rust"],
        help="prover backend",
    )
    p_proof.add_argument(
        "--attr",
        action="append",
        required=True,
        dest="attr_ids",
        help="disclosed attribute id (repeatable, in order)",
    )
    p_proof.add_argument(
        "--timestamp",
        required=True,
        type=staging.iso_datetime,
        help="verification time, ISO 8601 with UTC offset",
    )

    p_flip = sub.add_parser(
        "flip-bit",
        description=flip_bit.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_flip.add_argument("--proof", required=True, dest="proof_name", help="source proof vector")
    p_flip.add_argument(
        "--name",
        type=staging.vector_name,
        help="vector name (source name plus -bit-flipped when absent)",
    )
    p_flip.add_argument(
        "--byte",
        type=int,
        dest="byte_index",
        help="byte index (middle byte when absent)",
    )
    p_flip.add_argument("--bit", type=int, default=0, choices=range(8), help="bit index, 0 to 7")

    args = parser.parse_args()
    staging.require_committed()
    command = shlex.join(["generate.py", *sys.argv[1:]])
    if args.command == "key":
        key.key(command, args.name, args.role, args.seed)
    elif args.command == "certificate":
        certificate.certificate(
            command,
            args.name,
            args.key_name,
            args.signed_by,
            args.subject,
            args.issuer,
            args.ca,
            args.valid_from,
            args.valid_until,
            args.serial,
        )
    elif args.command == "credential":
        credential.credential(
            command,
            args.name,
            args.ds_certificate_name,
            args.device_key_name,
            args.doctype,
            args.claims,
            args.valid_from,
            args.valid_until,
            args.seed,
        )
    elif args.command == "presentation":
        presentation.presentation(
            command,
            args.name,
            args.credential_name,
            args.transcript,
            args.device_namespaces,
            args.disclose,
        )
    elif args.command == "proof":
        prove.prove(
            command,
            args.name,
            args.presentation_name,
            args.circuit_name,
            args.backend,
            args.attr_ids,
            args.timestamp,
        )
    elif args.command == "flip-bit":
        flip_bit.flip_bit(command, args.proof_name, args.name, args.byte_index, args.bit)


if __name__ == "__main__":
    main()
