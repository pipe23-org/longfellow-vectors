#!/usr/bin/env python3
"""Construct new vectors and stage them for admission.

    uv run generate_vectors.py create-presentation --name <name> \\
        --transcript <hex> --valid-from <iso> --valid-until <iso> \\
        [--doctype <doctype>] [--claim <namespace> <id> <json>]... \\
        [--device-namespace <namespace> <id> <json>]...

    uv run generate_vectors.py prove --name <name> \\
        --presentation <vector-name> --circuit <vector-name> \\
        --backend <google-cpp|isrg-rust> --attr <id>... --timestamp <iso>

    uv run generate_vectors.py flip-bit --proof <vector-name> \\
        [--name <name>] [--byte <index>] [--bit <0-7>]

generate_vectors.py writes the bytes it constructs under
tools/generation/staging/<name>/, which is not tracked, and prints the
add_vector.py command that admits them, to be run from tools/admission.

Admission reads the commit and the in-repo path from the staged file's own
checkout, so a file staged from a tree with uncommitted changes is admitted
against a commit its bytes do not come from.

docs/admission.md holds the rules the admission modes follow.
"""

import argparse

from generation import create_presentation, flip_bit, prove, staging


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_presentation = sub.add_parser(
        "create-presentation",
        description=create_presentation.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_presentation.add_argument(
        "--name", required=True, type=staging.vector_name, help=staging.NAME_HELP
    )
    p_presentation.add_argument(
        "--doctype",
        default="eu.europa.ec.av.1",
        help="doctype of the response's single document",
    )
    p_presentation.add_argument(
        "--claim",
        action="append",
        default=[],
        dest="claims",
        nargs=3,
        metavar=("NAMESPACE", "ID", "VALUE"),
        help="issuer-signed claim, as namespace, id, and the value as JSON; repeatable, and "
        "defaults to eu.europa.ec.av.1 age_over_18 true when none is given",
    )
    p_presentation.add_argument(
        "--device-namespace",
        action="append",
        default=[],
        dest="device_namespaces",
        nargs=3,
        metavar=("NAMESPACE", "ID", "VALUE"),
        help="device-signed item, as namespace, id, and the value as JSON; repeatable, and "
        "the empty map is issued when none is given",
    )
    p_presentation.add_argument(
        "--transcript",
        required=True,
        help="CBOR SessionTranscript the device signature is bound to, hex",
    )
    p_presentation.add_argument(
        "--valid-from",
        required=True,
        type=staging.moment,
        help="MSO signed and validFrom timestamp, and the certificate's window start, as an "
        "ISO 8601 date-time carrying a UTC offset",
    )
    p_presentation.add_argument(
        "--valid-until",
        required=True,
        type=staging.moment,
        help="MSO validUntil timestamp, and the certificate's window end, as an ISO 8601 "
        "date-time carrying a UTC offset",
    )

    p_prove = sub.add_parser(
        "prove",
        description=prove.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_prove.add_argument("--name", required=True, type=staging.vector_name, help=staging.NAME_HELP)
    p_prove.add_argument(
        "--presentation",
        required=True,
        dest="presentation_name",
        help="admitted presentation vector to prove over",
    )
    p_prove.add_argument(
        "--circuit",
        required=True,
        dest="circuit_name",
        help="admitted circuit vector to prove with",
    )
    p_prove.add_argument(
        "--backend",
        required=True,
        choices=["google-cpp", "isrg-rust"],
        help="implementation that produces the proof bytes, by backend registry name",
    )
    p_prove.add_argument(
        "--attr",
        action="append",
        required=True,
        dest="attr_ids",
        help="attribute id to disclose; its namespace and CBOR value come from the "
        "presentation, and the claims are proved in the order given; repeatable",
    )
    p_prove.add_argument(
        "--timestamp",
        required=True,
        type=staging.moment,
        help="verification time to prove at, as an ISO 8601 date-time carrying a UTC offset",
    )

    p_flip = sub.add_parser(
        "flip-bit",
        description=flip_bit.DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_flip.add_argument(
        "--proof", required=True, dest="proof_name", help="admitted proof vector to derive from"
    )
    p_flip.add_argument(
        "--name",
        type=staging.vector_name,
        help=f"{staging.NAME_HELP}; defaults to the source name plus -bit-flipped",
    )
    p_flip.add_argument(
        "--byte",
        type=int,
        dest="byte_index",
        help="index of the byte to flip a bit of; defaults to the middle byte, len // 2",
    )
    p_flip.add_argument(
        "--bit", type=int, default=0, choices=range(8), help="bit of the byte to flip, 0 to 7"
    )

    args = parser.parse_args()
    if args.command == "create-presentation":
        create_presentation.create_presentation(
            args.name,
            args.doctype,
            args.claims or [["eu.europa.ec.av.1", "age_over_18", "true"]],
            args.device_namespaces,
            args.transcript,
            args.valid_from,
            args.valid_until,
        )
    elif args.command == "prove":
        prove.prove(
            args.name,
            args.presentation_name,
            args.circuit_name,
            args.backend,
            args.attr_ids,
            args.timestamp,
        )
    elif args.command == "flip-bit":
        flip_bit.flip_bit(args.proof_name, args.name, args.byte_index, args.bit)


if __name__ == "__main__":
    main()
