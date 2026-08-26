#!/usr/bin/env python3
"""Construct new vectors and stage them for admission.

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

generate.py writes the bytes it constructs under
tools/generation/staging/<name>/, which is not tracked, and prints the
admit.py command that admits them, to be run from tools/admission. Each
command reads the vectors it builds on from the collection by name.

The printed command records constructed provenance: --generator holds the
command line with every value the command generated filled in, and --ref the
commit tools/generation runs from. --ref is omitted when tools/generation has
uncommitted changes. Re-running the recorded command line reproduces the bytes
for every command but proof, whose prover draws its own randomness.

docs/admission.md holds the rules the admission commands follow.
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
        help="the key's position in the ISO 18013-5 trust chain",
    )
    p_key.add_argument(
        "--seed",
        type=staging.hex_string,
        help="seed the private scalar is derived from, hex; 32 random bytes when absent",
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
        help="admitted key vector the certificate certifies",
    )
    p_certificate.add_argument(
        "--signed-by",
        help="admitted certificate vector whose key signs this one, resolved through its key "
        "reference; the certificate is self-signed under --key when absent",
    )
    p_certificate.add_argument("--subject", required=True, help="subject common name")
    p_certificate.add_argument(
        "--issuer",
        help="issuer common name; the signer certificate's subject common name when absent, "
        "and --subject on a self-signed certificate",
    )
    p_certificate.add_argument(
        "--ca",
        action="store_true",
        help="build a CA certificate, basicConstraints CA and keyUsage keyCertSign, admitted "
        "with role iaca; a leaf carries keyUsage digitalSignature and role document-signer",
    )
    p_certificate.add_argument(
        "--valid-from",
        required=True,
        type=staging.iso_datetime,
        help="start of the validity window, as an ISO 8601 date-time carrying a UTC offset",
    )
    p_certificate.add_argument(
        "--valid-until",
        required=True,
        type=staging.iso_datetime,
        help="end of the validity window, as an ISO 8601 date-time carrying a UTC offset",
    )
    p_certificate.add_argument(
        "--serial",
        type=int,
        help="serial number to carry; x509.random_serial_number() when absent",
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
        help="admitted document-signer certificate vector the x5chain carries; its key "
        "reference resolves the key that signs the MSO",
    )
    p_credential.add_argument(
        "--device-key",
        required=True,
        dest="device_key_name",
        help="admitted key vector the MSO's deviceKeyInfo binds",
    )
    p_credential.add_argument(
        "--doctype",
        default="eu.europa.ec.av.1",
        help="doctype the MSO carries",
    )
    p_credential.add_argument(
        "--claim",
        action="append",
        required=True,
        dest="claims",
        nargs=3,
        metavar=("NAMESPACE", "ID", "VALUE"),
        help="issuer-signed claim, as namespace, id, and the value as JSON; repeatable",
    )
    p_credential.add_argument(
        "--valid-from",
        required=True,
        type=staging.iso_datetime,
        help="MSO signed and validFrom timestamp, as an ISO 8601 date-time carrying a UTC offset",
    )
    p_credential.add_argument(
        "--valid-until",
        required=True,
        type=staging.iso_datetime,
        help="MSO validUntil timestamp, as an ISO 8601 date-time carrying a UTC offset",
    )
    p_credential.add_argument(
        "--seed",
        type=staging.hex_string,
        help="seed the IssuerSignedItem salts are derived from, hex; 32 random bytes when absent",
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
        help="admitted credential vector to present; its device_key reference resolves the key "
        "that signs the transcript",
    )
    p_presentation.add_argument(
        "--transcript",
        required=True,
        type=staging.hex_string,
        help="CBOR SessionTranscript the device signature is bound to, hex",
    )
    p_presentation.add_argument(
        "--device-namespace",
        action="append",
        default=[],
        dest="device_namespaces",
        nargs=3,
        metavar=("NAMESPACE", "ID", "VALUE"),
        help="device-signed item, as namespace, id, and the value as JSON; repeatable, and "
        "the empty map is signed when none is given",
    )
    p_presentation.add_argument(
        "--disclose",
        action="append",
        default=[],
        nargs=2,
        metavar=("NAMESPACE", "ID"),
        help="issuer-signed item of the credential to carry, as namespace and id; repeatable, "
        "and every item the credential holds is carried when none is given",
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
        help="admitted presentation vector to prove over",
    )
    p_proof.add_argument(
        "--circuit",
        required=True,
        dest="circuit_name",
        help="admitted circuit vector to prove with",
    )
    p_proof.add_argument(
        "--backend",
        required=True,
        choices=["google-cpp", "isrg-rust"],
        help="implementation that produces the proof bytes, by backend registry name",
    )
    p_proof.add_argument(
        "--attr",
        action="append",
        required=True,
        dest="attr_ids",
        help="attribute id to disclose; its namespace and CBOR value come from the "
        "presentation, and the claims are proved in the order given; repeatable",
    )
    p_proof.add_argument(
        "--timestamp",
        required=True,
        type=staging.iso_datetime,
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
