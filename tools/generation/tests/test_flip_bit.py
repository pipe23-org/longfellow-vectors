from pathlib import Path

import pytest

from generation import flip_bit, staging

PROOF_NAME = "source"
DERIVED_NAME = "source-bit-flipped"
MIDDLE_BYTE = 32
BIT = 0
COMMAND = "generate.py flip-bit --proof source"
COMMAND_TAIL = (
    "--name source-bit-flipped "
    "--prover google-cpp --circuit v7-1attr --presentation smoke --attr age_over_18 "
    "--timestamp 2026-08-02T00:00:00+00:00 "
    "--comment 'source with bit 0 of byte 32 flipped'"
)


def test_flip_bit_changes_one_bit(collection: Path) -> None:
    flip_bit.flip_bit(COMMAND, PROOF_NAME, None, None, BIT)

    source = staging.collection().mdoc.proof(PROOF_NAME).bytes
    derived = (staging.STAGING / DERIVED_NAME / f"{DERIVED_NAME}.proof").read_bytes()
    assert len(derived) == len(source)
    differing = sum((a ^ b).bit_count() for a, b in zip(source, derived, strict=True))
    assert differing == 1


def test_flip_bit_command_states_the_derivation(
    collection: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    flip_bit.flip_bit(COMMAND, PROOF_NAME, None, None, BIT)

    printed = capsys.readouterr().out.rstrip("\n")
    assert f"--generator '{COMMAND}'" in printed
    assert printed.endswith(COMMAND_TAIL)
