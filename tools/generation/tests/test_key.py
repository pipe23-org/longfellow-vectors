"""key derives one key per seed and records the seed it used."""

import re
from pathlib import Path

import pytest

from generation import key, staging

ROLE = "device"
SEED = "00" * 31 + "01"
OTHER_SEED = "00" * 31 + "02"


def test_one_seed_gives_one_key(collection: Path) -> None:
    key.key("generate.py key --name first --role device --seed " + SEED, "first", ROLE, SEED)
    key.key("generate.py key --name second --role device --seed " + SEED, "second", ROLE, SEED)

    first = (staging.STAGING / "first" / "first.pem").read_bytes()
    second = (staging.STAGING / "second" / "second.pem").read_bytes()
    assert first == second


def test_different_seeds_give_different_keys(collection: Path) -> None:
    key.key("generate.py key --name first --role device --seed " + SEED, "first", ROLE, SEED)
    key.key(
        "generate.py key --name other --role device --seed " + OTHER_SEED,
        "other",
        ROLE,
        OTHER_SEED,
    )

    first = (staging.STAGING / "first" / "first.pem").read_bytes()
    other = (staging.STAGING / "other" / "other.pem").read_bytes()
    assert first != other


def test_command_carries_the_seed_it_generated(
    collection: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key.key("generate.py key --name generated --role device", "generated", ROLE, None)

    printed = capsys.readouterr().out
    generated = (staging.STAGING / "generated" / "generated.pem").read_bytes()
    recorded = re.search(r"--seed ([0-9a-f]+)", printed)
    assert recorded is not None, "the printed command carries no --seed"
    key.key("generate.py key --name repeated --role device", "repeated", ROLE, recorded.group(1))
    assert (staging.STAGING / "repeated" / "repeated.pem").read_bytes() == generated
