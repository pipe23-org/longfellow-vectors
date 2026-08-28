import json
import subprocess
import sys
from pathlib import Path

import pytest

import admit
from admission import records

DATA = Path(__file__).parent / "data"
REPO = "github.com/pipe23-org/fixtures"


def test_repository_provenance_records_ref_and_path(
    collection: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_repo = tmp_path / "source"
    (source_repo / "keys").mkdir(parents=True)
    (source_repo / "keys" / "device.pem").write_bytes((DATA / "device-key.pem").read_bytes())
    subprocess.run(["git", "init", "-q"], cwd=source_repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=source_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "import"],
        cwd=source_repo,
        check=True,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source_repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "key",
            str(source_repo / "keys" / "device.pem"),
            "--repo",
            REPO,
            "--name",
            "device",
            "--role",
            "device",
        ],
    )

    admit.main()

    sidecar = json.loads((records.KEYS / "device.json").read_text())
    assert sidecar["provenance"] == {
        "type": "repository",
        "repo": REPO,
        "ref": head,
        "path": "keys/device.pem",
    }


def test_dirty_source_checkout_refused(
    collection: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_repo = tmp_path / "source"
    (source_repo / "keys").mkdir(parents=True)
    (source_repo / "keys" / "device.pem").write_bytes((DATA / "device-key.pem").read_bytes())
    subprocess.run(["git", "init", "-q"], cwd=source_repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=source_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "import"],
        cwd=source_repo,
        check=True,
    )
    (source_repo / "notes.txt").write_text("uncommitted\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "admit.py",
            "key",
            str(source_repo / "keys" / "device.pem"),
            "--repo",
            REPO,
            "--name",
            "device",
            "--role",
            "device",
        ],
    )

    with pytest.raises(SystemExit) as refused:
        admit.main()

    assert "has uncommitted changes" in str(refused.value)
    assert not (records.KEYS / "device.json").exists()
