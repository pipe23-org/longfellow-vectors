from pathlib import Path
from typing import Any

from . import records

DESCRIPTION = "Admit a circuit."


def import_circuit(
    blob_path: str,
    repo: str,
    name: str,
    version: int,
    num_attributes: int,
    comment: str | None,
) -> None:
    source = Path(blob_path)
    blob = source.read_bytes()
    sidecar: dict[str, Any] = {
        "schema": "mdoc-circuits-v1.schema.json",
        "system": records.SYSTEM,
    }
    sidecar["sha256"] = records.sha256(blob)
    sidecar["version"] = version
    sidecar["num_attributes"] = num_attributes
    sidecar["provenance"] = records.provenance(source, repo)
    if comment is not None:
        sidecar["comment"] = comment
    records.write_record(records.CIRCUITS / f"{name}.circuit", blob, sidecar)
