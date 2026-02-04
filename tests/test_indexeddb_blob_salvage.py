import csv
import json
from pathlib import Path

import ccl_wrapper


def test_salvage_indexeddb_blob_dir_writes_inventory_and_copies(tmp_path: Path):
    profile_dir = tmp_path / "profile"
    host_id = "example.host"
    blob_dir = profile_dir / "IndexedDB" / f"{host_id}.indexeddb.blob"
    blob_dir.mkdir(parents=True)

    blob_name = "0000000001"
    payload = b"indexeddb-blob"
    blob_path = blob_dir / blob_name
    blob_path.write_bytes(payload)

    out_dir = tmp_path / "out"
    dest = ccl_wrapper._salvage_indexeddb_blob_dir(
        profile_dir,
        host_id,
        out_dir,
        root_tag="root",
        profile_name="profile",
        errors_writer=None,
    )

    assert dest is not None
    dest_path = Path(dest)
    inv_jsonl = dest_path / "blob_inventory.jsonl"
    inv_csv = dest_path / "blob_inventory.csv"

    assert inv_jsonl.exists()
    assert inv_csv.exists()

    jsonl_lines = inv_jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert len(jsonl_lines) >= 1
    event = json.loads(jsonl_lines[0])
    assert event["host_id"] == host_id
    assert event["profile_path"] == str(profile_dir)
    assert event["rel_path"] == blob_name
    assert event["size_bytes"] == len(payload)
    assert event["mtime_utc"].endswith("Z")
    assert event["root_tag"] == "root"
    assert event["profile_name"] == "profile"

    with inv_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    assert len(rows) >= 1
    assert rows[0]["rel_path"] == blob_name
    assert int(rows[0]["size_bytes"]) == len(payload)
    assert rows[0]["copied_to"]

    copied_blob = dest_path / blob_name
    assert copied_blob.exists()
    assert copied_blob.read_bytes() == payload
