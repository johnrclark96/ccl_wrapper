from pathlib import Path

import ccl_wrapper


def test_indexeddb_blob_fallback_reads_direct_file(tmp_path: Path):
    profile_dir = tmp_path / "profile"
    host_id = "host123"
    blob_dir = profile_dir / "IndexedDB" / f"{host_id}.indexeddb.blob"
    blob_dir.mkdir(parents=True)

    blob_number = 1
    payload = b"blob-bytes"
    blob_path = blob_dir / f"{blob_number:010d}"
    blob_path.write_bytes(payload)

    info = ccl_wrapper._read_indexeddb_blob_fallback(
        profile_dir,
        host_id,
        blob_number,
        blob_max_bytes=1024,
    )

    assert info["data"] == payload
    assert info["blob_source"] == "path_fallback"
    assert info["host_id"] == host_id
    assert info["blob_number"] == blob_number
    assert info["reason"] == ""
    assert info["truncated"] is False


def test_indexeddb_blob_fallback_missing_file(tmp_path: Path):
    profile_dir = tmp_path / "profile"
    host_id = "host123"
    blob_dir = profile_dir / "IndexedDB" / f"{host_id}.indexeddb.blob"
    blob_dir.mkdir(parents=True)

    info = ccl_wrapper._read_indexeddb_blob_fallback(
        profile_dir,
        host_id,
        99,
        blob_max_bytes=1024,
    )

    assert info["data"] is None
    assert info["blob_source"] == "path_fallback"
    assert info["reason"] == "blob_file_missing"
