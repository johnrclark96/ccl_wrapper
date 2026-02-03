import base64
import gzip
import json
import sys
import types
from pathlib import Path

import ccl_wrapper


def test_gzip_bomb_truncated():
    data = b"a" * (ccl_wrapper.MAX_DECODED_BYTES * 2)
    payload = gzip.compress(data)
    info = ccl_wrapper.smart_decode_payload(payload)
    assert info["was_truncated"] is True
    assert info["decoded_len"] == ccl_wrapper.MAX_DECODED_BYTES
    assert "gzip" in info["transform_chain"]


def test_base64_gzip_chain_decodes():
    raw = json.dumps({"a": 1}).encode("utf-8")
    gz = gzip.compress(raw)
    b64 = base64.b64encode(gz).decode("ascii")
    info = ccl_wrapper.smart_decode_payload(b64)
    assert "base64" in info["transform_chain"]
    assert "gzip" in info["transform_chain"]
    assert "\"a\"" in (info.get("json_preview") or "")


def test_base64_with_whitespace_decodes():
    raw = json.dumps({"a": 2}).encode("utf-8")
    gz = gzip.compress(raw)
    b64 = base64.b64encode(gz).decode("ascii")
    spaced = f"{b64[:10]}\n{b64[10:20]}  {b64[20:]}"
    info = ccl_wrapper.smart_decode_payload(spaced)
    assert "base64" in info["transform_chain"]
    assert "gzip" in info["transform_chain"]


def test_invalid_base64_is_ignored():
    payload = "not-base64!!!!"
    info = ccl_wrapper.smart_decode_payload(payload)
    assert "base64" not in info["transform_chain"]
    assert info["errors"] == []


def test_encoding_attribution_is_empty_by_default():
    raw = json.dumps({"a": 1}).encode("utf-8")
    gz = gzip.compress(raw)
    b64 = base64.b64encode(gz).decode("ascii")
    info = ccl_wrapper.smart_decode_payload(b64)
    assert info["decoded_encoding"] == ""


def test_multi_step_chain_base64_gzip_zlib():
    import zlib

    raw = json.dumps({"a": 3}).encode("utf-8")
    zed = zlib.compress(raw)
    gz = gzip.compress(zed)
    b64 = base64.b64encode(gz).decode("ascii")
    info = ccl_wrapper.smart_decode_payload(b64)
    assert info["transform_chain"][:3] == ["base64", "gzip", "zlib"]


def test_utf16_heuristic_false_for_random_bytes():
    data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert ccl_wrapper.should_decode_utf16le(data) is False


def test_decode_pipeline_returns_original_bytes():
    data = b"hello world"
    res = ccl_wrapper._decode_bytes_pipeline(
        data,
        max_input_bytes=ccl_wrapper.MAX_INPUT_BYTES,
        max_decoded_bytes=ccl_wrapper.MAX_DECODED_BYTES,
        max_depth=ccl_wrapper.MAX_DECODE_DEPTH,
    )
    assert res["decoded_bytes"] == data
    assert res["transform_chain"] == []
    assert res["error"] == ""


def test_filter_csv_row_strips_extra_keys():
    row = {"a": 1, "b": 2, "extra": 3}
    filtered = ccl_wrapper.filter_csv_row(row, ["a", "b"])
    assert set(filtered.keys()) == {"a", "b"}


def test_export_leveldb_raw_writes_reason(tmp_path: Path):
    out_path = tmp_path / "raw.jsonl"
    log_path = tmp_path / "log.txt"
    logger = ccl_wrapper.Logger(log_path, verbose=False)
    result = ccl_wrapper.export_leveldb_raw(
        tmp_path,
        out_path,
        origin="",
        root_tag="root",
        profile_name="profile",
        logger=logger,
        errors_writer=None,
        stage="raw_leveldb",
    )
    lines = out_path.read_text(encoding="utf-8").splitlines()
    assert lines, "Expected a metadata record when raw LevelDB API is missing"
    record = json.loads(lines[0])
    assert record.get("exported") is False
    assert record.get("reason") == "raw_leveldb_api_missing"
    assert result.get("reason") == "raw_leveldb_api_missing"


def test_raw_leveldb_fallback_marker(monkeypatch, tmp_path: Path):
    class BrokenRaw:
        def __init__(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    class FakeLevelDb:
        def __init__(self, *_args, **_kwargs):
            pass

        def iterate_records(self, **_kwargs):
            yield (b"k", b"v")

    storage_mod = types.ModuleType("storage_formats.ccl_leveldb")
    storage_mod.RawLevelDb = BrokenRaw
    storage_pkg = types.ModuleType("storage_formats")
    storage_pkg.__path__ = []
    monkeypatch.setitem(sys.modules, "storage_formats", storage_pkg)
    monkeypatch.setitem(sys.modules, "storage_formats.ccl_leveldb", storage_mod)

    ccl_mod = types.ModuleType("ccl_chromium_reader.ccl_chromium_leveldb")
    ccl_mod.LevelDB = FakeLevelDb
    ccl_pkg = types.ModuleType("ccl_chromium_reader")
    ccl_pkg.__path__ = []
    monkeypatch.setitem(sys.modules, "ccl_chromium_reader", ccl_pkg)
    monkeypatch.setitem(sys.modules, "ccl_chromium_reader.ccl_chromium_leveldb", ccl_mod)

    out_path = tmp_path / "raw.jsonl"
    log_path = tmp_path / "log.txt"
    logger = ccl_wrapper.Logger(log_path, verbose=False)
    result = ccl_wrapper.export_leveldb_raw(
        tmp_path,
        out_path,
        origin="",
        root_tag="root",
        profile_name="profile",
        logger=logger,
        errors_writer=None,
        stage="raw_leveldb",
    )
    assert result.get("raw_leveldb_used") == "fallback_ccl"
    assert "boom" in result.get("raw_leveldb_error", "")


def test_compact_bytes_json_preview_is_bounded():
    data = b"a" * (32 * 1024)
    obj = ccl_wrapper.compact_bytes_json(data, max_preview_bytes=1024)
    assert obj["len"] == len(data)
    assert obj["preview_truncated"] is True


def test_export_local_storage_missing_dir(tmp_path: Path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    log_path = tmp_path / "log.txt"
    logger = ccl_wrapper.Logger(log_path, verbose=False)
    res = ccl_wrapper.export_local_storage(
        None,
        tmp_path,
        out_dir,
        root_tag="root",
        profile_name="profile",
        logger=logger,
        errors_writer=None,
    )
    assert res["exported"] is False
    assert res["reason"] == "missing_local_storage_leveldb"


def test_base64_cap_skips_decode():
    max_chars = (ccl_wrapper.MAX_INPUT_BYTES * 4) // 3 + 8
    payload = "A" * (max_chars + 10)
    info = ccl_wrapper.smart_decode_payload(payload)
    assert "base64_skipped_too_large" in (info.get("notes") or [])


def test_find_blob_indices_none_blob_type():
    value = []
    value.append(value)
    found = ccl_wrapper.find_blob_indices(value, None)
    assert found == []
