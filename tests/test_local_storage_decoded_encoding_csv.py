import csv
import sys
import types

import ccl_wrapper


class FakeRecord:
    def __init__(self, script_key, value):
        self.script_key = script_key
        self.value = value


class FakeLocalStoreDb:
    records = []

    def __init__(self, path):
        self.path = path

    def iter_storage_keys(self, include_deletions=False):
        return ["https://example.com"]

    def iter_records_for_storage_key(self, storage_key, include_deletions=False):
        return iter(self.records)


def test_local_storage_csv_uses_decoded_encoding_from_payload(tmp_path, monkeypatch):
    profile_dir = tmp_path / "profile"
    (profile_dir / "Local Storage" / "leveldb").mkdir(parents=True)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    FakeLocalStoreDb.records = [FakeRecord("key", b"plain")]

    ls_module = types.ModuleType("ccl_chromium_localstorage")
    ls_module.LocalStoreDb = FakeLocalStoreDb
    parent_module = types.ModuleType("ccl_chromium_reader")
    parent_module.ccl_chromium_localstorage = ls_module
    monkeypatch.setitem(sys.modules, "ccl_chromium_reader", parent_module)
    monkeypatch.setitem(sys.modules, "ccl_chromium_reader.ccl_chromium_localstorage", ls_module)

    def fake_smart_decode_payload(*args, **kwargs):
        return {
            "kind": "bytes",
            "raw_len": 5,
            "decoded_len": 5,
            "decoded_encoding": "utf-8",
            "transform_chain": [],
            "text_preview": "hi",
            "json_preview": None,
            "extracted_files": [],
            "errors": [],
            "notes": [],
        }

    monkeypatch.setattr(ccl_wrapper, "smart_decode_payload", fake_smart_decode_payload)

    ccl_wrapper.export_local_storage(
        None,
        profile_dir,
        out_dir,
        "root",
        "Default",
        ccl_wrapper.Logger(tmp_path / "run.log", verbose=False),
        None,
    )

    csv_path = out_dir / "local_storage" / "local_storage_records.csv"
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert "decoded_encoding" in reader.fieldnames
        rows = list(reader)

    assert rows[0]["decoded_encoding"] == "utf-8"
