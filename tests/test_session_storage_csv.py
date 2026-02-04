import csv
import logging
import sys
import types

from ccl_wrapper import export_session_storage


class FakeRecord:
    def __init__(self, key, value, seq):
        self.key = key
        self.value = value
        self.leveldb_seq_number = seq


class FakeSessionStoreDb:
    records_by_host = {}

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def iter_hosts(self):
        return list(self.records_by_host.keys())

    def iter_records_for_host(self, host):
        return iter(self.records_by_host.get(host, []))


def test_session_storage_csv_includes_namespace_and_map_fields(tmp_path, monkeypatch):
    prof_dir = tmp_path / "profile"
    (prof_dir / "Session Storage").mkdir(parents=True)
    out_dir = tmp_path / "out"

    host = "example.com"
    map_key = "map-abc123-foo"
    namespace_key = "namespace-1111_2222-ns.example"
    utf16_value = b"\xff\xfeh\x00i\x00"
    FakeSessionStoreDb.records_by_host = {
        host: [
            FakeRecord(map_key, b"plain", 1),
            FakeRecord(namespace_key, utf16_value, 2),
        ]
    }

    ss_module = types.ModuleType("ccl_chromium_sessionstorage")
    ss_module.SessionStoreDb = FakeSessionStoreDb
    parent_module = types.ModuleType("ccl_chromium_reader")
    parent_module.ccl_chromium_sessionstorage = ss_module
    monkeypatch.setitem(sys.modules, "ccl_chromium_reader", parent_module)
    monkeypatch.setitem(sys.modules, "ccl_chromium_reader.ccl_chromium_sessionstorage", ss_module)

    export_session_storage(
        prof_dir,
        profile_obj={},
        profile_out_dir=out_dir,
        root_tag="root",
        profile_name="profile",
        logger=logging.getLogger("test"),
        errors_writer=None,
    )

    csv_path = out_dir / "session_storage" / "session_storage_records.csv"
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        assert "map_id" in reader.fieldnames
        assert "namespace_uuid" in reader.fieldnames
        assert "namespace_host" in reader.fieldnames
        assert "decoded_encoding" in reader.fieldnames
        rows = list(reader)

    map_row = next(row for row in rows if row["map_id"] == "abc123")
    namespace_row = next(row for row in rows if row["namespace_uuid"] == "1111-2222")

    assert map_row["namespace_host"] == host
    assert namespace_row["namespace_host"] == "ns.example"
    assert namespace_row["decoded_encoding"] == "utf-16-le"
