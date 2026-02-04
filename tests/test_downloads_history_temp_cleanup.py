import csv
import logging
import sqlite3

from ccl_wrapper import export_downloads


def test_downloads_history_temp_cleanup(tmp_path):
    prof_dir = tmp_path / "profile"
    prof_dir.mkdir(parents=True)
    history_path = prof_dir / "History"

    conn = sqlite3.connect(history_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                tab_url TEXT,
                start_time INTEGER,
                end_time INTEGER,
                target_path TEXT
            )
            """
        )
        cur.execute(
            "INSERT INTO downloads (id, tab_url, start_time, end_time, target_path) VALUES (?, ?, ?, ?, ?)",
            (1, "https://example.com", 0, 0, "/tmp/file.txt"),
        )
        conn.commit()
    finally:
        conn.close()

    out_dir = tmp_path / "out"

    export_downloads(
        profile_obj={},
        prof_dir=prof_dir,
        profile_out_dir=out_dir,
        root_tag="root",
        profile_name="profile",
        logger=logging.getLogger("test"),
        errors_writer=None,
    )

    csv_path = out_dir / "downloads" / "downloads.csv"
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert rows

    temp_files = list((out_dir / "downloads").glob("_History_*.sqlite"))
    assert temp_files == []
