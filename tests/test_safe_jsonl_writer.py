from pathlib import Path

import ccl_wrapper


def test_safe_jsonl_writer_falls_back(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    writer = ccl_wrapper.SafeJsonlWriter(out_dir)
    primary_path = out_dir / "errors.jsonl"
    primary_path.mkdir(parents=True, exist_ok=True)

    writer.write_event({"stage": "test_event", "note": "first"})
    writer.write_event({"stage": "test_event", "note": "second"})

    fallback_path = out_dir / "errors_fallback.jsonl"
    assert fallback_path.exists()
    lines = [line for line in fallback_path.read_text(encoding="utf-8", errors="replace").splitlines() if line]
    assert len(lines) >= 2
    joined = "\n".join(lines)
    assert "first" in joined
    assert "second" in joined
