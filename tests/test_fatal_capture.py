from pathlib import Path

import ccl_wrapper


def test_capture_fatal_exception_writes_fatal(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        raise RuntimeError("boom")
    except RuntimeError as exc:
        exit_code = ccl_wrapper.capture_fatal_exception(exc, out_dir=out_dir, errors_path=None)

    assert exit_code != 0
    fatal_path = out_dir / "fatal.txt"
    assert fatal_path.exists()
    text = fatal_path.read_text(encoding="utf-8", errors="replace")
    assert "RuntimeError" in text


def test_capture_fatal_exception_uses_traceback(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        raise ValueError("trace me")
    except ValueError as exc:
        captured = exc

    exit_code = ccl_wrapper.capture_fatal_exception(captured, out_dir=out_dir, errors_path=None)

    assert exit_code != 0
    fatal_path = out_dir / "fatal.txt"
    text = fatal_path.read_text(encoding="utf-8", errors="replace")
    assert "ValueError: trace me" in text
    assert "test_capture_fatal_exception_uses_traceback" in text
