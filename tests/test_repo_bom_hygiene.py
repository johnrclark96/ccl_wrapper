from pathlib import Path

import ccl_wrapper


def test_repo_files_do_not_start_with_utf8_bom() -> None:
    root = Path(ccl_wrapper.__file__).resolve().parent
    files = [
        root / "ccl_wrapper.py",
        root / ".gitignore",
        root / "README.md",
        root / "ROADMAP.md",
        root / "AGENTS.md",
        root / "requirements-codex.txt",
        root / "tests/test_fatal_capture.py",
        root / "tests/test_smoke_self_check.py",
    ]
    bad = []
    for path in files:
        if path.read_bytes().startswith(b"\xef\xbb\xbf"):
            bad.append(str(path.relative_to(root)))
    assert not bad, f"UTF-8 BOM present in: {bad}"
