import builtins
import sys
from pathlib import Path

import ccl_wrapper


def _block_ccl_imports(monkeypatch) -> None:
    original_import = builtins.__import__

    def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("ccl_chromium_reader"):
            raise ImportError("blocked ccl_chromium_reader")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    for key in list(sys.modules):
        if key.startswith("ccl_chromium_reader"):
            del sys.modules[key]


def _make_logger(tmp_path: Path) -> ccl_wrapper.Logger:
    return ccl_wrapper.Logger(tmp_path / "run.log", verbose=False)


def test_export_local_storage_missing_dir_does_not_require_dependency(tmp_path, monkeypatch) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    _block_ccl_imports(monkeypatch)

    result = ccl_wrapper.export_local_storage(
        None,
        profile_dir,
        out_dir,
        "root",
        "Default",
        _make_logger(tmp_path),
        None,
    )

    assert result["exported"] is False
    assert result["reason"] == "missing_local_storage_leveldb"


def test_export_local_storage_missing_dependency_returns_structured_result(tmp_path, monkeypatch) -> None:
    profile_dir = tmp_path / "profile"
    ls_dir = profile_dir / "Local Storage" / "leveldb"
    ls_dir.mkdir(parents=True)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    _block_ccl_imports(monkeypatch)

    result = ccl_wrapper.export_local_storage(
        None,
        profile_dir,
        out_dir,
        "root",
        "Default",
        _make_logger(tmp_path),
        None,
    )

    assert result["exported"] is False
    assert result["reason"] == "missing_dependency"
    assert result["dependency"] == "ccl_chromium_reader"
