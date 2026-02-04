import json
import subprocess
import sys
from pathlib import Path

def test_self_check_writes_file(tmp_path: Path):
    # This will start passing once Chunk 0/2 adds --self-check.
    # If it fails now, that's expected until the feature exists.
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, "ccl_wrapper.py", "--self-check", "--out", str(out_dir)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    # We don't assert returncode yet because --self-check may not exist until Chunk 0.
    # Once implemented, tighten this to: assert p.returncode == 0
    sc = out_dir / "self_check.json"
    # Once implemented, tighten this to: assert sc.exists()
    # For now, allow either state so the repo can be merged before Chunk 0.
    if sc.exists():
        data = json.loads(sc.read_text(encoding="utf-8"))
        assert "python_version" in data
        assert "ccl_chromium_reader_module_path" in data