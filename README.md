CCL Chromium Reader Wrapper

This repo contains the code-only wrapper script used to export Chromium artifacts via ccl_chromium_reader.
Private datasets and export outputs are intentionally excluded.

Workflow:
- Codex makes a PR for one roadmap chunk.
- Review PR diff in ChatGPT.
- Pull/merge locally.
- Sync ccl_wrapper.py into runner folder and run acceptance checks against local private dataset.

Recommended runline (PowerShell):
```
$Py = "C:\Users\johnr\Documents\Forensic\ccl\venv\Scripts\python.exe"
& $Py -u -X faulthandler .\ccl_wrapper.py --root "<ROOT>" --out "<OUT>" 2>&1 | Tee-Object -FilePath "<OUT>\console.log"
```

Notes:
- Stderr is captured by Tee-Object; -u/-X faulthandler help preserve tracebacks.
