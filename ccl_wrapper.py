#!/usr/bin/env python3
r"""
run_ccl_chromium_export_merged_v15.py

Max-coverage Chromium (Chrome/Edge) User Data export using ccl_chromium_reader.

Design goals (for forensic review / LLM ingestion):
- Stream outputs (CSV/JSONL) to avoid memory blowups.
- Preserve raw source files (copy key JSON/SQLite) alongside parsed exports.
- Prefer ccl_chromium_reader high-level APIs (ChromiumProfileFolder) where available.
- Include "deleted"/tombstoned records where ccl supports it.
- Produce a single top-level report.md + manifest.json + errors.jsonl summarizing what was extracted.

This script assumes you run it with the Python environment where `ccl_chromium_reader` is installed.

Typical Windows usage (PowerShell), from your User Data folder:
    & "C:\\Users\\johnr\\Documents\\Forensic\\ccl\\venv\\Scripts\\python.exe" `
      "C:\\Users\\johnr\\Documents\\Forensic\\ccl\\run_ccl_chromium_export_merged_v15.py" `
      --root "." --out ".\ccl_reader_export"

Notes:
- Activating the venv is optional if you call the venv python.exe explicitly.
- Default --root is current directory.
"""

from __future__ import annotations

import argparse
import base64
import csv
import inspect
import datetime as _dt
import datetime
import hashlib
import io
import json
import os
import platform
import re
import shutil
import sqlite3
import sys
import threading
import traceback
import tempfile
import time
from collections import Counter
from dataclasses import is_dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

# Needed for localstorage/sessionstorage exporters that reference ccl.*
try:
    import ccl_chromium_reader as ccl  # type: ignore
except Exception:
    ccl = None  # type: ignore

# Optional: shared_proto_db downloads (Chrome 122+ stores downloads in shared_proto_db for some profiles)
try:
    from ccl_chromium_reader import ccl_shared_proto_db_downloads as shared_proto_db_downloads  # type: ignore
except Exception:
    shared_proto_db_downloads = None  # type: ignore




# -----------------------------
# Small utilities
# -----------------------------

_FATAL_OUT_DIR: Optional[Path] = None
_FATAL_ERRORS_PATH: Optional[Path] = None

def utc_now_iso() -> str:
    tz = getattr(_dt, "UTC", _dt.timezone.utc)
    return _dt.datetime.now(tz).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)



def ensure_dir(p: Union[str, Path]) -> Path:
    """Create directory (and parents) if needed; return Path.

    Accepts a directory path as str/Path.
    """
    pp = Path(p)
    safe_mkdir(pp)
    return pp

def write_text(path: Union[str, Path], text: str, *, encoding: str = "utf-8") -> None:
    """Write text to disk (creating parent dirs).

    This wrapper exists because some export stages write small schema/debug files, and we
    want a single, consistent, non-crashy implementation.
    """
    p = Path(path)
    if p.parent:
        safe_mkdir(p.parent)
    # Be tolerant of odd byte sequences in text that's already been decoded upstream.
    p.write_text(text, encoding=encoding, errors="replace")





def iterate_cache_compat(profile_obj: Any, *, decompress: bool = True, omit_cached_data: bool = False):
    '''
    Compatibility wrapper for ChromiumProfileFolder.iterate_cache across ccl_chromium_reader versions.

    Some versions accept decompress= and/or omit_cached_data=; others accept no kwargs.
    We try the richest signature first, then progressively fall back.
    '''
    fn = getattr(profile_obj, "iterate_cache", None)
    if fn is None:
        return iter(())
    kwargs = {}
    try:
        sig = inspect.signature(fn)
        if "decompress" in sig.parameters:
            kwargs["decompress"] = decompress
        if "omit_cached_data" in sig.parameters:
            kwargs["omit_cached_data"] = omit_cached_data
    except Exception:
        kwargs = {"decompress": decompress, "omit_cached_data": omit_cached_data}

    for kw in (kwargs, {"decompress": decompress}, {"omit_cached_data": omit_cached_data}, {}):
        try:
            return fn(**kw) if kw else fn()
        except TypeError:
            continue
    return iter(())

def slug(s: str, max_len: int = 80) -> str:
    s = s.strip()
    s = re.sub(r"[^\w\-. ]+", "_", s, flags=re.UNICODE)
    s = re.sub(r"\s+", "_", s)
    s = s.strip("._")
    if not s:
        return "unnamed"
    return s[:max_len]


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def try_json_loads(s: str) -> Optional[Any]:
    try:
        return json.loads(s)
    except Exception:
        return None


def best_effort_text(b: Union[bytes, bytearray, memoryview], max_len: int = 50_000) -> str:
    """Decode bytes for human readability. Never raises."""
    try:
        if isinstance(b, memoryview):
            b = b.tobytes()
        if isinstance(b, bytearray):
            b = bytes(b)
        if not isinstance(b, (bytes,)):
            return str(b)

        if len(b) > max_len:
            b = b[:max_len]

        # Heuristic: try UTF-8 first, then UTF-16LE.
        for enc in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
            try:
                t = b.decode(enc)
                # quick printable heuristic
                if enc.startswith("utf-16"):
                    return t
                printable = sum(1 for ch in t if (ch == "\n" or ch == "\r" or ch == "\t" or (" " <= ch <= "~")))
                if len(t) == 0:
                    return ""
                if printable / max(1, len(t)) >= 0.85:
                    return t
            except Exception:
                pass

        # fallback: hex preview
        return "0x" + b[:200].hex()
    except Exception:
        return "<decode_error>"


def jsonable(x: Any) -> Any:
    """Convert objects (including bytes, dataclasses, and ccl record objects) into JSON-serializable form."""
    try:
        if x is None:
            return None
        if isinstance(x, (str, int, float, bool)):
            return x
        if isinstance(x, (bytes, bytearray, memoryview)):
            b = x.tobytes() if isinstance(x, memoryview) else (bytes(x) if isinstance(x, bytearray) else x)
            # Keep bytes bounded in JSON outputs; full bytes should live in separate files.
            max_preview = 4096
            preview = b[:max_preview]
            return {
                "_kind": "bytes",
                "len": len(b),
                "sha256": hashlib.sha256(b).hexdigest(),
                "text_preview": best_effort_text(preview, max_len=20_000),
                "b64_preview": __import__("base64").b64encode(preview).decode("ascii"),
                "preview_truncated": len(preview) < len(b),
            }
        if isinstance(x, (list, tuple, set)):
            return [jsonable(v) for v in x]
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                out[str(k)] = jsonable(v)
            return out
        if is_dataclass(x):
            return jsonable(asdict(x))
        # common pattern: ccl objects with attrs
        if hasattr(x, "__dict__"):
            d = {k: v for k, v in vars(x).items() if not k.startswith("_")}
            if d:
                d["_kind"] = type(x).__name__
                return jsonable(d)
        return str(x)
    except Exception:
        return str(x)


def write_json(path: Path, obj: Any) -> None:
    """Write JSON with best-effort conversion so exports never fail on bytes/Path/etc."""
    safe_mkdir(path.parent)
    with path.open("w", encoding="utf-8", errors="replace", newline="\n") as f:
        json.dump(jsonable(obj), f, ensure_ascii=False, indent=2)
        f.write("\n")

def build_self_check() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "python_version": sys.version,
        "sys.executable": sys.executable,
        "sys.prefix": sys.prefix,
        "platform": platform.platform(),
        "ccl_chromium_reader_version": None,
        "ccl_chromium_reader_module_path": None,
        "sys_path_head": list(sys.path[:10]),
    }
    try:
        import importlib.metadata as md
        info["ccl_chromium_reader_version"] = md.version("ccl_chromium_reader")
    except Exception:
        pass
    try:
        import ccl_chromium_reader as ccl_module  # type: ignore
        info["ccl_chromium_reader_module_path"] = getattr(ccl_module, "__file__", None)
    except Exception:
        pass
    return info

def capture_fatal_exception(exc: BaseException, *, out_dir: Optional[Path], errors_path: Optional[Path]) -> int:
    exc_type = type(exc).__name__
    exc_msg = str(exc)
    tb = traceback.format_exc()
    print(f"{exc_type}: {exc_msg}", file=sys.stderr, flush=True)
    print(tb, file=sys.stderr, flush=True)

    fatal_path: Optional[Path] = None
    if out_dir is not None and out_dir.exists():
        fatal_path = out_dir / "fatal.txt"
    else:
        temp_dir = Path(os.getenv("TEMP") or os.getenv("TMPDIR") or tempfile.gettempdir())
        tz = getattr(_dt, "UTC", _dt.timezone.utc)
        timestamp = _dt.datetime.now(tz).strftime("%Y%m%d_%H%M%S")
        fatal_path = temp_dir / f"ccl_fatal_{timestamp}.txt"
        print(f"fatal traceback written to: {fatal_path}", file=sys.stderr, flush=True)

    try:
        write_text(fatal_path, tb)
    except Exception:
        pass

    if errors_path is not None:
        try:
            evt = {
                "stage": "fatal",
                "exc_type": exc_type,
                "exc": exc_msg,
                "traceback": tb,
                "ts": utc_now_iso(),
            }
            with errors_path.open("a", encoding="utf-8", errors="replace", newline="\n") as f:
                f.write(json.dumps(jsonable(evt), ensure_ascii=False) + "\n")
        except Exception:
            pass

    return 2

# -----------------------------
# Smart decode / decompress helpers (foundation)
# -----------------------------

def _csv_cellify(v: Any, *, max_chars: int = 32_000) -> str:
    """
    Convert arbitrary values to a CSV-safe string (bounded).
    NOTE: CSV is a convenience output; JSONL remains canonical.
    """
    try:
        if v is None:
            s = ""
        elif isinstance(v, (bytes, bytearray, memoryview)):
            s = best_effort_text(v)
        elif isinstance(v, (dict, list, tuple, set)):
            s = json.dumps(jsonable(v), ensure_ascii=False)
        else:
            s = str(v)
    except Exception:
        s = "<unprintable>"

    # Remove embedded NULs which can break csv writers on some platforms
    s = s.replace("\x00", "")

    if len(s) > max_chars:
        s = s[: max_chars - 20] + "…[truncated]"
    return s



# --- warning de-duplication (prevents terminal spam on repeated identical failures)
_WARN_ONCE_KEYS = set()

def warn_once(key_parts, message):
    """Print a WARNING message only once per unique key in this run."""
    try:
        key = tuple(key_parts) if isinstance(key_parts, (list, tuple)) else (str(key_parts),)
    except Exception:
        key = (str(key_parts),)
    if key in _WARN_ONCE_KEYS:
        return False
    _WARN_ONCE_KEYS.add(key)
    print(f"WARNING: {message}", flush=True)
    return True

def log_error_event(
    errors_writer: Optional["JsonlWriter"],
    logger: Optional["Logger"],
    *,
    stage: str,
    context: Optional[Dict[str, Any]] = None,
    exc: Optional[BaseException] = None,
) -> None:
    """
    Write a structured error event to errors.jsonl (if available) and emit a one-line WARNING to console.
    This is the foundation for "no silent stage loss."
    """
    evt: Dict[str, Any] = {"ts_utc": utc_now_iso(), "stage": stage}
    if context:
        evt.update(context)
    if exc is not None:
        evt["exc_type"] = type(exc).__name__
        evt["exc"] = str(exc)
        try:
            evt["traceback"] = traceback.format_exc(limit=50)
        except Exception:
            pass

    try:
        if errors_writer is not None:
            errors_writer.write(evt)
    except Exception:
        # If errors writing fails, we still want *some* console signal
        pass

    try:
        if logger is not None:
            # Keep console warning single-line
            msg = f"stage={stage}"
            if exc is not None:
                msg += f" err={type(exc).__name__}: {exc}"
            logger.warn(msg)
    except Exception:
        pass


def stage_wrap(
    stage: str,
    fn,
    *,
    errors_writer: Optional["JsonlWriter"],
    logger: Optional["Logger"],
    context: Optional[Dict[str, Any]] = None,
    default: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute a stage function and guarantee that failures are visible (console + errors.jsonl),
    returning a JSON-serializable dict on failure.
    """
    try:
        res = fn()
        if isinstance(res, dict):
            return res
        return {"exported": True, "result": jsonable(res)}
    except Exception as e:
        log_error_event(errors_writer, logger, stage=stage, context=context, exc=e)
        if default is not None:
            return default
        return {"exported": False, "error": f"{type(e).__name__}: {e}"}


def smart_decode_payload(
    payload: Any,
    *,
    out_dir: Optional[Path] = None,
    limits: Optional[Dict[str, Any]] = None,
    payload_subdir: Optional[Union[str, Path]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Best-effort local decode/decompress/extract for bytes-like payloads.
    Step 1 foundation: safe, bounded, never raises.
    Step 2/3 will integrate this into exporters.
    """
    lim = {
        "max_bytes_to_process": 50_000_000,
        "max_text_chars": 200_000,
        "max_json_chars": 2_000_000,
        "payloads_dir_name": "payloads",
        "decoded_dir_name": "payloads_decoded",
    }
    if limits:
        lim.update(limits)

    info: Dict[str, Any] = {
        "kind": None,
        "raw_len": None,
        "decoded_len": None,
        "transform_chain": [],
        "text_preview": None,
        "json_preview": None,
        "extracted_files": [],
        "notes": [],
        "errors": [],
    }

    try:
        _ = context
        if payload is None:
            info["kind"] = "none"
            return info

        if isinstance(payload, str):
            info["kind"] = "str"
            info["raw_len"] = len(payload)
            s = payload
            if len(s) > lim["max_text_chars"]:
                s = s[: lim["max_text_chars"]] + "…[truncated]"
                info["notes"].append("text_truncated")
            info["text_preview"] = s
            # Try JSON preview
            if s and s.lstrip()[:1] in "{[" and len(s) <= lim["max_json_chars"]:
                try:
                    obj = json.loads(s)
                    info["json_preview"] = json.dumps(obj, ensure_ascii=False)[: lim["max_text_chars"]]
                except Exception:
                    pass
            return info

        # Normalize bytes-like
        b: Optional[bytes] = None
        if isinstance(payload, memoryview):
            b = payload.tobytes()
        elif isinstance(payload, bytearray):
            b = bytes(payload)
        elif isinstance(payload, bytes):
            b = payload
        elif isinstance(payload, (dict, list, tuple)):
            info["kind"] = "json_obj"
            s = json.dumps(jsonable(payload), ensure_ascii=False)
            info["raw_len"] = len(s)
            info["json_preview"] = s[: lim["max_text_chars"]] + ("…[truncated]" if len(s) > lim["max_text_chars"] else "")
            return info
        else:
            info["kind"] = type(payload).__name__
            s = str(payload)
            info["raw_len"] = len(s)
            info["text_preview"] = s[: lim["max_text_chars"]] + ("…[truncated]" if len(s) > lim["max_text_chars"] else "")
            return info

        info["kind"] = "bytes"
        info["raw_len"] = len(b)

        # Bound processing
        if len(b) > lim["max_bytes_to_process"]:
            b = b[: lim["max_bytes_to_process"]]
            info["notes"].append("bytes_prefix_only")

        # Write raw payload if requested
        sub = Path(payload_subdir) if payload_subdir else None
        if out_dir is not None:
            try:
                raw_dir = out_dir / lim["payloads_dir_name"]
                if sub is not None:
                    raw_dir = raw_dir / sub
                ensure_dir(raw_dir)
                h = hashlib.sha256(b).hexdigest()
                raw_path = raw_dir / f"{h}.bin"
                if not raw_path.exists():
                    raw_path.write_bytes(b)
                info["extracted_files"].append(str(raw_path))
            except Exception as e:
                info["errors"].append(f"write_raw_failed: {type(e).__name__}: {e}")

        # Attempt simple decompress by magic bytes (gzip, zlib-ish, zip)
        data = b
        try:
            import gzip, zlib, zipfile  # stdlib
            if data[:2] == b"\x1f\x8b":
                info["transform_chain"].append("gzip")
                data = gzip.decompress(data)
            elif len(data) >= 2 and data[0] == 0x78 and data[1] in (0x01, 0x9C, 0xDA):
                info["transform_chain"].append("zlib")
                data = zlib.decompress(data)
            elif data[:2] == b"PK":
                info["transform_chain"].append("zip_detected")
                # For Step 1, we won't auto-extract members yet; just note.
                info["notes"].append("zip_detected_not_extracted_step1")
        except Exception as e:
            info["errors"].append(f"decompress_failed: {type(e).__name__}: {e}")

        info["decoded_len"] = len(data) if isinstance(data, (bytes, bytearray)) else None

        # Write decoded bytes
        if out_dir is not None and isinstance(data, (bytes, bytearray)) and data != b:
            try:
                dec_dir = out_dir / lim["decoded_dir_name"]
                if sub is not None:
                    dec_dir = dec_dir / sub
                ensure_dir(dec_dir)
                h = hashlib.sha256(data).hexdigest()
                dec_path = dec_dir / f"{h}.bin"
                if not dec_path.exists():
                    dec_path.write_bytes(bytes(data))
                info["extracted_files"].append(str(dec_path))
            except Exception as e:
                info["errors"].append(f"write_decoded_failed: {type(e).__name__}: {e}")

        # Text preview heuristic
        try:
            preview = best_effort_text(data, max_len=lim["max_text_chars"])
            info["text_preview"] = preview
            if preview and preview.lstrip()[:1] in "{[" and len(preview) <= lim["max_json_chars"]:
                try:
                    obj = json.loads(preview)
                    info["json_preview"] = json.dumps(obj, ensure_ascii=False)[: lim["max_text_chars"]]
                except Exception:
                    pass
        except Exception:
            pass

        return info

    except Exception as e:
        # Never raise; return minimal failure info
        info["errors"].append(f"smart_decode_failed: {type(e).__name__}: {e}")
        return info


class JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        safe_mkdir(path.parent)
        self.f = path.open("w", encoding="utf-8", errors="replace", newline="\n")
        self.count = 0

    def write(self, obj: Any) -> None:
        self.f.write(json.dumps(jsonable(obj), ensure_ascii=False) + "\n")
        self.count += 1

    def write_row(self, obj: Any) -> None:
        # Compatibility alias for older call sites
        self.write(obj)

    def flush(self) -> None:
        try:
            self.f.flush()
        except Exception:
            pass

    def close(self) -> None:
        self.flush()
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class CsvWriter:
    def __init__(self, path: Path, fieldnames: List[str], *, max_cell_chars: int = 32_000):
        self.path = path
        self.fieldnames = fieldnames
        self.max_cell_chars = int(max_cell_chars)
        safe_mkdir(path.parent)
        self.f = path.open("w", encoding="utf-8", errors="replace", newline="")
        self.w = csv.DictWriter(
            self.f,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
            quotechar='"',
            doublequote=True,
            escapechar="\\",
            lineterminator="\n",
        )
        self.w.writeheader()
        self.count = 0
        self.row_errors = 0

    def write(self, row: Dict[str, Any]) -> None:
        # Convert all values to bounded strings.
        out = {k: _csv_cellify(row.get(k), max_chars=self.max_cell_chars) for k in self.fieldnames}
        try:
            self.w.writerow(out)
            self.count += 1
        except Exception:
            # Last-ditch sanitize: drop NULs and force str() for everything.
            try:
                out2 = {k: str(out.get(k, "")).replace("\x00", "") for k in self.fieldnames}
                self.w.writerow(out2)
                self.count += 1
                self.row_errors += 1
            except Exception:
                # Skip row (CSV is best-effort). JSONL remains canonical.
                self.row_errors += 1

    def write_row(self, row: Dict[str, Any]) -> None:
        # Backwards-compatible alias; some call sites use write_row(...)
        self.write(row)

    def close(self) -> None:
        try:
            self.f.flush()
        finally:
            self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


# -----------------------------
# Logging + heartbeat
# -----------------------------

class Logger:
    def __init__(self, log_path: Path, verbose: bool = True, warn_limit: int = 25):
        self.log_path = log_path
        safe_mkdir(log_path.parent)
        self._lock = threading.Lock()
        self.verbose = verbose
        self.warn_limit = int(warn_limit) if warn_limit is not None else 25
        self._warn_counts = Counter()
        self._last = ""
        self._start = time.time()
        with log_path.open("w", encoding="utf-8", errors="replace", newline="\n") as f:
            f.write(f"[{utc_now_iso()}] start\n")

    def info(self, msg: str) -> None:
        line = f"[{utc_now_iso()}] {msg}"
        with self._lock:
            self._last = msg
            with self.log_path.open("a", encoding="utf-8", errors="replace", newline="\n") as f:
                f.write(line + "\n")
        if self.verbose:
            print(line, flush=True)

    def notice(self, msg: str) -> None:
        """Always print to console (and write to run log), regardless of verbose."""
        line = f"[{utc_now_iso()}] {msg}"
        with self._lock:
            self._last = msg
            with self.log_path.open("a", encoding="utf-8", errors="replace", newline="\n") as f:
                f.write(line + "\n")
        print(line, flush=True)

    def log(self, msg: str) -> None:
        # Compatibility alias; some code uses logger.log(...)
        self.info(str(msg))

    def warn(self, msg: str) -> None:
        """Write warning to run_log; print to console with rate-limiting to avoid spam."""
        line = f"[{utc_now_iso()}] WARNING: {msg}"
        with self._lock:
            self._last = f"WARNING: {msg}"
            with self.log_path.open("a", encoding="utf-8", errors="replace", newline="\n") as f:
                f.write(line + "\n")

        # warn_limit semantics:
        #   -1 => never suppress
        #    0 => suppress all console warning lines
        #   >0 => print at most N times per unique warning message (+1 extra note when suppression starts)
        key = msg
        self._warn_counts[key] += 1
        n = self._warn_counts[key]

        if self.warn_limit == -1:
            print(line, flush=True)
            return
        if self.warn_limit == 0:
            return
        if n <= self.warn_limit:
            print(line, flush=True)
            return
        if n == self.warn_limit + 1:
            print(f"[{utc_now_iso()}] WARNING: (suppressed further repeats of this warning) {msg}", flush=True)

    def warning(self, msg: str) -> None:
        self.warn(msg)

    def error(self, msg: str) -> None:
        line = f"[{utc_now_iso()}] ERROR: {msg}"
        with self._lock:
            self._last = f"ERROR: {msg}"
            with self.log_path.open("a", encoding="utf-8", errors="replace", newline="\n") as f:
                f.write(line + "\n")
        print(line, flush=True)

    def debug(self, msg: str) -> None:
        if self.verbose:
            self.info(f"DEBUG: {msg}")

    def last(self) -> str:
        with self._lock:
            return self._last

    def seconds_running(self) -> int:
        return int(time.time() - self._start)


class Heartbeat(threading.Thread):
    def __init__(self, logger: Logger, interval_s: int):
        super().__init__(daemon=True)
        self.logger = logger
        self.interval_s = max(1, int(interval_s))
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.interval_s)
            try:
                self.logger.info(f"heartbeat: t+{self.logger.seconds_running()}s last='{self.logger.last()}'")
            except Exception:
                pass


# -----------------------------
# Discovery helpers
# -----------------------------

PROFILE_MARKERS = [
    "History",
    "Preferences",
    "Bookmarks",
    "IndexedDB",
    "Local Storage",
    "Session Storage",
    "Service Worker",
]

ROOT_MARKERS = [
    "Local State",
    "First Run",
    "Last Version",
]

def looks_like_user_data_root(p: Path) -> bool:
    if not p.is_dir():
        return False
    for m in ROOT_MARKERS:
        if (p / m).exists():
            return True
    return False


def discover_user_data_roots(root: Path, logger: logging.Logger) -> List[Path]:
    """Discover one or more Chromium *user-data* roots under the provided path.

    Accepts either:
      - a direct user-data root (contains 'Local State' and profiles like 'Default'), OR
      - a container directory whose immediate children include a user-data root (e.g. 'User Data' or 'User_Data').

    Also includes any versioned roots found under '<root>/Snapshots/*' when present.
    """
    root = Path(root).expanduser()

    # Guard rails: avoid confusing "0 roots" runs when the caller forgets to set $Root,
    # or uses the placeholder path from examples.
    root_str = str(root)
    if (not root_str.strip()) or ("Path\\To\\Chrome\\User Data" in root_str) or ("Path\\To\\Chrome\\User_Data" in root_str):
        logger.error(f"FATAL: invalid --root value: {root!s}")
        return []

    if not root.exists():
        logger.error(f"FATAL: --root does not exist: {root!s}")
        return []

    try:
        root = root.resolve()
    except Exception:
        # If resolve fails (permissions, odd paths), continue with the raw path.
        pass

    candidates: List[Path] = []

    # Direct root
    if looks_like_user_data_root(root):
        candidates.append(root)

    # Common child folder names (space vs underscore)
    for name in ("User Data", "User_Data"):
        cand = root / name
        if looks_like_user_data_root(cand):
            candidates.append(cand)

    # If the user passed a container directory, scan immediate children for roots.
    if not candidates:
        try:
            for child in root.iterdir():
                if child.is_dir() and looks_like_user_data_root(child):
                    candidates.append(child)
        except Exception as e:
            logger.warning(f"Root child-scan failed for {root!s}: {type(e).__name__}: {e}")

    roots_set = set()

    for base in candidates:
        roots_set.add(base)
        snap_dir = base / "Snapshots"
        if snap_dir.is_dir():
            try:
                for ver in sorted(snap_dir.iterdir(), key=lambda p: p.name):
                    if ver.is_dir() and looks_like_user_data_root(ver):
                        roots_set.add(ver)
            except Exception as e:
                logger.warning(f"Snapshots scan failed for {snap_dir!s}: {type(e).__name__}: {e}")

    uniq = sorted(roots_set, key=lambda p: str(p).lower())

    logger.info(f"discovered {len(uniq)} user-data root(s)")
    for r in uniq:
        logger.info(f"  root: {r}")

    return uniq


def discover_profile_dirs(user_data_root: Path, logger: Logger) -> List[Path]:
    """
    A profile dir is any immediate child directory that contains at least one profile marker.
    """
    out: List[Path] = []
    if not user_data_root.is_dir():
        return out
    for child in sorted(user_data_root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.lower() in ("shadercache", "safebrowsing", "crashpad", "snapshots"):
            continue

        # Only consider real Chromium profile directories, not companion "* files" folders or other artifacts.
        n = child.name
        if not (
            n == "Default"
            or re.match(r"^Profile \d+$", n)
            or n in ("Guest Profile", "System Profile")
        ):
            continue
        # markers
        for m in PROFILE_MARKERS:
            if (child / m).exists():
                out.append(child)
                break

    logger.info(f"found {len(out)} profile folder(s) in {user_data_root}")
    for p in out:
        logger.info(f"  profile: {p.name} ({p})")
    return out


def tag_for_root(user_data_root: Path, main_root: Path) -> str:
    """
    Tag for the root directory to keep outputs separated.
    """
    try:
        rel = user_data_root.relative_to(main_root.resolve())
        rel_s = str(rel).replace("\\", "/")
        return slug(rel_s) if rel_s else "root"
    except Exception:
        # If it isn't under main_root, fallback to last part(s)
        return slug(user_data_root.name)


# -----------------------------
# Export functions
# -----------------------------

def copy_if_exists(src: Path, dst: Path, logger: Logger) -> bool:
    try:
        if src.exists() and src.is_file():
            safe_mkdir(dst.parent)
            shutil.copy2(src, dst)
            logger.info(f"copied: {src} -> {dst}")
            return True
    except Exception as e:
        logger.info(f"copy failed: {src} -> {dst} ({e})")
    return False


def export_json_file(src: Path, out_dir: Path, logger: Logger, *, name: str) -> Dict[str, Any]:
    """
    Copies a JSON file and also writes a pretty-printed version + small extracts.
    """
    res: Dict[str, Any] = {"name": name, "src": str(src), "copied": False, "parsed": False}
    raw_copy = out_dir / f"{name}.raw.json"
    pretty = out_dir / f"{name}.pretty.json"
    extract = out_dir / f"{name}.extract.json"
    try:
        if not src.exists():
            res["missing"] = True
            return res
        safe_mkdir(out_dir)
        shutil.copy2(src, raw_copy)
        res["copied"] = True

        data = json.loads(src.read_text(encoding="utf-8", errors="replace"))
        res["parsed"] = True
        write_json(pretty, data)

        # small extract: keep only top-level keys + a few known interesting branches if present
        keep: Dict[str, Any] = {"_keys": sorted(list(data.keys()))}
        for k in ("profile", "account_info", "browser", "signin", "user_experience_metrics"):
            if k in data:
                keep[k] = data[k]
        write_json(extract, keep)
        return res
    except Exception as e:
        res["error"] = str(e)
        logger.info(f"export_json_file failed for {src}: {e}")
        return res


def export_root_artifacts(user_data_root: Path, out_root: Path, logger: Logger) -> Dict[str, Any]:
    """
    Root-level artifacts (Local State, Last Version, etc).
    """
    res: Dict[str, Any] = {"root": str(user_data_root), "artifacts": []}
    root_files = [
        ("local_state", user_data_root / "Local State"),
        ("last_version", user_data_root / "Last Version"),
        ("first_run", user_data_root / "First Run"),
    ]
    out_dir = out_root / "root_files"
    safe_mkdir(out_dir)

    for name, src in root_files:
        if src.exists() and src.is_file():
            if name == "local_state":
                res["artifacts"].append(export_json_file(src, out_dir, logger, name=name))
            else:
                copied = copy_if_exists(src, out_dir / f"{name}.raw", logger)
                res["artifacts"].append({"name": name, "src": str(src), "copied": copied})
        else:
            res["artifacts"].append({"name": name, "src": str(src), "missing": True})

    # Extract Local State accounts summary (if present)
    try:
        ls = user_data_root / "Local State"
        if ls.exists():
            data = json.loads(ls.read_text(encoding="utf-8", errors="replace"))
            rows = []

            # profile.info_cache
            info_cache = (data.get("profile") or {}).get("info_cache") or {}
            if isinstance(info_cache, dict):
                for prof_path, obj in info_cache.items():
                    if not isinstance(obj, dict):
                        continue
                    rows.append({
                        "source": "profile.info_cache",
                        "profile_path": prof_path,
                        "name": obj.get("name"),
                        "gaia_name": obj.get("gaia_name"),
                        "user_name": obj.get("user_name") or obj.get("username"),
                        "gaia_id": obj.get("gaia_id"),
                        "email": obj.get("email"),
                        "is_ephemeral": obj.get("is_ephemeral"),
                    })

            # account_info (structure varies)
            acct = data.get("account_info")
            if isinstance(acct, list):
                for obj in acct:
                    if isinstance(obj, dict):
                        rows.append({
                            "source": "account_info[]",
                            "profile_path": "",
                            "name": obj.get("full_name") or obj.get("given_name"),
                            "gaia_name": obj.get("full_name") or obj.get("given_name"),
                            "user_name": obj.get("email"),
                            "gaia_id": obj.get("gaia_id") or obj.get("account_id"),
                            "email": obj.get("email"),
                            "is_ephemeral": "",
                        })

            if rows:
                csv_path = out_dir / "local_state_accounts.csv"
                with CsvWriter(csv_path, ["source", "profile_path", "name", "gaia_name", "user_name", "gaia_id", "email", "is_ephemeral"]) as cw:
                    for r in rows:
                        cw.write(r)
                res["local_state_accounts_csv"] = str(csv_path)

    except Exception as e:
        logger.info(f"Local State account extract failed: {e}")
        res["local_state_accounts_error"] = str(e)

    return res


def connect_sqlite_readonly(sqlite_path: Path) -> sqlite3.Connection:
    # Use URI read-only; works for normal files. If it fails, fallback to normal connect.
    try:
        uri = f"file:{sqlite_path.as_posix()}?mode=ro"
        return sqlite3.connect(uri, uri=True)
    except Exception:
        return sqlite3.connect(str(sqlite_path))


def export_history_sqlite(history_db: Path, out_dir: Path, logger: "Logger", *, export_all_tables: bool = False) -> Dict[str, Any]:
    """
    Export selected tables (or all tables) from a Chrome/Chromium History SQLite DB.

    Notes on robustness:
    - Some History DBs (especially snapshot copies) contain invalid UTF-8 in TEXT columns
      (commonly in tables like `meta` and `history_sync_metadata`). The default sqlite3
      text decoding will raise and abort a whole table export.
    - To preserve maximum evidence, we open with `text_factory=bytes` and then decode
      per-cell when it looks like text; otherwise we store `base64:<...>`.

    Output:
    - <table>.csv  (rows)
    - <table>_schema.json  (PRAGMA table_info)
    """
    safe_mkdir(out_dir)
    res: Dict[str, Any] = {"history": {"exported": False, "tables": [], "tables_exported": [], "tables_failed": []}}

    # Tables that tend to be investigator-useful (plus some metadata)
    keep_tables = {
        "urls",
        "visits",
        "visit_source",
        "downloads",
        "downloads_url_chains",
        "segments",
        "segment_usage",
        "typed_url_sync_metadata",
        "keyword_search_terms",
        "keywords",
        "clusters",
        "cluster_keywords",
        "clusters_and_visits",
        "cluster_visit_duplicates",
        "history_sync_metadata",
        "meta",
    }

    def _printable_ratio(s: str) -> float:
        if not s:
            return 0.0
        # Keep it cheap and bounded
        sample = s[:2000]
        printable = sum(1 for ch in sample if (32 <= ord(ch) <= 126) or ch in "\r\n\t")
        return printable / max(1, len(sample))

    def _decode_bytes(b: bytes) -> str | None:
        if not b:
            return ""
        # Try UTF-8 first; if it looks bad, try UTF-16; otherwise fall back to base64.
        for enc in ("utf-8", "utf-16le", "utf-16be"):
            try:
                s = b.decode(enc)
            except Exception:
                continue
            # Reject obvious garbage
            if "\x00" in s:
                continue
            if _printable_ratio(s) >= 0.70:
                return s
        return None

    def _cell(v: Any) -> Any:
        if v is None:
            return ""
        if isinstance(v, (int, float, bool)):
            return v
        if isinstance(v, (datetime.datetime, datetime.date)):
            return v.isoformat()
        if isinstance(v, bytes):
            s = _decode_bytes(v)
            if s is not None:
                return s
            return "base64:" + base64.b64encode(v).decode("ascii")
        # Some drivers can return memoryview; normalize
        if isinstance(v, memoryview):
            vb = bytes(v)
            s = _decode_bytes(vb)
            if s is not None:
                return s
            return "base64:" + base64.b64encode(vb).decode("ascii")
        return str(v)

    try:
        conn = connect_sqlite_readonly(history_db)
        # Avoid sqlite3 UnicodeDecodeError on malformed TEXT; we'll decode per-cell.
        conn.text_factory = bytes
        cur = conn.cursor()

        def _tname(x: Any) -> str:
            if isinstance(x, (bytes, bytearray, memoryview)):
                return bytes(x).decode("utf-8", errors="replace")
            return str(x)

        raw_tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        tables = [_tname(t) for t in raw_tables]
        res["history"]["tables"] = tables

        selected = tables if export_all_tables else [t for t in tables if t in keep_tables]

        for t in selected:
            out_csv = out_dir / f"{t}.csv"
            out_schema = out_dir / f"{t}_schema.json"

            try:
                # Schema
                tq = t.replace('"', '""')
                schema_rows = cur.execute(f'PRAGMA table_info("{tq}")').fetchall()
                schema = []
                for r in schema_rows:
                    schema.append(
                        {
                            "cid": r[0],
                            "name": _tname(r[1]),
                            "type": _tname(r[2]),
                            "notnull": r[3],
                            "dflt_value": _tname(r[4]) if r[4] is not None else None,
                            "pk": r[5],
                        }
                    )
                write_text(out_schema, json.dumps(schema, ensure_ascii=False, indent=2))

                # Rows
                colnames = [c["name"] for c in schema]
                with out_csv.open("w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
                    w.writerow(colnames)

                    q = f'SELECT * FROM "{tq}"'
                    for row in cur.execute(q):
                        # row is a tuple; write as-is (decoded per cell)
                        w.writerow([_cell(v) for v in row])

                res["history"]["tables_exported"].append(t)
            except Exception as e:
                res["history"]["tables_failed"].append({"table": t, "error": str(e)})
                logger.warn(f"History export failed for table {t}: {e}")

        res["history"]["exported"] = True
    except Exception as e:
        res["history"]["error"] = str(e)
        logger.warn(f"History export failed: {e}")
    finally:
        try:
            conn.close()  # type: ignore[name-defined]
        except Exception:
            pass

    return res



# -----------------------------
# Profile inventory + JSON artifact copying (for local human review)
# -----------------------------

def _ts_to_utc_iso(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    try:
        return _dt.datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"
    except Exception:
        return ""


def export_profile_files_inventory(
    prof_dir: Path,
    profile_out_dir: Path,
    logger: Logger,
    errors_writer: Optional[JsonlWriter] = None,
) -> Dict[str, Any]:
    """Emit a stat-only inventory of the entire profile folder (no content reads)."""
    out_dir = profile_out_dir / "inventory"
    ensure_dir(out_dir)
    jsonl_path = out_dir / "inventory.jsonl"
    csv_path = out_dir / "inventory.csv"

    fieldnames = [
        "profile_name",
        "profile_path",
        "rel_path",
        "abs_path",
        "is_file",
        "is_dir",
        "size_bytes",
        "mtime_utc",
        "ctime_utc",
        "atime_utc",
    ]

    rows = 0
    errs = 0

    def _emit_err(stage: str, path: Path, exc: Exception) -> None:
        nonlocal errs
        errs += 1
        ev = {
            "stage": stage,
            "profile_name": prof_dir.name,
            "profile_path": str(prof_dir),
            "path": str(path),
            "error": f"{type(exc).__name__}: {exc}",
        }
        if errors_writer is not None:
            try:
                errors_writer.write(ev)
            except Exception:
                pass
        logger.warn(f"stage={stage} profile={prof_dir.name} path={path} err={type(exc).__name__}: {exc}")

    try:
        with JsonlWriter(jsonl_path) as jw, CsvWriter(csv_path, fieldnames) as cw:
            # Include the root itself
            for root, dirnames, filenames in os.walk(str(prof_dir)):
                root_p = Path(root)
                # record the directory itself
                try:
                    st = root_p.stat()
                    rel = root_p.relative_to(prof_dir)
                    row = {
                        "profile_name": prof_dir.name,
                        "profile_path": str(prof_dir),
                        "rel_path": str(rel) if str(rel) else ".",
                        "abs_path": str(root_p),
                        "is_file": False,
                        "is_dir": True,
                        "size_bytes": 0,
                        "mtime_utc": _ts_to_utc_iso(getattr(st, "st_mtime", None)),
                        "ctime_utc": _ts_to_utc_iso(getattr(st, "st_ctime", None)),
                        "atime_utc": _ts_to_utc_iso(getattr(st, "st_atime", None)),
                    }
                    jw.write(row)
                    cw.write(row)
                    rows += 1
                except Exception as e:
                    _emit_err("inventory_stat_failed", root_p, e)

                # record files in this directory
                for fn in filenames:
                    p = root_p / fn
                    try:
                        st = p.stat()
                        rel = p.relative_to(prof_dir)
                        row = {
                            "profile_name": prof_dir.name,
                            "profile_path": str(prof_dir),
                            "rel_path": str(rel),
                            "abs_path": str(p),
                            "is_file": True,
                            "is_dir": False,
                            "size_bytes": int(getattr(st, "st_size", 0) or 0),
                            "mtime_utc": _ts_to_utc_iso(getattr(st, "st_mtime", None)),
                            "ctime_utc": _ts_to_utc_iso(getattr(st, "st_ctime", None)),
                            "atime_utc": _ts_to_utc_iso(getattr(st, "st_atime", None)),
                        }
                        jw.write(row)
                        cw.write(row)
                        rows += 1
                    except Exception as e:
                        _emit_err("inventory_stat_failed", p, e)
    except Exception as e:
        _emit_err("inventory_failed", prof_dir, e)
        return {"exported": False, "rows": rows, "errors": errs, "jsonl": str(jsonl_path), "csv": str(csv_path), "error": str(e)}

    return {"exported": True, "rows": rows, "errors": errs, "jsonl": str(jsonl_path), "csv": str(csv_path)}


def export_profile_json_files(
    prof_dir: Path,
    out_dir: Path,
    logger: Logger,
    errors_writer: Optional[JsonlWriter] = None,
) -> Dict[str, Any]:
    """Copy targeted, high-signal JSON/text artifacts for local human review."""
    ensure_dir(out_dir)
    copied_dir = out_dir / "copied"
    ensure_dir(copied_dir)

    jsonl_path = out_dir / "json_files.jsonl"
    csv_path = out_dir / "json_files.csv"
    fieldnames = ["src_path", "dst_path", "rel_path", "size_bytes", "sha256", "copied_ok", "error"]

    # Build candidate list (targeted)
    candidates: List[Path] = []
    for name in ["Preferences", "Secure Preferences", "Bookmarks", "Bookmarks.bak"]:
        p = prof_dir / name
        if p.exists() and p.is_file():
            candidates.append(p)

    # Any *.json at profile root
    try:
        for p in prof_dir.glob("*.json"):
            if p.is_file():
                candidates.append(p)
    except Exception:
        pass

    # Extension manifests: Extensions/<extid>/<version>/manifest.json
    ext_root = prof_dir / "Extensions"
    if ext_root.exists() and ext_root.is_dir():
        try:
            for extid_dir in ext_root.iterdir():
                if not extid_dir.is_dir():
                    continue
                for ver_dir in extid_dir.iterdir():
                    if not ver_dir.is_dir():
                        continue
                    man = ver_dir / "manifest.json"
                    if man.exists() and man.is_file():
                        candidates.append(man)
        except Exception:
            pass

    # De-dupe (preserve order)
    seen = set()
    uniq: List[Path] = []
    for c in candidates:
        s = str(c)
        if s in seen:
            continue
        seen.add(s)
        uniq.append(c)

    rows = 0
    errs = 0

    def _emit_err(stage: str, src: Path, exc: Exception) -> None:
        nonlocal errs
        errs += 1
        ev = {
            "stage": stage,
            "profile_name": prof_dir.name,
            "profile_path": str(prof_dir),
            "src": str(src),
            "error": f"{type(exc).__name__}: {exc}",
        }
        if errors_writer is not None:
            try:
                errors_writer.write(ev)
            except Exception:
                pass
        logger.warn(f"stage={stage} profile={prof_dir.name} src={src} err={type(exc).__name__}: {exc}")

    try:
        with JsonlWriter(jsonl_path) as jw, CsvWriter(csv_path, fieldnames) as cw:
            for src in uniq:
                rel = ""
                try:
                    rel = str(src.relative_to(prof_dir))
                except Exception:
                    rel = src.name
                dst = copied_dir / rel
                try:
                    ensure_dir(dst.parent)
                    shutil.copy2(str(src), str(dst))
                    size = 0
                    try:
                        size = int(dst.stat().st_size)
                    except Exception:
                        pass
                    sha = ""
                    try:
                        sha = sha256_file(dst)
                    except Exception:
                        sha = ""
                    row = {
                        "src_path": str(src),
                        "dst_path": str(dst),
                        "rel_path": rel,
                        "size_bytes": size,
                        "sha256": sha,
                        "copied_ok": True,
                        "error": "",
                    }
                    jw.write(row)
                    cw.write(row)
                    rows += 1
                except Exception as e:
                    _emit_err("json_file_copy_failed", src, e)
                    row = {
                        "src_path": str(src),
                        "dst_path": str(dst),
                        "rel_path": rel,
                        "size_bytes": "",
                        "sha256": "",
                        "copied_ok": False,
                        "error": f"{type(e).__name__}: {e}",
                    }
                    try:
                        jw.write(row)
                        cw.write(row)
                    except Exception:
                        pass
                    rows += 1
    except Exception as e:
        _emit_err("json_files_failed", prof_dir, e)
        return {"exported": False, "rows": rows, "errors": errs, "jsonl": str(jsonl_path), "csv": str(csv_path), "error": str(e)}

    return {"exported": True, "rows": rows, "errors": errs, "jsonl": str(jsonl_path), "csv": str(csv_path), "copied_dir": str(copied_dir)}


def export_downloads(profile_obj: Any, prof_dir: Path, profile_out_dir: Path, root_tag: str, profile_name: str,
                     logger: Logger, errors_writer: Optional[JsonlWriter]) -> None:
    """Export downloads with maximum coverage.

    Strategy:
      1) Prefer ccl_chromium_reader high-level iterators when they work.
      2) If the shared-proto downloads DB is missing (common in snapshot/partial profiles), fall back to History SQLite.
    """
    out_dir = ensure_dir(profile_out_dir / "downloads")
    jw = JsonlWriter(out_dir / "downloads.jsonl")
    cw = CsvWriter(out_dir / "downloads.csv", fieldnames=[
        "root_tag", "profile_name",
        "start_time_utc", "end_time_utc",
        "url", "tab_url", "referrer",
        "target_path", "current_path",
        "total_bytes", "received_bytes",
        "state", "danger_type", "interrupt_reason",
        "opened", "by_ext_id", "by_ext_name",
        "source", "notes"
    ])

    def _chrome_time_1601us_to_iso(val: Any) -> Optional[str]:
        # Chrome/WebKit time: microseconds since 1601-01-01 UTC
        try:
            if val is None:
                return None
            if isinstance(val, bool):
                return None
            x = int(val)
            if x <= 0:
                return None
            base = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            dt = base + datetime.timedelta(microseconds=x)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            return None

    def _dt_to_iso(val: Any) -> Optional[str]:
        try:
            if val is None:
                return None
            if isinstance(val, str):
                return val
            if isinstance(val, datetime.datetime):
                if val.tzinfo is None:
                    val = val.replace(tzinfo=datetime.timezone.utc)
                return val.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            return None
        except Exception:
            return None

    def _iter_downloads_history_sqlite() -> Iterator[Dict[str, Any]]:
        history = prof_dir / "History"
        if not history.is_file():
            return iter(())
        # Copy to temp to avoid locking issues
        tmp = out_dir / f"_History_{history.stat().st_size}.sqlite"
        try:
            shutil.copy2(history, tmp)
        except Exception:
            tmp = history
        try:
            conn = sqlite3.connect(str(tmp))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Column discovery
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}
            if "downloads" not in tables:
                return iter(())
            cur.execute("PRAGMA table_info(downloads)")
            cols = [r[1] for r in cur.fetchall()]
            colset = set(cols)

            url_map: Dict[int, str] = {}
            if "downloads_url_chains" in tables and {"id", "chain_index", "url"}.issubset(
                {c for c in ["id", "chain_index", "url"]}):
                # best-effort: last chain_index per id
                try:
                    cur.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index")
                    for r in cur.fetchall():
                        url_map[int(r["id"])] = r["url"]
                except Exception:
                    pass

            cur.execute("SELECT * FROM downloads")
            for r in cur.fetchall():
                rid = None
                try:
                    rid = int(r["id"]) if "id" in colset else None
                except Exception:
                    rid = None
                url = None
                if rid is not None and rid in url_map:
                    url = url_map[rid]
                # other URL-ish fields seen in some schemas
                for k in ["tab_url", "referrer", "site_url", "url"]:
                    if url is None and k in colset:
                        v = r[k]
                        if isinstance(v, str) and v:
                            url = v
                yield {
                    "_source": "history_sqlite",
                    "id": rid,
                    "start_time_utc": _chrome_time_1601us_to_iso(r["start_time"]) if "start_time" in colset else None,
                    "end_time_utc": _chrome_time_1601us_to_iso(r["end_time"]) if "end_time" in colset else None,
                    "url": url,
                    "tab_url": r["tab_url"] if "tab_url" in colset else None,
                    "referrer": r["referrer"] if "referrer" in colset else None,
                    "target_path": r["target_path"] if "target_path" in colset else None,
                    "current_path": r["current_path"] if "current_path" in colset else None,
                    "total_bytes": r["total_bytes"] if "total_bytes" in colset else None,
                    "received_bytes": r["received_bytes"] if "received_bytes" in colset else None,
                    "state": r["state"] if "state" in colset else None,
                    "danger_type": r["danger_type"] if "danger_type" in colset else None,
                    "interrupt_reason": r["interrupt_reason"] if "interrupt_reason" in colset else None,
                    "opened": r["opened"] if "opened" in colset else None,
                    "by_ext_id": r["by_ext_id"] if "by_ext_id" in colset else None,
                    "by_ext_name": r["by_ext_name"] if "by_ext_name" in colset else None,
                }
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _iter_downloads_shared_proto_db() -> Iterator[Any]:
        # Returns an iterator of download objects from shared_proto_db, if available.
        if shared_proto_db_downloads is None:
            return iter(())
        shared_dir = prof_dir / "shared_proto_db"
        if not (shared_dir.exists() and shared_dir.is_dir()):
            return iter(())

        if hasattr(shared_proto_db_downloads, "read_downloads"):
            try:
                return shared_proto_db_downloads.read_downloads(str(shared_dir))
            except Exception:
                return iter(())

        if hasattr(shared_proto_db_downloads, "OpenDownloadsDb"):
            def _gen():
                for open_arg in (shared_dir, prof_dir):
                    try:
                        db = shared_proto_db_downloads.OpenDownloadsDb(str(open_arg))
                        for d in db.iter_downloads():
                            yield d
                        return
                    except Exception:
                        continue
            return _gen()

        return iter(())

    def _call_download_iterator(fn: Any) -> Iterator[Any]:
        # Some ccl versions expect in_dir/profile_dir; feature-detect.
        try:
            return fn()
        except TypeError:
            try:
                return fn(prof_dir)
            except Exception:
                raise

    def _normalize_download_obj(d: Any, source: str) -> Dict[str, Any]:
        # Works with dict-like or object-like download records.
        get = (lambda k, default=None: d.get(k, default)) if isinstance(d, dict) else (lambda k, default=None: getattr(d, k, default))

        url = get("url") or get("original_url") or get("tab_url") or get("referrer")
        row = {
            "root_tag": root_tag,
            "profile_name": profile_name,
            "start_time_utc": _dt_to_iso(get("start_time")) or _chrome_time_1601us_to_iso(get("start_time")) or _dt_to_iso(get("start_time_utc")) or get("start_time_utc"),
            "end_time_utc": _dt_to_iso(get("end_time")) or _chrome_time_1601us_to_iso(get("end_time")) or _dt_to_iso(get("end_time_utc")) or get("end_time_utc"),
            "url": url,
            "tab_url": get("tab_url"),
            "referrer": get("referrer"),
            "target_path": str(get("target_path")) if get("target_path") is not None else None,
            "current_path": str(get("current_path")) if get("current_path") is not None else None,
            "total_bytes": get("total_bytes") or get("total_bytes_long") or get("total_bytes_int"),
            "received_bytes": get("received_bytes") or get("received_bytes_long") or get("received_bytes_int"),
            "state": get("state"),
            "danger_type": get("danger_type") or get("danger"),
            "interrupt_reason": get("interrupt_reason") or get("interrupt"),
            "opened": get("opened"),
            "by_ext_id": get("by_ext_id"),
            "by_ext_name": get("by_ext_name"),
            "source": source,
            "notes": None,
        }
        return row

    try:
        rows_written = 0

        # Candidate sources in preference order
        candidates: List[Tuple[str, Callable[[], Iterator[Any]]]] = []
        if shared_proto_db_downloads is not None:
            candidates.append(("shared_proto_db", _iter_downloads_shared_proto_db))

        if hasattr(profile_obj, "iter_downloads"):
            candidates.append(("profile_obj.iter_downloads", lambda: _call_download_iterator(profile_obj.iter_downloads)))

        # Some ccl versions expose downloads through history
        if hasattr(profile_obj, "get_history"):
            try:
                hist = profile_obj.get_history()
                if hasattr(hist, "iter_downloads"):
                    candidates.append(("profile_obj.get_history().iter_downloads", lambda: hist.iter_downloads()))
            except Exception:
                pass

        # Final fallback: direct History SQLite
        candidates.append(("history_sqlite", _iter_downloads_history_sqlite))

        used_source = None
        for source_name, factory in candidates:
            iter_ok = False
            try:
                it = factory()
                for d in it:
                    # history_sqlite already yields dict rows; others need normalization
                    if isinstance(d, dict) and d.get("_source") == "history_sqlite":
                        row = {
                            "root_tag": root_tag,
                            "profile_name": profile_name,
                            "start_time_utc": d.get("start_time_utc"),
                            "end_time_utc": d.get("end_time_utc"),
                            "url": d.get("url"),
                            "tab_url": d.get("tab_url"),
                            "referrer": d.get("referrer"),
                            "target_path": d.get("target_path"),
                            "current_path": d.get("current_path"),
                            "total_bytes": d.get("total_bytes"),
                            "received_bytes": d.get("received_bytes"),
                            "state": d.get("state"),
                            "danger_type": d.get("danger_type"),
                            "interrupt_reason": d.get("interrupt_reason"),
                            "opened": d.get("opened"),
                            "by_ext_id": d.get("by_ext_id"),
                            "by_ext_name": d.get("by_ext_name"),
                            "source": source_name,
                            "notes": None,
                        }
                    else:
                        row = _normalize_download_obj(d, source_name)

                    jw.write(row)
                    try:
                        cw.write_row(row)
                    except Exception as e:
                        # CSV row issues must never kill downloads export
                        log_error_event(errors_writer, logger, stage="downloads_csv_row_failed",
                                        context={"root_tag": root_tag, "profile_name": profile_name, "source": source_name},
                                        exc=e)
                    rows_written += 1
                iter_ok = True
            except Exception as e:
                log_error_event(errors_writer, logger, stage="downloads_iterator_failed",
                                context={"root_tag": root_tag, "profile_name": profile_name, "source": source_name},
                                exc=e)
            if iter_ok and rows_written > 0:
                used_source = source_name
                break

        logger.info(f"[downloads] rows_written={rows_written} source={used_source}")

    except Exception as e:
        log_error_event(errors_writer, logger, stage="downloads", context={"root_tag": root_tag, "profile_name": profile_name}, exc=e)
        raise
    finally:
        jw.close()
        cw.close()
def export_local_storage(profile_obj: Any, prof_dir: Path, profile_out_dir: Path, root_tag: str, profile_name: str,
                        logger: Logger, errors_writer: Optional[JsonlWriter]) -> None:
    stage = "local_storage"
    out_dir = ensure_dir(profile_out_dir / stage)

    jsonl_path = out_dir / "local_storage_records.jsonl"
    csv_path = out_dir / "local_storage_records.csv"

    payloads_raw_dir = ensure_dir(out_dir / "payloads_raw")
    payloads_decoded_dir = ensure_dir(out_dir / "payloads_decoded")

    total_records = 0
    storage_key_count = 0
    record_errors = 0

    from ccl_chromium_reader.ccl_chromium_localstorage import LocalStoreDb  # type: ignore

    ls_dir = prof_dir / "Local Storage" / "leveldb"
    if not ls_dir.exists():
        logger.warn(f"[{stage}] missing directory: {ls_dir}")
        return

    try:
        lsdb = LocalStoreDb(ls_dir)
    except Exception as e:
        log_error_event(
            errors_writer,
            logger,
            stage=f"{stage}_init_failed",
            context={"root_tag": root_tag, "profile_name": profile_name, "ls_dir": str(ls_dir)},
            exc=e,
        )
        return

    # Feature-detect include_deletions support on iter_storage_keys.
    try:
        sig = inspect.signature(lsdb.iter_storage_keys)
        if "include_deletions" in sig.parameters:
            storage_keys_iter = lsdb.iter_storage_keys(include_deletions=True)
        else:
            storage_keys_iter = lsdb.iter_storage_keys()
    except Exception:
        storage_keys_iter = lsdb.iter_storage_keys()

    with JsonlWriter(jsonl_path) as jw, CsvWriter(
        csv_path,
        fieldnames=[
            "root_tag",
            "profile_name",
            "storage_key",
            "script_key",
            "leveldb_seq_number",
            "approx_batch_timestamp_utc",
            "decoded_kind",
            "raw_len",
            "decoded_len",
            "transform_chain",
            "text_preview",
            "json_preview",
            "b64_preview",
            "extracted_files_count",
            "first_extracted_file",
        ],
    ) as cw:
        for storage_key in storage_keys_iter:
            storage_key_count += 1
            storage_key_str = str(storage_key)
            storage_key_slug = slug(storage_key_str, max_len=120)

            try:
                rec_iter = lsdb.iter_records_for_storage_key(storage_key, include_deletions=True)
            except Exception as e:
                record_errors += 1
                log_error_event(
                    errors_writer,
                    logger,
                    stage=f"{stage}_iter_records_failed",
                    context={"root_tag": root_tag, "profile_name": profile_name, "storage_key": storage_key_str},
                    exc=e,
                )
                continue

            for rec in rec_iter:
                try:
                    script_key = getattr(rec, "script_key", None)
                    seq = (
                        getattr(rec, "leveldb_seq_number", None)
                        or getattr(rec, "seq_number", None)
                        or getattr(rec, "sequence_number", None)
                        or getattr(rec, "seq", None)
                    )
                    try:
                        seq_int = int(seq) if seq is not None else None
                    except Exception:
                        seq_int = None

                    approx_ts = None
                    if seq_int is not None:
                        try:
                            batch = lsdb.find_batch(seq_int)
                            if batch is not None:
                                ts = getattr(batch, "timestamp_utc", None) or getattr(batch, "timestamp", None)
                                if isinstance(ts, datetime.datetime):
                                    if ts.tzinfo is None:
                                        ts = ts.replace(tzinfo=datetime.timezone.utc)
                                    approx_ts = ts.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                                elif ts:
                                    approx_ts = str(ts)
                        except Exception:
                            approx_ts = None

                    value = getattr(rec, "value", None)
                    decoded = smart_decode_payload(
                        value,
                        context={
                            "category": stage,
                            "root_tag": root_tag,
                            "profile_name": profile_name,
                            "storage_key": storage_key_str,
                            "script_key": script_key,
                            "seq": seq_int,
                        },
                        out_dir=out_dir,
                        limits={
                            "payloads_dir_name": "payloads_raw",
                            "decoded_dir_name": "payloads_decoded",
                        },
                        payload_subdir=f"{storage_key_slug}",
                    )

                    row = {
                        "root_tag": root_tag,
                        "profile_name": profile_name,
                        "storage_key": storage_key_str,
                        "script_key": script_key,
                        "leveldb_seq_number": seq_int,
                        "approx_batch_timestamp_utc": approx_ts,
                        "decoded_kind": decoded.get("kind"),
                        "raw_len": decoded.get("raw_len"),
                        "decoded_len": decoded.get("decoded_len"),
                        "transform_chain": " > ".join(decoded.get("transform_chain", []) or []),
                        "text_preview": decoded.get("text_preview"),
                        "json_preview": decoded.get("json_preview"),
                        "b64_preview": decoded.get("b64_preview"),
                        "extracted_files_count": decoded.get("extracted_files_count"),
                        "first_extracted_file": decoded.get("first_extracted_file"),
                    }

                    jw.write({"row": row, "decoded": decoded})
                    try:
                        cw.write_row(row)
                    except Exception as e:
                        log_error_event(
                            errors_writer,
                            logger,
                            stage=f"{stage}_csv_row_failed",
                            context={"root_tag": root_tag, "profile_name": profile_name, "storage_key": storage_key_str},
                            exc=e,
                        )

                    total_records += 1
                except Exception as e:
                    record_errors += 1
                    log_error_event(
                        errors_writer,
                        logger,
                        stage=f"{stage}_record_failed",
                        context={"root_tag": root_tag, "profile_name": profile_name, "storage_key": storage_key_str},
                        exc=e,
                    )

    logger.info(
        f"[{stage}] storage_keys={storage_key_count} records={total_records} record_errors={record_errors} "
        f"out={out_dir}"
    )
def export_session_storage(
    prof_dir: Path,
    profile_obj: Any,
    profile_out_dir: Path,
    root_tag: str,
    profile_name: str,
    logger: Logger,
    errors_writer: Optional[JsonlWriter] = None,
) -> Dict[str, Any]:
    """
    Step 2A: Session Storage export using ccl_chromium_reader SessionStoreDb (README pattern).

    - Streams JSONL + CSV.
    - Applies smart_decode_payload to bytes-like values.
    - Writes artifacts to:
        session_storage/payloads_raw/
        session_storage/payloads_decoded/
      scoped under hosts/<host>/...
    """
    stage = "session_storage"
    out_dir = profile_out_dir / "session_storage"
    ensure_dir(out_dir)

    jsonl_path = out_dir / "session_storage_records.jsonl"
    csv_path = out_dir / "session_storage_records.csv"

    fieldnames = [
        "root_tag",
        "profile_name",
        "host",
        "key",
        "leveldb_seq_number",
        "decoded_kind",
        "raw_len",
        "decoded_len",
        "transform_chain",
        "text_preview",
        "json_preview",
        "extracted_files_count",
        "first_extracted_file",
    ]

    limits = {
        "payloads_dir_name": "payloads_raw",
        "decoded_dir_name": "payloads_decoded",
        "max_bytes_to_process": 50 * 1024 * 1024,
        "max_text_chars": 20000,
        "max_json_chars": 2 * 1024 * 1024,
        "base64_preview_bytes": 64 * 1024,
        "max_zip_members": 10,
        "max_zip_member_bytes": 10 * 1024 * 1024,
        "max_zip_total_bytes": 25 * 1024 * 1024,
        "write_raw_always": False,
        "write_decoded_always": False,
        "max_artifact_write_bytes": 50 * 1024 * 1024,
        "artifact_force_write_bytes": 2 * 1024 * 1024,
    }

    ss_dir_candidates = [
        prof_dir / "Session Storage",
        prof_dir / "Session Storage" / "leveldb",
    ]
    ss_leveldb_dir = next((p for p in ss_dir_candidates if p.exists()), None)

    if ss_leveldb_dir is None:
        logger.info(f"[{stage}] Session Storage LevelDB not found in expected locations.")
        with JsonlWriter(jsonl_path) as jw, CsvWriter(csv_path, fieldnames=fieldnames) as cw:
            pass
        return {"exported": False, "reason": "missing_session_storage_leveldb"}

    # Import the intended SessionStoreDb API
    try:
        from ccl_chromium_reader import ccl_chromium_sessionstorage as _ccl_ss  # type: ignore
    except Exception as e:
        log_error_event(
            errors_writer,
            logger,
            stage=f"{stage}_import_failed",
            context={"root_tag": root_tag, "profile_name": profile_name, "profile_dir": str(prof_dir)},
            exc=e,
        )
        with JsonlWriter(jsonl_path) as jw, CsvWriter(csv_path, fieldnames=fieldnames) as cw:
            pass
        return {"exported": False, "reason": "import_failed"}

    exported = 0
    record_errors = 0
    host_count = 0

    try:
        db = _ccl_ss.SessionStoreDb(ss_leveldb_dir)
    except Exception as e:
        log_error_event(
            errors_writer,
            logger,
            stage=f"{stage}_open_failed",
            context={"root_tag": root_tag, "profile_name": profile_name, "leveldb_dir": str(ss_leveldb_dir)},
            exc=e,
        )
        with JsonlWriter(jsonl_path) as jw, CsvWriter(csv_path, fieldnames=fieldnames) as cw:
            pass
        return {"exported": False, "reason": "open_failed", "path": str(ss_leveldb_dir)}

    with db, JsonlWriter(jsonl_path) as jw, CsvWriter(csv_path, fieldnames=fieldnames) as cw:
        try:
            for host in db.iter_hosts():
                host_count += 1
                host_slug = slug(str(host), max_len=120)
                try:
                    rec_iter = db.iter_records_for_host(host)
                except Exception as e:
                    record_errors += 1
                    log_error_event(
                        errors_writer,
                        logger,
                        stage=f"{stage}_iter_records_failed",
                        context={"root_tag": root_tag, "profile_name": profile_name, "host": str(host)},
                        exc=e,
                    )
                    continue

                for rec in rec_iter:
                    try:
                        key = getattr(rec, "key", None) or getattr(rec, "script_key", None) or ""
                        seq = (
                            getattr(rec, "leveldb_seq_number", None)
                            or getattr(rec, "seq_number", None)
                            or getattr(rec, "sequence_number", None)
                            or getattr(rec, "seq", None)
                        )
                        try:
                            seq_int = int(seq) if seq is not None else None
                        except Exception:
                            seq_int = None

                        value = getattr(rec, "value", None)
                        decoded = smart_decode_payload(
                            value,
                            out_dir=out_dir,
                            payload_subdir=f"hosts/{host_slug}",
                            limits=limits,
                        )

                        row = {
                            "root_tag": root_tag,
                            "profile_name": profile_name,
                            "host": str(host),
                            "key": str(key),
                            "leveldb_seq_number": seq_int if seq_int is not None else "",
                            "decoded": decoded,
                        }
                        jw.write(row)

                        csv_row = {
                            "root_tag": root_tag,
                            "profile_name": profile_name,
                            "host": str(host),
                            "key": str(key),
                            "leveldb_seq_number": seq_int if seq_int is not None else "",
                            "decoded_kind": decoded.get("kind", ""),
                            "raw_len": decoded.get("raw_len", ""),
                            "decoded_len": decoded.get("decoded_len", ""),
                            "transform_chain": " > ".join(decoded.get("transform_chain", []) or []),
                            "text_preview": decoded.get("text_preview", "") or "",
                            "json_preview": decoded.get("json_preview", "") or "",
                            "extracted_files_count": len(decoded.get("extracted_files", []) or []),
                            "first_extracted_file": (decoded.get("extracted_files", []) or [""])[0],
                        }
                        try:
                            cw.write_row(csv_row)
                        except Exception as e:
                            log_error_event(
                                errors_writer,
                                logger,
                                stage=f"{stage}_csv_row_failed",
                                context={'root_tag': root_tag, 'profile_name': profile_name},
                                exc=e,
                            )

                        exported += 1
                        if exported % 5000 == 0:
                            logger.info(f"[{stage}] exported {exported} record(s) ...")
                    except Exception as e:
                        record_errors += 1
                        log_error_event(
                            errors_writer,
                            logger,
                            stage=f"{stage}_record_failed",
                            context={"root_tag": root_tag, "profile_name": profile_name, "host": str(host)},
                            exc=e,
                        )
                        continue

        except Exception as e:
            log_error_event(
                errors_writer,
                logger,
                stage=f"{stage}_iteration_failed",
                context={"root_tag": root_tag, "profile_name": profile_name, "leveldb_dir": str(ss_leveldb_dir)},
                exc=e,
            )

    return {
        "exported": True,
        "records": exported,
        "hosts": host_count,
        "record_errors": record_errors,
        "leveldb_dir": str(ss_leveldb_dir),
    }

def find_blob_indices(value: Any, BlobIndexType: Any) -> List[Any]:
    """
    Recursively find BlobIndex objects inside a decoded IndexedDB value.
    """
    found = []
    try:
        if value is None:
            return found
        if BlobIndexType is not None and isinstance(value, BlobIndexType):
            return [value]
        if isinstance(value, dict):
            for v in value.values():
                found.extend(find_blob_indices(v, BlobIndexType))
        elif isinstance(value, (list, tuple, set)):
            for v in value:
                found.extend(find_blob_indices(v, BlobIndexType))
        elif is_dataclass(value):
            found.extend(find_blob_indices(asdict(value), BlobIndexType))
        elif hasattr(value, "__dict__"):
            # avoid deep recursion into huge objects; only walk public attrs
            d = {k: v for k, v in vars(value).items() if not k.startswith("_")}
            if d:
                found.extend(find_blob_indices(d, BlobIndexType))
    except Exception:
        pass
    return found




def _salvage_indexeddb_blob_dir(profile_path, host_id, out_dir, *, root_tag=None, profile_name=None, errors_writer=None):
    """If an IndexedDB origin fails to parse, inventory/copy its *.indexeddb.blob folder for later triage.

    - Works both with scripts that have root_tag/profile_name context and those that don't.
    - Always bounds the work to avoid runaway copies.
    """
    try:
        profile_path = Path(profile_path)
        blob_dir = profile_path / "IndexedDB" / f"{host_id}.indexeddb.blob"
        if not blob_dir.exists() or not blob_dir.is_dir():
            return None

        dest = Path(out_dir) / "indexeddb" / "blob_fallback" / host_id
        ensure_dir(dest)
        inv_jsonl = dest / "blob_inventory.jsonl"
        inv_csv = dest / "blob_inventory.csv"

        # bounded copy/inventory (avoid runaway sizes)
        max_files = 5000
        max_total_bytes = 2 * 1024 * 1024 * 1024  # 2 GiB cap
        total_bytes = 0
        files = 0

        with JsonlWriter(inv_jsonl) as jw, SafeCsvWriter(inv_csv, fieldnames=["rel_path", "size_bytes", "mtime_utc", "copied_to"]) as cw:
            for p in blob_dir.rglob("*"):
                if not p.is_file():
                    continue
                rel = str(p.relative_to(blob_dir))
                st = p.stat()
                size = int(st.st_size)
                mtime = datetime.datetime.utcfromtimestamp(st.st_mtime).replace(microsecond=0).isoformat() + "Z"
                copied_to = ""

                # copy while under caps
                if files < max_files and (total_bytes + size) <= max_total_bytes:
                    dest_path = dest / rel
                    ensure_dir(dest_path.parent)
                    try:
                        shutil.copy2(p, dest_path)
                        copied_to = str(dest_path)
                        total_bytes += size
                    except Exception:
                        copied_to = ""

                row = {"rel_path": rel, "size_bytes": size, "mtime_utc": mtime, "copied_to": copied_to}
                event = {"host_id": host_id, "profile_path": str(profile_path), **row}
                if root_tag is not None:
                    event["root_tag"] = root_tag
                if profile_name is not None:
                    event["profile_name"] = profile_name

                jw.write(event)
                cw.writerow(row)
                files += 1

        return str(dest)

    except Exception as e:
        warn_once(("indexeddb_blob_salvage_failed", str(profile_path), host_id), f"stage=indexeddb_blob_salvage_failed err={type(e).__name__}: {e}")
        if errors_writer is not None:
            log_error_event(errors_writer, stage="indexeddb_blob_salvage_failed", root_tag=root_tag, profile_name=profile_name, host_id=host_id, err=repr(e))
        return None
        dest = Path(out_dir) / "indexeddb" / "blob_fallback" / host_id
        ensure_dir(dest)
        inv_jsonl = dest / "blob_inventory.jsonl"
        inv_csv = dest / "blob_inventory.csv"
        # bounded copy/inventory (avoid runaway sizes)
        max_files = 5000
        max_total_bytes = 2 * 1024 * 1024 * 1024  # 2 GiB cap
        total_bytes = 0
        files = 0
        with JsonlWriter(inv_jsonl) as jw, SafeCsvWriter(inv_csv, fieldnames=["rel_path","size_bytes","mtime_utc","copied_to"]) as cw:
            for p in blob_dir.rglob("*"):
                if not p.is_file():
                    continue
                rel = str(p.relative_to(blob_dir))
                st = p.stat()
                size = int(st.st_size)
                mtime = datetime.datetime.utcfromtimestamp(st.st_mtime).replace(microsecond=0).isoformat() + "Z"
                copied_to = ""
                # copy while under caps
                if files < max_files and (total_bytes + size) <= max_total_bytes:
                    dest_path = dest / rel
                    ensure_dir(dest_path.parent)
                    try:
                        shutil.copy2(p, dest_path)
                        copied_to = str(dest_path)
                        total_bytes += size
                    except Exception:
                        copied_to = ""
                row={"rel_path": rel, "size_bytes": size, "mtime_utc": mtime, "copied_to": copied_to}
                jw.write({"root_tag": root_tag, "profile_name": profile_name, "host_id": host_id, **row})
                cw.writerow(row)
                files += 1
        return str(dest)
    except Exception as e:
        warn_once(("indexeddb_blob_salvage_failed", root_tag, profile_name, host_id), f"stage=indexeddb_blob_salvage_failed err={type(e).__name__}: {e}")
        if errors_writer is not None:
            log_error_event(errors_writer, stage="indexeddb_blob_salvage_failed", root_tag=root_tag, profile_name=profile_name, host_id=host_id, err=repr(e))
        return None

def export_indexeddb(
    profile_obj: "ChromiumProfileFolder",
    out_dir: Path,
    logger: "Logger",
    *,
    extract_blobs: bool = False,
    blob_max_bytes: int = 5_000_000,
) -> Dict[str, Any]:
    """
    Export IndexedDB records via ccl_chromium_reader in a resilient way.

    Notes:
    - The library requires a host_id; we iterate hosts discovered from the IndexedDB directory.
    - Any single-origin failure is logged and skipped; we keep going.
    - Values can be complex (Blink/V8); we store bounded string representations plus type info.
    - Optional blob extraction copies external blob files referenced by records.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    result: Dict[str, Any] = {
        "export_dir": str(out_dir),
        "hosts": 0,
        "records": 0,
        "blobs_copied": 0,
        "errors": 0,
    }

    hosts_path = out_dir / "indexeddb_hosts.txt"
    records_csv = out_dir / "indexeddb_records.csv"
    records_jsonl = out_dir / "indexeddb_records.jsonl"
    blobs_dir = out_dir / "indexeddb_blobs"
    if extract_blobs:
        blobs_dir.mkdir(parents=True, exist_ok=True)

    def _safe_preview(s: str, limit: int = 4000) -> str:
        if s is None:
            return ""
        s = str(s)
        return s if len(s) <= limit else (s[:limit] + "...(truncated)")

    def _b64(b: bytes) -> str:
        try:
            return base64.b64encode(b).decode("ascii")
        except Exception:
            return ""

    def _key_bytes(key_obj: Any) -> bytes:
        try:
            if key_obj is None:
                return b""
            # IdbKey has .raw_key
            rk = getattr(key_obj, "raw_key", None)
            if isinstance(rk, (bytes, bytearray, memoryview)):
                return bytes(rk)
        except Exception:
            pass
        return b""

    def _value_preview(val: Any) -> str:
        try:
            if val is None:
                return ""
            if isinstance(val, (bytes, bytearray, memoryview)):
                b = bytes(val)
                return f"bytes({len(b)}) b64:{_b64(b[:256])}"
            # Avoid huge JSON dumps; just repr/str
            return _safe_preview(repr(val))
        except Exception:
            return ""

    # Iterate hosts
    try:
        hosts = list(profile_obj.iter_indexeddb_hosts())
    except Exception as e:
        logger.warn(f"iter_indexeddb_hosts failed: {e}")
        result["errors"] += 1
        return result

    result["hosts"] = len(hosts)
    try:
        hosts_path.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    except Exception:
        pass

    # CSV + JSONL
    fieldnames = [
        "host_id",
        "db_id",
        "obj_store_id",
        "is_live",
        "ldb_seq_no",
        "origin_file",
        "key_b64",
        "key_preview",
        "value_type",
        "value_preview",
        "external_value_path",
        "blob_copied_as",
    ]
    cw = CsvWriter(records_csv, fieldnames)

    try:
        jf = open(records_jsonl, "w", encoding="utf-8", newline="\n")
    except Exception as e:
        cw.close()
        logger.warn(f"Failed to open indexeddb_records.jsonl: {e}")
        result["errors"] += 1
        return result

    with jf:
        csv_enabled = (cw is not None)
        csv_disabled_logged = False
        for host_id in hosts:
            logger.debug(f"IndexedDB host: {host_id}")
            try:
                iterator = profile_obj.iter_indexeddb_records(host_id, include_deletions=True)
            except Exception as e:
                result["errors"] += 1
                logger.warn(f"iter_indexeddb_records failed for host {host_id}: {e}")
                continue

            # Consume iterator; any exception mid-stream should not kill other hosts.
            while True:
                try:
                    rec = next(iterator)
                except StopIteration:
                    break
                except Exception as e:
                    result["errors"] += 1
                    logger.warn(f"IndexedDB iteration error for host {host_id}: {e}")
                    break

                result["records"] += 1

                try:
                    key_bytes = _key_bytes(getattr(rec, "key", None))
                    key_b64 = _b64(key_bytes) if key_bytes else ""
                    key_preview = _safe_preview(key_bytes[:128].decode("utf-8", errors="replace")) if key_bytes else ""

                    val = getattr(rec, "value", None)
                    val_type = type(val).__name__ if val is not None else ""
                    val_preview = _value_preview(val)

                    ext = getattr(rec, "external_value_path", None)
                    blob_copied_as = ""

                    # Optional external blob copy
                    if extract_blobs and ext:
                        try:
                            p = Path(str(ext))
                            if not p.is_absolute():
                                base = Path(profile_obj.path) / "IndexedDB" / f"{host_id}.indexeddb.blob"
                                p = base / str(ext)
                            if p.exists() and p.is_file():
                                size = p.stat().st_size
                                if size <= blob_max_bytes:
                                    # deterministic filename: sha1 of source path + size
                                    h = hashlib.sha1((str(p) + "|" + str(size)).encode("utf-8", errors="replace")).hexdigest()
                                    dst = blobs_dir / f"{h}_{p.name}"
                                    if not dst.exists():
                                        shutil.copy2(p, dst)
                                    blob_copied_as = str(dst)
                                    result["blobs_copied"] += 1
                        except Exception as e:
                            result["errors"] += 1
                            logger.warn(f"Blob copy failed for host {host_id}: {e}")

                    row = {
                        "host_id": host_id,
                        "db_id": getattr(rec, "db_id", ""),
                        "obj_store_id": getattr(rec, "obj_store_id", ""),
                        "is_live": getattr(rec, "is_live", ""),
                        "ldb_seq_no": getattr(rec, "ldb_seq_no", ""),
                        "origin_file": str(getattr(rec, "origin_file", "")),
                        "key_b64": key_b64,
                        "key_preview": key_preview,
                        "value_type": val_type,
                        "value_preview": val_preview,
                        "external_value_path": str(ext) if ext else "",
                        "blob_copied_as": blob_copied_as,
                    }
                    jf.write(json.dumps(row, ensure_ascii=False) + "\n")
                    if csv_enabled:
                        try:
                            cw.write(row)
                        except Exception as e:
                            result["errors"] += 1
                            if not csv_disabled_logged:
                                logger.warn(f"IndexedDB CSV disabled after first write error (host {host_id}): {e}")
                                csv_disabled_logged = True
                            csv_enabled = False
                except Exception as e:
                    result["errors"] += 1
                    logger.warn(f"IndexedDB record export failed for host {host_id}: {e}")
                    continue

    cw.close()
    return result


def export_cache(profile_obj, out_dir: Path, logger: Logger, *, extract_bodies: bool, max_body_bytes: int, omit_data_when_listing: bool = True) -> Dict[str, Any]:
    """
    Exports HTTP cache entries. By default, writes a metadata index only (omit cached bodies).
    If extract_bodies is True, writes each body to disk (bounded) and records sha256/truncation.
    """
    res: Dict[str, Any] = {"cache": {"exported": False}}
    safe_mkdir(out_dir)

    idx_csv = out_dir / "cache_index.csv"
    idx_jsonl = out_dir / "cache_index.jsonl"
    bodies_dir = out_dir / "cache_bodies"

    fields = [
        "url",
        "top_frame_site",
        "frame_site",
        "request_time",
        "response_time",
        "content_type",
        "content_encoding",
        "etag",
        "cache_control",
        "was_decompressed",
        "metadata_location",
        "data_location",
        "body_path",
        "body_sha256",
        "body_bytes",
        "body_truncated",
    ]

    try:
        if extract_bodies:
            safe_mkdir(bodies_dir)

        with CsvWriter(idx_csv, fields) as cw, JsonlWriter(idx_jsonl) as jw:
            # If we are extracting bodies, we need data, otherwise omit for speed.
            omit = omit_data_when_listing and (not extract_bodies)
            for item in iterate_cache_compat(profile_obj, decompress=True, omit_cached_data=omit):
                meta = item.metadata
                # pull a few headers
                def hdr(name: str) -> str:
                    try:
                        vals = meta.get_attribute(name)
                        return vals[0] if vals else ""
                    except Exception:
                        return ""

                body_path = ""
                body_sha = ""
                body_bytes = ""
                body_trunc = ""
                if extract_bodies:
                    try:
                        data = item.data or b""
                        if len(data) > max_body_bytes:
                            data = data[:max_body_bytes]
                            body_trunc = "true"
                        else:
                            body_trunc = "false"
                        body_sha = hashlib.sha256(data).hexdigest()
                        body_bytes = str(len(data))
                        fn = slug(f"{body_sha}_{item.key.url}")[:180] + ".bin"
                        out_path = bodies_dir / fn
                        with out_path.open("wb") as f:
                            f.write(data)
                        body_path = str(out_path)
                    except Exception as e:
                        body_path = f"<error:{e}>"

                row = {
                    "url": item.key.url,
                    "top_frame_site": getattr(item.key, "isolation_key_top_frame_site", ""),
                    "frame_site": getattr(item.key, "isolation_key_frame_site", ""),
                    "request_time": meta.request_time.isoformat() if getattr(meta, "request_time", None) else "",
                    "response_time": meta.response_time.isoformat() if getattr(meta, "response_time", None) else "",
                    "content_type": hdr("content-type"),
                    "content_encoding": hdr("content-encoding"),
                    "etag": hdr("etag"),
                    "cache_control": hdr("cache-control"),
                    "was_decompressed": item.was_decompressed,
                    "metadata_location": str(item.metadata_location),
                    "data_location": str(item.data_location),
                    "body_path": body_path,
                    "body_sha256": body_sha,
                    "body_bytes": body_bytes,
                    "body_truncated": body_trunc,
                }
                cw.write(row)
                jw.write({"row": row, "key": jsonable(item.key), "metadata": {"headers": list((getattr(meta, "http_header_attributes", None) or []))}})

        res["cache"]["exported"] = True
        res["cache"]["index_csv"] = str(idx_csv)
        res["cache"]["index_jsonl"] = str(idx_jsonl)
        if extract_bodies:
            res["cache"]["bodies_dir"] = str(bodies_dir)
        return res
    except Exception as e:
        logger.info(f"export_cache failed: {e}")
        res["cache"]["error"] = str(e)
        return res


def export_notifications(profile_dir: Path, out_dir: Path, logger: Logger) -> Dict[str, Any]:
    """
    Exports Web Platform Notifications from 'Platform Notifications' LevelDB if present.
    """
    res: Dict[str, Any] = {"notifications": {"exported": False}}
    notif_dir = profile_dir / "Platform Notifications"
    if not notif_dir.exists() or not notif_dir.is_dir():
        res["notifications"]["missing"] = True
        return res

    safe_mkdir(out_dir)
    csv_path = out_dir / "notifications.csv"
    jsonl_path = out_dir / "notifications.jsonl"

    try:
        from ccl_chromium_reader.ccl_chromium_notifications import NotificationReader
        fields = [
            "origin", "persistent_notification_id", "notification_id",
            "title", "body",
            "timestamp", "creation_time",
            "closed_reason",
            "time_until_first_click_millis", "time_until_last_click_millis", "time_until_close_millis",
            "tag", "image", "icon", "badge",
            "leveldb_seq", "origin_file",
        ]
        with NotificationReader(notif_dir) as nr, CsvWriter(csv_path, fields) as cw, JsonlWriter(jsonl_path) as jw:
            for n in nr.read_notifications():
                row = {
                    "origin": n.origin,
                    "persistent_notification_id": n.persistent_notification_id,
                    "notification_id": n.notification_id,
                    "title": n.title,
                    "body": n.body,
                    "timestamp": n.timestamp.isoformat() if n.timestamp else "",
                    "creation_time": n.creation_time.isoformat() if n.creation_time else "",
                    "closed_reason": getattr(n.closed_reason, "name", str(n.closed_reason)),
                    "time_until_first_click_millis": n.time_until_first_click_millis,
                    "time_until_last_click_millis": n.time_until_last_click_millis,
                    "time_until_close_millis": n.time_until_close_millis,
                    "tag": n.tag,
                    "image": n.image,
                    "icon": n.icon,
                    "badge": n.badge,
                    "leveldb_seq": (getattr(getattr(n, "level_db_info", None), "seq", None) or getattr(getattr(n, "level_db_info", None), "sequence", None) or getattr(getattr(n, "level_db_info", None), "sequence_number", None) or ""),
                    "origin_file": str(getattr(getattr(n, "level_db_info", None), "origin_file", "")),
                }
                cw.write(row)
                jw.write({"notification": jsonable(n), "row": row})
        res["notifications"]["exported"] = True
        res["notifications"]["csv"] = str(csv_path)
        res["notifications"]["jsonl"] = str(jsonl_path)
        return res
    except Exception as e:
        logger.info(f"export_notifications failed: {e}")
        res["notifications"]["error"] = str(e)
        return res


def export_filesystem(profile_dir: Path, out_dir: Path, logger: Logger, *, copy_files: bool, copy_max_total_bytes: int) -> Dict[str, Any]:
    """
    Exports File System API metadata from 'File System' folder if present.
    Optionally copies local stored files (bounded by total bytes).
    """
    res: Dict[str, Any] = {"filesystem": {"exported": False}}
    fs_dir = profile_dir / "File System"
    if not fs_dir.exists() or not fs_dir.is_dir():
        res["filesystem"]["missing"] = True
        return res
    safe_mkdir(out_dir)

    csv_path = out_dir / "filesystem_files.csv"
    json_path = out_dir / "filesystem_storage.json"
    copied_dir = out_dir / "filesystem_copied_files"

    try:
        from ccl_chromium_reader.ccl_chromium_filesystem import FileSystem
        fs_obj = FileSystem(fs_dir)
        all_rows = []
        storage_json = {}
        total_copied = 0

        for origin in fs_obj.get_origins():
            folders = fs_obj.get_folders_for_origin(origin)
            storage_json[origin] = {"folders": folders, "stores": {}}
            for folder_id in folders:
                store = fs_obj.get_storage_for_folder(folder_id)
                # store has: persistent_files, persistent_deleted_files, temporary_files, temporary_deleted_files
                st = jsonable(store)
                storage_json[origin]["stores"][folder_id] = st

                # Build CSV rows from file info objects if possible
                for kind in ("persistent_files", "temporary_files"):
                    files_dict = getattr(store, kind, {}) or {}
                    for file_id, fi in files_dict.items():
                        try:
                            local_path = fs_obj.get_local_path_for_fileinfo(fi)
                            is_local = fs_obj.is_stored_locally(fi)
                        except Exception:
                            local_path = ""
                            is_local = ""
                        row = {
                            "origin": origin,
                            "folder_id": folder_id,
                            "store_kind": kind,
                            "file_id": file_id,
                            "path": getattr(fi, "path", ""),
                            "name": getattr(fi, "name", ""),
                            "size": getattr(fi, "size", ""),
                            "is_deleted": False,
                            "seq_no": getattr(fi, "seq_no", ""),
                            "is_local": is_local,
                            "local_path": str(local_path) if local_path else "",
                        }
                        all_rows.append(row)

                        if copy_files and local_path and Path(str(local_path)).exists():
                            try:
                                lp = Path(str(local_path))
                                sz = lp.stat().st_size
                                if total_copied + sz <= copy_max_total_bytes:
                                    safe_mkdir(copied_dir)
                                    dst = copied_dir / slug(f"{origin}_{folder_id}_{file_id}_{lp.name}", max_len=200)
                                    shutil.copy2(lp, dst)
                                    total_copied += sz
                                    row["copied_to"] = str(dst)
                                else:
                                    row["copied_to"] = "<skipped_total_limit>"
                            except Exception as e:
                                row["copied_to"] = f"<copy_error:{e}>"

                # Deleted files (seq no only)
                for kind in ("persistent_deleted_files", "temporary_deleted_files"):
                    del_dict = getattr(store, kind, {}) or {}
                    for file_id, seq_no in del_dict.items():
                        all_rows.append({
                            "origin": origin,
                            "folder_id": folder_id,
                            "store_kind": kind,
                            "file_id": file_id,
                            "path": "",
                            "name": "",
                            "size": "",
                            "is_deleted": True,
                            "seq_no": seq_no,
                            "is_local": "",
                            "local_path": "",
                            "copied_to": "",
                        })

        # Write outputs
        fields = sorted({k for r in all_rows for k in r.keys()})
        with CsvWriter(csv_path, fields) as cw:
            for r in all_rows:
                cw.write(r)
        write_json(json_path, storage_json)

        res["filesystem"]["exported"] = True
        res["filesystem"]["csv"] = str(csv_path)
        res["filesystem"]["json"] = str(json_path)
        res["filesystem"]["copied_total_bytes"] = total_copied
        if copy_files:
            res["filesystem"]["copied_dir"] = str(copied_dir)
        return res
    except Exception as e:
        logger.info(f"export_filesystem failed: {e}")
        res["filesystem"]["error"] = str(e)
        return res


def export_snss_sessions(profile_dir: Path, out_dir: Path, logger: Logger) -> Dict[str, Any]:
    """
    Exports session restore artifacts (Current/Last Session/Tabs + Sessions folder) using ccl_chromium_snss2.
    Produces:
      - sessions_commands.jsonl (all commands)
      - sessions_navigation.csv (navigation entries with url/title/timestamp)
    """
    res: Dict[str, Any] = {"snss2": {"exported": False}}
    safe_mkdir(out_dir)

    targets: List[Tuple[str, Path]] = []

    # Common root files
    for name in ("Current Session", "Current Tabs", "Last Session", "Last Tabs"):
        p = profile_dir / name
        if p.exists() and p.is_file():
            targets.append((name, p))

    # Sessions folder
    sess_dir = profile_dir / "Sessions"
    if sess_dir.is_dir():
        for p in sorted(sess_dir.iterdir()):
            if p.is_file() and (p.name.startswith("Session_") or p.name.startswith("Tabs_")):
                targets.append((p.name, p))

    if not targets:
        res["snss2"]["missing"] = True
        return res

    try:
        from ccl_chromium_reader.ccl_chromium_snss2 import SnssFile, SnssFileType, NavigationEntry
        cmd_jsonl = out_dir / "sessions_commands.jsonl"
        nav_csv = out_dir / "sessions_navigation.csv"

        nav_fields = ["source_file", "offset", "id_type", "index", "url", "title", "timestamp", "transition_type", "referrer_url", "http_status"]
        with JsonlWriter(cmd_jsonl) as jw, CsvWriter(nav_csv, nav_fields) as cw:
            for label, path in targets:
                # choose file type based on name
                ftype = SnssFileType.Tab if "Tabs" in label or label.startswith("Tabs_") else SnssFileType.Session
                try:
                    with path.open("rb") as f:
                        sf = SnssFile(ftype, f)
                        for cmd in sf.iter_session_commands():
                            jw.write({"source_file": label, "path": str(path), "cmd": jsonable(cmd)})
                            if isinstance(cmd, NavigationEntry):
                                row = {
                                    "source_file": label,
                                    "offset": cmd.offset,
                                    "id_type": getattr(cmd.id_type, "name", str(cmd.id_type)),
                                    "index": cmd.index,
                                    "url": cmd.url,
                                    "title": cmd.title,
                                    "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else "",
                                    "transition_type": getattr(cmd.transition_type, "name", str(cmd.transition_type)),
                                    "referrer_url": cmd.referrer_url or "",
                                    "http_status": cmd.http_status or "",
                                }
                                cw.write(row)
                except Exception as e:
                    jw.write({"source_file": label, "path": str(path), "error": str(e)})

        res["snss2"]["exported"] = True
        res["snss2"]["commands_jsonl"] = str(cmd_jsonl)
        res["snss2"]["navigation_csv"] = str(nav_csv)
        return res
    except Exception as e:
        logger.info(f"export_snss_sessions failed: {e}")
        res["snss2"]["error"] = str(e)
        return res


# -----------------------------
# Orchestration
# -----------------------------

def build_report(out_dir: Path, manifest: Dict[str, Any], logger: Logger) -> None:
    """
    Writes report.md and manifest.json + a flat file list.
    """
    safe_mkdir(out_dir)
    manifest_path = out_dir / "manifest.json"
    write_json(manifest_path, manifest)

    # Flat file list
    files_csv = out_dir / "output_files.csv"
    rows = []
    for p in sorted(out_dir.rglob("*")):
        if p.is_file():
            try:
                st = p.stat()
                rows.append({
                    "rel_path": str(p.relative_to(out_dir)),
                    "size_bytes": st.st_size,
                    "mtime": _dt.datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
            except Exception:
                rows.append({"rel_path": str(p.relative_to(out_dir)), "size_bytes": "", "mtime": ""})
    with CsvWriter(files_csv, ["rel_path", "size_bytes", "mtime"]) as cw:
        for r in rows:
            cw.write(r)

    # Markdown report
    report = out_dir / "report.md"
    lines = []
    lines.append(f"# ccl_chromium_reader export report")
    lines.append("")
    lines.append(f"- Run timestamp (UTC): {manifest.get('run', {}).get('started_utc')}")
    lines.append(f"- Script: {manifest.get('run', {}).get('script')}")
    lines.append(f"- Root input: {manifest.get('run', {}).get('root')}")
    lines.append(f"- Output dir: {out_dir}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    roots = manifest.get("roots", [])
    lines.append(f"- User-data roots processed: {len(roots)}")
    prof_count = sum(len(r.get("profiles", [])) for r in roots)
    lines.append(f"- Profiles processed: {prof_count}")
    lines.append("")
    lines.append("## Outputs")
    lines.append("")
    lines.append(f"- manifest.json")
    lines.append(f"- output_files.csv")
    lines.append(f"- errors.jsonl")
    lines.append("")
    lines.append("## Roots and profiles")
    lines.append("")
    for r in roots:
        lines.append(f"### Root: `{r.get('root_tag')}`")
        lines.append(f"- Path: `{r.get('root_path')}`")
        lines.append(f"- Profiles: {len(r.get('profiles', []))}")
        for p in r.get("profiles", []):
            lines.append(f"  - Profile: `{p.get('profile_name')}`  (path: `{p.get('profile_path')}`)")
            arts = p.get("exports", {})
            # show what succeeded
            lines.append(f"    - Export groups: {', '.join(sorted(arts.keys())) if arts else ''}")
        lines.append("")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="Export Chromium user data using ccl_chromium_reader (max coverage).")
    ap.add_argument("--root", required=False, help="Path to a Chromium \"User Data\" root folder (the folder containing \"Local State\" and profile folders like \"Default\"). Example: C:\\Users\\<you>\\AppData\\Local\\Google\\Chrome\\User Data  (or your extracted User_Data folder).")
    ap.add_argument("--out", default="", help="Output directory (default: <root>\\ccl_reader_export_<timestamp>).")
    ap.add_argument("--heartbeat", type=int, default=20, help="Heartbeat interval seconds (default: 20).")
    ap.add_argument("--no-verbose", action="store_true", help="Disable console logging (still writes run_log.txt).")
    ap.add_argument("--self-check", action="store_true", help="Run pre-flight environment check and write <out>/self_check.json.")

    ap.add_argument("--export-all-history-tables", action="store_true", help="Also export every History.sqlite table to CSV (can be large).")

    ap.add_argument("--cache-extract-bodies", action="store_true", help="Extract cached bodies to disk (bounded).")
    ap.add_argument("--cache-max-body-bytes", type=int, default=2_000_000, help="Max bytes per cached body when extracting (default: 2,000,000).")

    ap.add_argument("--indexeddb-extract-blobs", action="store_true", help="Extract IndexedDB external blobs to disk (bounded).")
    ap.add_argument("--indexeddb-blob-max-bytes", type=int, default=5_000_000, help="Max bytes per extracted IndexedDB blob (default: 5,000,000).")

    ap.add_argument("--filesystem-copy-files", action="store_true", help="Copy File System API stored files (bounded by total bytes).")
    ap.add_argument("--filesystem-copy-max-total-bytes", type=int, default=200_000_000, help="Max total bytes to copy from File System API (default: 200,000,000).")

    args = ap.parse_args()

    root = Path(args.root).expanduser() if args.root else None
    tz = getattr(_dt, "UTC", _dt.timezone.utc)
    out_dir = Path(args.out).resolve() if args.out else ((root or Path.cwd()) / f"ccl_reader_export_{_dt.datetime.now(tz).strftime('%Y%m%d_%H%M%S')}")
    safe_mkdir(out_dir)
    global _FATAL_OUT_DIR, _FATAL_ERRORS_PATH
    _FATAL_OUT_DIR = out_dir

    if args.self_check:
        write_json(out_dir / "self_check.json", build_self_check())
        if root is None:
            return 0
    elif root is None:
        raise SystemExit(2)

    log_path = out_dir / "run_log.txt"
    logger = Logger(log_path, verbose=(not args.no_verbose))
    hb = Heartbeat(logger, args.heartbeat)
    hb.start()

    errors_path = out_dir / "errors.jsonl"
    safe_mkdir(errors_path.parent)
    errors_writer = JsonlWriter(errors_path)
    _FATAL_ERRORS_PATH = errors_path

    manifest: Dict[str, Any] = {
        "run": {
            "started_utc": utc_now_iso(),
            "script": str(Path(__file__).name),
            "root": str(root),
            "out": str(out_dir),
            "args": vars(args),
            "python": {"version": sys.version, "executable": sys.executable},
        },
        "package": {},
        "roots": [],
    }

    # Package versions
    try:
        import importlib.metadata as md
        manifest["package"]["ccl_chromium_reader_version"] = md.version("ccl_chromium_reader")
    except Exception:
        pass

    try:
        from ccl_chromium_reader.ccl_chromium_profile_folder import ChromiumProfileFolder
    except Exception as e:
        logger.info(f"FATAL: could not import ccl_chromium_reader: {e}")
        errors_writer.write({"fatal": True, "error": str(e)})
        errors_writer.close()
        hb.stop()
        return 2

    try:
        roots = discover_user_data_roots(root, logger)
        if not roots:
            msg = f"No Chromium user-data roots discovered under: {root!s}"
            logger.error("FATAL: " + msg)
            log_error_event(
                errors_writer,
                logger,
                stage="root_discovery",
                context={"root": str(root), "message": msg},
                exc=RuntimeError(msg),
            )
            raise RuntimeError(msg)

        for ud_root in roots:
            root_tag = tag_for_root(ud_root, root)
            root_out = out_dir / "roots" / root_tag
            safe_mkdir(root_out)

            logger.info(f"processing root_tag='{root_tag}' root='{ud_root}'")
            root_entry: Dict[str, Any] = {
                "root_tag": root_tag,
                "root_path": str(ud_root),
                "exports": {},
                "profiles": [],
            }

            # root-level exports
            try:
                root_entry["exports"]["root_files"] = export_root_artifacts(ud_root, root_out, logger)
            except Exception as e:
                errors_writer.write({"root": str(ud_root), "stage": "root_files", "error": str(e)}); logger.warn(f"stage=root_files root_tag={root_tag} root={ud_root} err={type(e).__name__}: {e}")
                root_entry["exports"]["root_files_error"] = str(e)

            profiles = discover_profile_dirs(ud_root, logger)
            for prof_dir in profiles:
                profile_name = prof_dir.name
                profile_tag = slug(profile_name, 120)
                prof_out = root_out / "profiles" / profile_tag
                safe_mkdir(prof_out)

                logger.info(f"processing profile='{profile_name}' ({prof_dir})")

                prof_entry: Dict[str, Any] = {
                    "profile_name": profile_name,
                    "profile_path": str(prof_dir),
                    "exports": {},
                }

                # file inventory + json copies
                try:
                    prof_entry["exports"]["inventory"] = export_profile_files_inventory(prof_dir, prof_out, logger, errors_writer)
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "inventory", "error": str(e)}); logger.warn(f"stage=inventory profile={profile_name} path={prof_dir} err={type(e).__name__}: {e}")

                try:
                    prof_entry["exports"]["json_files"] = export_profile_json_files(prof_dir, prof_out / "json", logger, errors_writer)
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "json_files", "error": str(e)}); logger.warn(f"stage=json_files profile={profile_name} path={prof_dir} err={type(e).__name__}: {e}")

                # ccl high-level profile object
                try:
                    # Prefer legacy cache path (Cache\\Cache_Data). If missing but Network\\Cache\\Cache_Data exists, point the reader at prof_dir\\Network.
                    cache_folder = None
                    try:
                        if not (prof_dir / "Cache" / "Cache_Data").exists():
                            if (prof_dir / "Network" / "Cache" / "Cache_Data").exists():
                                cache_folder = prof_dir / "Network"
                    except Exception:
                        cache_folder = None

                    profile_obj = ChromiumProfileFolder(prof_dir, cache_folder=cache_folder)
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "ChromiumProfileFolder", "error": str(e)}); logger.warn(f"stage=ChromiumProfileFolder profile={profile_name} path={prof_dir} err={type(e).__name__}: {e}")
                    prof_entry["exports"]["profile_open_error"] = str(e)
                    root_entry["profiles"].append(prof_entry)
                    continue

                # History.sqlite (raw sqlite parsing + optional all tables)
                try:
                    hist_db = prof_dir / "History"
                    if hist_db.is_file():
                        prof_entry["exports"]["history"] = export_history_sqlite(
                            hist_db, prof_out / "history", logger, export_all_tables=args.export_all_history_tables
                        )
                    else:
                        prof_entry["exports"]["history"] = {"exported": False, "reason": "missing History file"}
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "history", "error": str(e)})
                # Downloads (prefer shared_proto_db support when available)
                prof_entry["exports"]["downloads"] = stage_wrap(
                    "downloads",
                    lambda: export_downloads(profile_obj, prof_dir, prof_out, root_tag, profile_name, logger, errors_writer),
                    errors_writer=errors_writer,
                    logger=logger,
                    context={"root_tag": root_tag, "profile_name": profile_name, "profile_dir": str(prof_dir)},
                    default={"exported": False, "reason": "exception"},
                )

                # Local Storage (LocalStoreDb)
                prof_entry["exports"]["local_storage"] = stage_wrap(
                    "local_storage",
                    lambda: export_local_storage(profile_obj, prof_dir, prof_out, root_tag, profile_name, logger, errors_writer),
                    errors_writer=errors_writer,
                    logger=logger,
                    context={"root_tag": root_tag, "profile_name": profile_name, "profile_dir": str(prof_dir)},
                    default={"exported": False, "reason": "exception"},
                )

                # Session Storage (SessionStoreDb)
                prof_entry["exports"]["session_storage"] = stage_wrap(
                    "session_storage",
                    lambda: export_session_storage(prof_dir, profile_obj, prof_out, root_tag, profile_name, logger, errors_writer),
                    errors_writer=errors_writer,
                    logger=logger,
                    context={"root_tag": root_tag, "profile_name": profile_name, "profile_dir": str(prof_dir)},
                    default={"exported": False, "reason": "exception"},
                )


                # IndexedDB
                try:
                    prof_entry["exports"]["indexeddb"] = export_indexeddb(
                        profile_obj,
                        prof_out / "indexeddb",
                        logger,
                        extract_blobs=args.indexeddb_extract_blobs,
                        blob_max_bytes=args.indexeddb_blob_max_bytes,
                    )
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "indexeddb", "error": str(e)})

                # Cache

                try:

                    cache_present = (prof_dir / "Cache" / "Cache_Data").exists() or (prof_dir / "Network" / "Cache" / "Cache_Data").exists()

                    if cache_present:

                        prof_entry["exports"]["cache"] = export_cache(
                        profile_obj,
                        prof_out / "cache",
                        logger,
                        extract_bodies=args.cache_extract_bodies,
                        max_body_bytes=args.cache_max_body_bytes,
                        omit_data_when_listing=True,
                    )

                    else:

                        prof_entry["exports"]["cache"] = {"exported": False, "reason": "missing Cache/Cache_Data"}

                except Exception as e:

                    errors_writer.write({"profile": str(prof_dir), "stage": "cache", "error": str(e)})

                # Notifications
                try:
                    prof_entry["exports"]["notifications"] = export_notifications(prof_dir, prof_out / "notifications", logger)
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "notifications", "error": str(e)})

                # File System API
                try:
                    prof_entry["exports"]["filesystem"] = export_filesystem(
                        prof_dir,
                        prof_out / "filesystem",
                        logger,
                        copy_files=args.filesystem_copy_files,
                        copy_max_total_bytes=args.filesystem_copy_max_total_bytes,
                    )
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "filesystem", "error": str(e)})

                # Session restore (SNSS2)
                try:
                    prof_entry["exports"]["snss2"] = export_snss_sessions(prof_dir, prof_out / "snss2", logger)
                except Exception as e:
                    errors_writer.write({"profile": str(prof_dir), "stage": "snss2", "error": str(e)})

                # Close profile store resources if it supports it
                try:
                    profile_obj.close()
                except Exception:
                    pass

                root_entry["profiles"].append(prof_entry)

            manifest["roots"].append(root_entry)

        # Persist manifest before report generation (so a report failure doesn't lose the run summary)
        try:
            write_json(out_dir / "manifest.json", manifest)
        except Exception as e:
            logger.log(f"manifest write failed: {e}")

        # finalize report
        try:
            build_report(out_dir, manifest, logger)
        except Exception as e:
            logger.log(f"build_report failed (non-fatal): {e}")
        logger.info("done")
        return 0
    finally:
        try:
            errors_writer.close()
        except Exception:
            pass
        hb.stop()


if __name__ == "__main__":
    try:
        exit_code = main()
    except BaseException as exc:
        exit_code = capture_fatal_exception(exc, out_dir=_FATAL_OUT_DIR, errors_path=_FATAL_ERRORS_PATH)
    raise SystemExit(exit_code)
