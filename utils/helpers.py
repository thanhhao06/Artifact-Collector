import os
import hashlib
import subprocess
from datetime import datetime, timezone


def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_output_dir(base_dir="output", prefix="triage"):
    timestamp = get_timestamp()
    output_dir = os.path.join(base_dir, f"{prefix}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def safe_write_text(file_path, content):
    with open(file_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)


def format_file_size(size_bytes):
    if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def calculate_file_hash(file_path, algorithm="sha256"):
    """Calculates SHA256 or MD5 hash of a file safely."""
    if not os.path.isfile(file_path):
        return ""
    try:
        h = hashlib.sha256() if algorithm == "sha256" else hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def calculate_string_hash(text, algorithm="sha256"):
    """Calculates hash of a string safely."""
    try:
        h = hashlib.sha256() if algorithm == "sha256" else hashlib.md5()
        h.update(str(text).encode("utf-8", errors="ignore"))
        return h.hexdigest()
    except Exception:
        return ""


def webkit_timestamp_to_iso(microseconds):
    """Converts WebKit / Chromium microsecond timestamp (since 1601-01-01) to ISO-8601 UTC."""
    try:
        val = int(microseconds)
        if val <= 0:
            return ""
        seconds = val / 1_000_000.0
        if seconds > 1e12:
            seconds /= 1_000_000.0
        unix_ts = seconds - 11644473600
        if unix_ts < 0 or unix_ts > 4102444800:
            return ""
        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def firefox_prtime_to_iso(microseconds):
    """Converts Firefox PRTime (microseconds since 1970-01-01) to ISO-8601 UTC."""
    try:
        val = int(microseconds)
        if val <= 0:
            return ""
        unix_ts = val / 1_000_000.0
        if unix_ts < 0 or unix_ts > 4102444800:
            return ""
        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def windows_filetime_to_iso(filetime):
    """Converts Windows 64-bit FILETIME (100-nanosecond intervals since 1601-01-01) to ISO-8601 UTC."""
    try:
        val = int(filetime)
        if val <= 0:
            return ""
        unix_ts = (val / 10_000_000.0) - 11644473600
        if unix_ts < 0 or unix_ts > 4102444800:
            return ""
        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def run_cmd(command_args, timeout=15, shell=False):
    """Executes a command safely and returns dict with stdout, stderr, return_code."""
    try:
        result = subprocess.run(
            command_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            shell=shell
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
            "success": result.returncode == 0
        }
    except Exception as exc:
        return {
            "stdout": "",
            "stderr": str(exc),
            "return_code": -1,
            "success": False
        }
