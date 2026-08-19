import os
import re
from utils.helpers import run_cmd


def _is_unquoted_vulnerable(path_str):
    """
    Checks if a service binary path contains spaces and lacks quotes,
    which is an Unquoted Service Path vulnerability (CWE-428).
    """
    if not path_str:
        return False
    path = path_str.strip()
    if path.startswith('"') or path.startswith("'"):
        return False
    # If path contains arguments, isolate binary path
    exe_part = path.split(" -")[0].split(" /")[0].strip()
    if " " in exe_part and not (exe_part.startswith(r"C:\Windows\System32") or exe_part.startswith(r"C:\Windows\SysWOW64")):
        return True
    return False


def _collect_windows_services():
    services = []
    if os.name != "nt":
        return services

    ps_script = """
    try {
        Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, StartMode, PathName, StartName, ProcessId | ConvertTo-Json -Compress
    } catch {}
    """
    res = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=15)
    if res["stdout"] and res["stdout"].startswith(("[", "{")):
        try:
            import json
            parsed = json.loads(res["stdout"])
            if isinstance(parsed, dict):
                parsed = [parsed]
            for item in parsed:
                path = item.get("PathName") or ""
                unquoted_vuln = _is_unquoted_vulnerable(path)
                is_suspicious = any(p in path.lower() for p in [r"\temp", r"\downloads", "powershell", "wscript", "cscript", "mshta", "cmd.exe /c"]) or unquoted_vuln

                services.append({
                    "name": item.get("Name", ""),
                    "display_name": item.get("DisplayName", ""),
                    "state": item.get("State", ""),
                    "start_mode": item.get("StartMode", ""),
                    "path_name": path,
                    "account": item.get("StartName", ""),
                    "pid": item.get("ProcessId", 0),
                    "unquoted_path_vuln": unquoted_vuln,
                    "is_suspicious": is_suspicious,
                })
        except Exception:
            pass

    return services


def _collect_linux_services():
    services = []
    res = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-pager"], timeout=10)
    if res["stdout"]:
        for line in res["stdout"].splitlines():
            line = line.strip()
            if line.endswith(".service") or ".service" in line:
                parts = line.split()
                if len(parts) >= 4:
                    services.append({
                        "name": parts[0],
                        "display_name": " ".join(parts[4:]) if len(parts) > 4 else parts[0],
                        "state": parts[3],
                        "start_mode": parts[1],
                        "path_name": "",
                        "account": "root",
                        "pid": 0,
                        "unquoted_path_vuln": False,
                        "is_suspicious": False,
                    })
    return services


def collect_services():
    """Collects system services with status, execution binary, service account, and vulnerability analysis."""
    if os.name == "nt":
        return _collect_windows_services()
    else:
        return _collect_linux_services()
