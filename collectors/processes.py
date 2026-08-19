import os
import psutil
from datetime import datetime
from utils.helpers import calculate_file_hash, format_file_size

# Suspicious paths where binaries should not normally run from
SUSPICIOUS_PATH_PATTERNS = [
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\windows\temp",
    r"\users\public",
    r"\downloads",
    r"\perflogs",
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user",
]

# Living-off-the-land binaries (LOLBAS / GTFOBins) commonly abused
LOLBAS_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "certutil.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "wscript.exe", "cscript.exe",
    "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "net.exe", "net1.exe",
    "nltest.exe", "whoami.exe", "wmic.exe", "hh.exe", "reg.exe", "at.exe",
    "curl.exe", "wget.exe", "bash", "sh", "python", "python3", "perl", "ruby",
    "nc", "ncat", "socat"
}


def _analyze_suspicious(name, exe, cmdline):
    reasons = []
    lower_name = (name or "").lower()
    lower_exe = (exe or "").lower()
    lower_cmd = (cmdline or "").lower()

    # 1. Suspicious path check
    for pattern in SUSPICIOUS_PATH_PATTERNS:
        if pattern in lower_exe or pattern in lower_cmd:
            reasons.append(f"Execution from temp or public directory: {pattern}")
            break

    # 2. LOLBAS with suspicious arguments
    if lower_name in LOLBAS_NAMES:
        if any(term in lower_cmd for term in ["-enc", "-encodedcommand", "downloadstring", "iex", "frombase64string", "webclient"]):
            reasons.append("PowerShell/Script executing encoded or remote payload cradle")
        elif "certutil" in lower_name and any(term in lower_cmd for term in ["-urlcache", "-f", "http://", "https://"]):
            reasons.append("Certutil abused for file download")
        elif "vssadmin" in lower_name and "delete shadows" in lower_cmd:
            reasons.append("Vssadmin deleting shadow copies (Ransomware behavior)")
        elif "rundll32" in lower_name and any(ext in lower_cmd for ext in [".tmp", ".dat", ".png", ".jpg", ".txt"]):
            reasons.append("Rundll32 executing non-standard DLL/extension")
        elif "mshta" in lower_name and ("http" in lower_cmd or "vbscript" in lower_cmd or "javascript" in lower_cmd):
            reasons.append("Mshta executing remote or inline script")
        elif "wmic" in lower_name and "process call create" in lower_cmd:
            reasons.append("WMIC creating child process")
        elif any(term in lower_cmd for term in ["/bin/sh -i", "/bin/bash -i", "nc -e", "bash -i >&"]):
            reasons.append("Interactive reverse shell execution")

    # 3. Masquerading check
    if os.name == "nt":
        if lower_name in ["svchost.exe", "csrss.exe", "smss.exe", "lsass.exe", "services.exe", "wininit.exe"]:
            if lower_exe and not (r"\windows\system32" in lower_exe or r"\windows\syswow64" in lower_exe):
                reasons.append(f"Critical system process running from non-system location: {exe}")

    return len(reasons) > 0, reasons


def collect_processes():
    processes = []
    pid_to_name = {}

    # First pass: map PID to process name for parent lookup
    raw_proc_list = []
    for proc in psutil.process_iter([
        "pid", "ppid", "name", "username", "exe", "cmdline", "create_time", "status", "num_threads"
    ]):
        try:
            info = proc.info
            pid_to_name[info["pid"]] = info.get("name") or "unknown"
            raw_proc_list.append((proc, info))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Second pass: gather telemetry, hashes, memory, CPU, parent name and threat flags
    for proc, info in raw_proc_list:
        try:
            pid = info.get("pid")
            ppid = info.get("ppid")
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            cmdline_list = info.get("cmdline") or []
            cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list or "")
            username = info.get("username") or ""
            status = info.get("status") or ""
            threads = info.get("num_threads") or 0

            create_time_raw = info.get("create_time") or 0
            create_time_iso = datetime.fromtimestamp(create_time_raw).strftime("%Y-%m-%d %H:%M:%S") if create_time_raw > 0 else ""

            # Memory metrics
            mem_rss = 0
            mem_vms = 0
            mem_percent = 0.0
            try:
                mem_info = proc.memory_info()
                mem_rss = mem_info.rss
                mem_vms = mem_info.vms
                mem_percent = round(proc.memory_percent(), 2)
            except Exception:
                pass

            # CPU metric
            cpu_percent = 0.0
            try:
                cpu_percent = round(proc.cpu_percent(interval=0), 2)
            except Exception:
                pass

            # Executable Hash (SHA-256)
            sha256 = ""
            if exe and os.path.isfile(exe):
                sha256 = calculate_file_hash(exe, "sha256")

            # Threat detection / suspicious analysis
            is_suspicious, reasons = _analyze_suspicious(name, exe, cmdline)

            parent_name = pid_to_name.get(ppid, "")

            processes.append({
                "pid": pid,
                "ppid": ppid,
                "parent_name": parent_name,
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "username": username,
                "status": status,
                "create_time": create_time_iso,
                "create_time_raw": create_time_raw,
                "memory_rss": mem_rss,
                "memory_rss_formatted": format_file_size(mem_rss),
                "memory_vms": mem_vms,
                "memory_percent": mem_percent,
                "cpu_percent": cpu_percent,
                "num_threads": threads,
                "sha256": sha256,
                "is_suspicious": is_suspicious,
                "threat_reasons": reasons,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort processes by PID
    processes.sort(key=lambda x: x.get("pid") or 0)
    return processes
