import os
import glob
from pathlib import Path

SUSPICIOUS_PS_KEYWORDS = [
    "downloadstring", "downloadfile", "frombase64string", "iex", "invoke-expression",
    "bypass", "unrestricted", "encodedcommand", "mimikatz", "invoke-mimikatz",
    "add-mppreference", "disable-antivirus", "disable-realtime-monitoring",
    "stop-service", "vssadmin", "delete shadows", "net user /add", "net localgroup administrators /add",
    "whoami", "nltest", "invoke-webrequest", "iwr", "irm", "curl | bash", "bash -i"
]


def _collect_windows_powershell_history():
    history_entries = []
    if os.name != "nt":
        return history_entries

    system_drive = os.environ.get("SystemDrive", "C:")
    users_dir = os.path.join(system_drive, "\\Users")

    if not os.path.exists(users_dir):
        return history_entries

    try:
        for user_folder in os.listdir(users_dir):
            user_path = os.path.join(users_dir, user_folder)
            if not os.path.isdir(user_path) or user_folder.lower() in ["public", "default", "default user", "all users"]:
                continue

            ps_history_path = os.path.join(
                user_path, "AppData", "Roaming", "Microsoft", "Windows",
                "PowerShell", "PSReadLine", "ConsoleHost_history.txt"
            )

            if os.path.isfile(ps_history_path):
                try:
                    with open(ps_history_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    
                    for idx, line in enumerate(lines, start=1):
                        cmd = line.strip()
                        if not cmd:
                            continue
                        
                        lower_cmd = cmd.lower()
                        is_suspicious = any(kw in lower_cmd for kw in SUSPICIOUS_PS_KEYWORDS)
                        
                        history_entries.append({
                            "user": user_folder,
                            "line_number": idx,
                            "command": cmd,
                            "is_suspicious": is_suspicious,
                            "source_file": ps_history_path
                        })
                except Exception:
                    pass
    except Exception:
        pass

    return history_entries


def _collect_linux_shell_history():
    history_entries = []
    try:
        home_base = "/home"
        user_homes = [home_base + "/" + u for u in os.listdir(home_base)] if os.path.exists(home_base) else []
        user_homes.append("/root")

        for u_home in user_homes:
            if not os.path.isdir(u_home):
                continue
            username = os.path.basename(u_home)
            for hist_name in [".bash_history", ".zsh_history", ".history"]:
                hist_path = os.path.join(u_home, hist_name)
                if os.path.isfile(hist_path):
                    try:
                        with open(hist_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                        for idx, line in enumerate(lines, start=1):
                            cmd = line.strip()
                            if cmd:
                                lower_cmd = cmd.lower()
                                is_suspicious = any(kw in lower_cmd for kw in ["curl", "wget", "nc", "bash -i", "/dev/shm", "chmod +x", "base64 -d"])
                                history_entries.append({
                                    "user": username,
                                    "line_number": idx,
                                    "command": cmd,
                                    "is_suspicious": is_suspicious,
                                    "source_file": hist_path
                                })
                    except Exception:
                        pass
    except Exception:
        pass
    return history_entries


def collect_terminal_history():
    """Collects PowerShell console history and Linux shell history across all user profiles."""
    if os.name == "nt":
        return _collect_windows_powershell_history()
    else:
        return _collect_linux_shell_history()
