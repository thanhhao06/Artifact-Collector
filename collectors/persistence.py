import os
import glob
from pathlib import Path
from utils.helpers import run_cmd

RUN_REG_LOCATIONS = [
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM WOW64 Run"),
    (r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM WOW64 RunOnce"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policy Run"),
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policy Run"),
]


def _collect_windows_registry_autoruns():
    entries = []
    if os.name != "nt":
        return entries

    try:
        import winreg

        root_keys = {
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
        }

        for path_str, category in RUN_REG_LOCATIONS:
            hive_prefix, subkey = path_str.split("\\", 1)
            hive = root_keys.get(hive_prefix)
            if not hive:
                continue

            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    try:
                        val_name, val_data, val_type = winreg.EnumValue(key, i)
                        is_suspicious = any(p in str(val_data).lower() for p in [r"\temp", r"\downloads", "powershell", "wscript", "cscript", "mshta", "rundll32", "-enc"])
                        entries.append({
                            "category": category,
                            "location": path_str,
                            "entry_name": val_name,
                            "command": str(val_data),
                            "value_type": val_type,
                            "is_suspicious": is_suspicious
                        })
                    except Exception:
                        pass
                winreg.CloseKey(key)
            except Exception:
                pass

        # Check Winlogon Shell & Userinit
        try:
            wl_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 0, winreg.KEY_READ)
            shell_val, _ = winreg.QueryValueEx(wl_key, "Shell")
            userinit_val, _ = winreg.QueryValueEx(wl_key, "Userinit")
            winreg.CloseKey(wl_key)

            if shell_val and str(shell_val).lower() != "explorer.exe":
                entries.append({
                    "category": "Winlogon Hijack",
                    "location": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                    "entry_name": "Shell",
                    "command": str(shell_val),
                    "value_type": 1,
                    "is_suspicious": True
                })
            if userinit_val and not (r"userinit.exe" in str(userinit_val).lower()):
                entries.append({
                    "category": "Winlogon Hijack",
                    "location": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                    "entry_name": "Userinit",
                    "command": str(userinit_val),
                    "value_type": 1,
                    "is_suspicious": True
                })
        except Exception:
            pass

        # Check IFEO Debuggers
        try:
            ifeo_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_READ)
            subkeys_count = winreg.QueryInfoKey(ifeo_key)[0]
            for j in range(min(subkeys_count, 300)):
                try:
                    sub_name = winreg.EnumKey(ifeo_key, j)
                    sub_k = winreg.OpenKey(ifeo_key, sub_name, 0, winreg.KEY_READ)
                    try:
                        debugger, _ = winreg.QueryValueEx(sub_k, "Debugger")
                        if debugger:
                            entries.append({
                                "category": "IFEO Debugger Hijack",
                                "location": f"HKLM\\...\\Image File Execution Options\\{sub_name}",
                                "entry_name": sub_name,
                                "command": str(debugger),
                                "value_type": 1,
                                "is_suspicious": True
                            })
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(sub_k)
                except Exception:
                    pass
            winreg.CloseKey(ifeo_key)
        except Exception:
            pass

    except Exception:
        pass

    return entries


def _collect_windows_startup_folders():
    entries = []
    if os.name != "nt":
        return entries

    startup_dirs = [
        (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "User Startup Folder"),
        (os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"), "All Users Startup Folder"),
    ]

    for s_dir, category in startup_dirs:
        if os.path.exists(s_dir):
            try:
                for item in os.listdir(s_dir):
                    item_path = os.path.join(s_dir, item)
                    if os.path.isfile(item_path) and not item.lower() == "desktop.ini":
                        entries.append({
                            "category": category,
                            "location": s_dir,
                            "entry_name": item,
                            "command": item_path,
                            "value_type": "File",
                            "is_suspicious": any(ext in item.lower() for ext in [".bat", ".vbs", ".ps1", ".cmd", ".hta"])
                        })
            except Exception:
                pass
    return entries


def _collect_linux_persistence():
    entries = []
    if os.name == "nt":
        return entries

    # Check cron directories
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron"]
    for cp in cron_paths:
        if os.path.isfile(cp):
            try:
                with open(cp, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            entries.append({
                                "category": "Linux Cron",
                                "location": cp,
                                "entry_name": os.path.basename(cp),
                                "command": line,
                                "value_type": "Crontab",
                                "is_suspicious": "/tmp" in line or "/dev/shm" in line or "curl" in line or "wget" in line
                            })
            except Exception:
                pass
        elif os.path.isdir(cp):
            try:
                for fname in os.listdir(cp):
                    fpath = os.path.join(cp, fname)
                    if os.path.isfile(fpath):
                        entries.append({
                            "category": "Linux Cron Directory",
                            "location": cp,
                            "entry_name": fname,
                            "command": fpath,
                            "value_type": "CronJob",
                            "is_suspicious": False
                        })
            except Exception:
                pass

    # Check systemd user/system custom units
    systemd_paths = ["/etc/systemd/system", "/etc/systemd/user", "~/.config/systemd/user"]
    for sp in systemd_paths:
        expanded = os.path.expanduser(sp)
        if os.path.isdir(expanded):
            try:
                for fname in os.listdir(expanded):
                    if fname.endswith((".service", ".timer")):
                        entries.append({
                            "category": "Systemd Persistence",
                            "location": expanded,
                            "entry_name": fname,
                            "command": os.path.join(expanded, fname),
                            "value_type": "SystemdUnit",
                            "is_suspicious": False
                        })
            except Exception:
                pass

    return entries


def collect_persistence():
    """Collects autoruns and persistence mechanisms across Registry, Startup folders, and Linux services."""
    results = []
    if os.name == "nt":
        results.extend(_collect_windows_registry_autoruns())
        results.extend(_collect_windows_startup_folders())
    else:
        results.extend(_collect_linux_persistence())

    return results
