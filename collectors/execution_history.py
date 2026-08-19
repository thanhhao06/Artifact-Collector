import os
import struct
import codecs
from datetime import datetime
from utils.helpers import windows_filetime_to_iso, format_file_size


def _collect_windows_userassist():
    """
    Parses Windows UserAssist Registry (HKCU):
    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count
    Extracts ROT13 decoded application paths, run count, and last execution time.
    Works WITHOUT administrator privileges!
    """
    userassist_items = []
    if os.name != "nt":
        return userassist_items

    try:
        import winreg
        base_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        try:
            ua_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            return userassist_items

        subkeys_count = winreg.QueryInfoKey(ua_root)[0]
        for i in range(subkeys_count):
            guid_name = winreg.EnumKey(ua_root, i)
            count_path = f"{base_path}\\{guid_name}\\Count"
            try:
                count_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path, 0, winreg.KEY_READ)
                values_count = winreg.QueryInfoKey(count_key)[1]
                for j in range(values_count):
                    try:
                        raw_name, raw_bytes, val_type = winreg.EnumValue(count_key, j)
                        # Decode ROT-13
                        decoded_name = codecs.decode(raw_name, "rot_13")

                        # Remove UEME_RUNPATH: / UEME_RUNPIDL: prefix
                        clean_name = decoded_name
                        for prefix in ["UEME_RUNPATH:", "UEME_RUNPIDL:", "UEME_RUNCPL:", "UEME_RUNPIDL:%csidl2%\\"]:
                            if clean_name.startswith(prefix):
                                clean_name = clean_name[len(prefix):]

                        # Check if bytes contains execution telemetry (typically 72 bytes in Win7/10/11)
                        run_count = 0
                        iso_time = ""
                        if isinstance(raw_bytes, bytes) and len(raw_bytes) >= 68:
                            # Run count at offset 4 (4-byte int)
                            run_count = struct.unpack("<I", raw_bytes[4:8])[0]
                            # Last execution FILETIME at offset 60 (8-byte uint64)
                            filetime = struct.unpack("<Q", raw_bytes[60:68])[0]
                            if filetime > 0:
                                iso_time = windows_filetime_to_iso(filetime)

                        if clean_name and (run_count > 0 or iso_time):
                            app_base = os.path.basename(clean_name)
                            is_suspicious = any(p in clean_name.lower() for p in [r"\temp", r"\downloads", "powershell", "certutil", "mshta", "vssadmin", "mimikatz"])

                            userassist_items.append({
                                "source": "UserAssist (HKCU)",
                                "application": app_base or clean_name,
                                "prefetch_hash": f"Runs: {run_count}",
                                "last_execution_time": iso_time,
                                "file_size": f"{run_count} runs",
                                "is_suspicious": is_suspicious,
                                "file_path": clean_name
                            })
                    except Exception:
                        pass
                winreg.CloseKey(count_key)
            except Exception:
                pass
        winreg.CloseKey(ua_root)
    except Exception:
        pass

    return userassist_items


def _collect_windows_prefetch():
    prefetch_items = []
    if os.name != "nt":
        return prefetch_items

    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    prefetch_dir = os.path.join(sys_root, "Prefetch")

    if os.path.exists(prefetch_dir):
        try:
            entries = []
            for fname in os.listdir(prefetch_dir):
                if fname.lower().endswith(".pf"):
                    fpath = os.path.join(prefetch_dir, fname)
                    try:
                        stat = os.stat(fpath)
                        entries.append((fpath, fname, stat.st_mtime, stat.st_size))
                    except Exception:
                        pass

            # Sort newest execution first
            entries.sort(key=lambda x: x[2], reverse=True)

            for fpath, fname, mtime, size in entries[:250]:
                app_name = fname[:-3]
                app_hash = ""
                if "-" in app_name:
                    parts = app_name.rsplit("-", 1)
                    app_name = parts[0]
                    app_hash = parts[1]

                iso_time = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S") if mtime > 0 else ""
                is_suspicious = any(p in app_name.lower() for p in ["powershell", "certutil", "mshta", "vssadmin", "mimikatz", "rundll32", "bitsadmin", "wscript", "cscript"])

                prefetch_items.append({
                    "source": "Prefetch",
                    "application": app_name,
                    "prefetch_hash": app_hash,
                    "last_execution_time": iso_time,
                    "file_size": format_file_size(size),
                    "is_suspicious": is_suspicious,
                    "file_path": fpath
                })
        except Exception:
            pass

    return prefetch_items


def _collect_windows_bam():
    bam_items = []
    if os.name != "nt":
        return bam_items

    try:
        import winreg
        base_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        try:
            user_settings_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            base_path = r"SYSTEM\CurrentControlSet\Services\dam\UserSettings"
            try:
                user_settings_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ)
            except FileNotFoundError:
                return bam_items

        subkeys_count = winreg.QueryInfoKey(user_settings_key)[0]
        for i in range(subkeys_count):
            sid_name = winreg.EnumKey(user_settings_key, i)
            sid_path = f"{base_path}\\{sid_name}"
            try:
                sid_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sid_path, 0, winreg.KEY_READ)
                values_count = winreg.QueryInfoKey(sid_key)[1]
                for j in range(values_count):
                    try:
                        val_name, val_bytes, val_type = winreg.EnumValue(sid_key, j)
                        if isinstance(val_bytes, bytes) and len(val_bytes) >= 8:
                            filetime = struct.unpack("<Q", val_bytes[:8])[0]
                            iso_time = windows_filetime_to_iso(filetime)
                            app_name = os.path.basename(val_name)
                            is_suspicious = any(p in val_name.lower() for p in [r"\temp", r"\downloads", "powershell", "certutil", "mshta", "vssadmin"])

                            bam_items.append({
                                "source": "BAM Registry",
                                "application": app_name or val_name,
                                "prefetch_hash": sid_name,
                                "last_execution_time": iso_time,
                                "file_size": "N/A",
                                "is_suspicious": is_suspicious,
                                "file_path": val_name
                            })
                    except Exception:
                        pass
                winreg.CloseKey(sid_key)
            except Exception:
                pass

        winreg.CloseKey(user_settings_key)
    except Exception:
        pass

    return bam_items


def collect_execution_history():
    """Collects program execution history from UserAssist, Prefetch, and BAM."""
    results = []
    results.extend(_collect_windows_userassist())
    results.extend(_collect_windows_prefetch())
    results.extend(_collect_windows_bam())

    # Sort newest execution first
    results.sort(key=lambda x: x.get("last_execution_time") or "", reverse=True)
    return results
