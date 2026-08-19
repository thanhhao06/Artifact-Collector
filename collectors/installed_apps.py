import os
from utils.helpers import run_cmd

UNINSTALL_KEYS = [
    (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM 64-bit"),
    (r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM 32-bit"),
    (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU User"),
]


def _collect_windows_installed_apps():
    apps = []
    if os.name != "nt":
        return apps

    try:
        import winreg

        root_keys = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }

        for path_str, scope in UNINSTALL_KEYS:
            hive_prefix, subkey = path_str.split("\\", 1)
            hive = root_keys.get(hive_prefix)
            if not hive:
                continue

            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                count = winreg.QueryInfoKey(key)[0]
                for i in range(count):
                    try:
                        app_guid = winreg.EnumKey(key, i)
                        app_key = winreg.OpenKey(key, app_guid, 0, winreg.KEY_READ)

                        display_name = ""
                        try:
                            display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                        except FileNotFoundError:
                            pass

                        if not display_name:
                            winreg.CloseKey(app_key)
                            continue

                        display_version = ""
                        try:
                            display_version, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                        except FileNotFoundError:
                            pass

                        publisher = ""
                        try:
                            publisher, _ = winreg.QueryValueEx(app_key, "Publisher")
                        except FileNotFoundError:
                            pass

                        install_date = ""
                        try:
                            install_date, _ = winreg.QueryValueEx(app_key, "InstallDate")
                        except FileNotFoundError:
                            pass

                        install_location = ""
                        try:
                            install_location, _ = winreg.QueryValueEx(app_key, "InstallLocation")
                        except FileNotFoundError:
                            pass

                        uninstall_string = ""
                        try:
                            uninstall_string, _ = winreg.QueryValueEx(app_key, "UninstallString")
                        except FileNotFoundError:
                            pass

                        winreg.CloseKey(app_key)

                        apps.append({
                            "name": str(display_name),
                            "version": str(display_version),
                            "publisher": str(publisher),
                            "install_date": str(install_date),
                            "install_location": str(install_location),
                            "uninstall_string": str(uninstall_string),
                            "scope": scope,
                        })
                    except Exception:
                        pass
                winreg.CloseKey(key)
            except Exception:
                pass
    except Exception:
        pass

    # Sort alphabetically by app name
    apps.sort(key=lambda x: x["name"].lower())
    return apps


def _collect_linux_packages():
    packages = []
    # Debian/Ubuntu
    res = run_cmd(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"], timeout=8)
    if res["stdout"]:
        for line in res["stdout"].splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                packages.append({
                    "name": parts[0],
                    "version": parts[1],
                    "publisher": parts[2] if len(parts) > 2 else "",
                    "install_date": "",
                    "install_location": "",
                    "uninstall_string": f"apt remove {parts[0]}",
                    "scope": "System dpkg"
                })
        return packages

    # RPM / RHEL
    res_rpm = run_cmd(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"], timeout=8)
    if res_rpm["stdout"]:
        for line in res_rpm["stdout"].splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                packages.append({
                    "name": parts[0],
                    "version": parts[1],
                    "publisher": parts[2] if len(parts) > 2 else "",
                    "install_date": "",
                    "install_location": "",
                    "uninstall_string": f"rpm -e {parts[0]}",
                    "scope": "System rpm"
                })

    return packages


def collect_installed_apps():
    """Collects installed software and applications for triage inventory."""
    if os.name == "nt":
        return _collect_windows_installed_apps()
    else:
        return _collect_linux_packages()
