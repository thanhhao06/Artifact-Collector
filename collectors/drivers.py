import os
import csv
import io
from utils.helpers import run_cmd


def _collect_windows_drivers():
    drivers = []
    if os.name != "nt":
        return drivers

    res = run_cmd(["driverquery", "/v", "/fo", "csv"], timeout=12)
    if res["stdout"]:
        try:
            reader = csv.DictReader(io.StringIO(res["stdout"]))
            for row in reader:
                mod_name = row.get("Module Name", "")
                disp_name = row.get("Display Name", "")
                drv_type = row.get("Driver Type", "")
                link_date = row.get("Link Date", "")
                path = row.get("Path", "") or row.get("File Name", "")

                is_suspicious = bool(path and not path.lower().startswith(r"c:\windows\system32\drivers"))

                drivers.append({
                    "module_name": mod_name,
                    "display_name": disp_name,
                    "driver_type": drv_type,
                    "link_date": link_date,
                    "driver_path": path,
                    "is_suspicious": is_suspicious,
                })
        except Exception:
            pass

    return drivers


def _collect_linux_modules():
    modules = []
    res = run_cmd(["lsmod"], timeout=5)
    if res["stdout"]:
        for line in res["stdout"].splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3:
                modules.append({
                    "module_name": parts[0],
                    "display_name": parts[0],
                    "driver_type": "Kernel Module",
                    "link_date": "",
                    "driver_path": f"Size: {parts[1]} bytes, Used by: {parts[2]}",
                    "is_suspicious": False,
                })
    return modules


def collect_system_drivers():
    """Collects loaded kernel drivers, compile timestamps, and filesystem paths."""
    if os.name == "nt":
        return _collect_windows_drivers()
    else:
        return _collect_linux_modules()
