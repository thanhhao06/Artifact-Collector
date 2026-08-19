import os
import sys
import platform
import socket
import getpass
import time
from datetime import datetime, timezone
import psutil

from utils.helpers import format_file_size, run_cmd


def _is_admin():
    """Checks if the current script is running with elevated privileges (Admin/Root)."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def _get_uptime():
    try:
        boot_timestamp = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_timestamp)
        days, rem = divmod(uptime_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        boot_iso = datetime.fromtimestamp(boot_timestamp).strftime("%Y-%m-%d %H:%M:%S")
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s" if days > 0 else f"{hours}h {minutes}m {seconds}s"
        return boot_iso, uptime_str, uptime_seconds
    except Exception:
        return "", "", 0


def _get_cpu_info():
    try:
        cpu_name = platform.processor() or ""
        if os.name == "nt" and not cpu_name:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            cpu_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            winreg.CloseKey(key)
        return {
            "model": cpu_name.strip() if cpu_name else platform.machine(),
            "physical_cores": psutil.cpu_count(logical=False) or 0,
            "logical_cores": psutil.cpu_count(logical=True) or 0,
            "current_usage_percent": psutil.cpu_percent(interval=0.1),
        }
    except Exception:
        return {
            "model": platform.machine(),
            "physical_cores": 0,
            "logical_cores": 0,
            "current_usage_percent": 0,
        }


def _get_memory_info():
    try:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "total_ram": vm.total,
            "total_ram_formatted": format_file_size(vm.total),
            "available_ram": vm.available,
            "available_ram_formatted": format_file_size(vm.available),
            "used_ram": vm.used,
            "used_ram_formatted": format_file_size(vm.used),
            "ram_usage_percent": vm.percent,
            "total_swap": swap.total,
            "total_swap_formatted": format_file_size(swap.total),
            "used_swap": swap.used,
            "used_swap_formatted": format_file_size(swap.used),
            "swap_usage_percent": swap.percent,
        }
    except Exception:
        return {}


def _get_disk_partitions():
    disks = []
    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "opts": part.opts,
                    "total": usage.total,
                    "total_formatted": format_file_size(usage.total),
                    "used": usage.used,
                    "used_formatted": format_file_size(usage.used),
                    "free": usage.free,
                    "free_formatted": format_file_size(usage.free),
                    "percent": usage.percent,
                })
            except (PermissionError, OSError):
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "opts": part.opts,
                    "total": 0,
                    "total_formatted": "N/A",
                    "used": 0,
                    "used_formatted": "N/A",
                    "free": 0,
                    "free_formatted": "N/A",
                    "percent": 0,
                })
    except Exception:
        pass
    return disks


def _get_network_interfaces():
    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface_name, addr_list in addrs.items():
            ipv4_list = []
            ipv6_list = []
            mac_addr = ""

            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4_list.append({
                        "ip": addr.address,
                        "netmask": addr.netmask or "",
                        "broadcast": addr.broadcast or ""
                    })
                elif addr.family == getattr(socket, "AF_INET6", 23):
                    ipv6_list.append(addr.address)
                elif addr.family == getattr(psutil, "AF_LINK", -1) or str(addr.family) in ("AF_LINK", "17", "-1"):
                    mac_addr = addr.address

            stat = stats.get(iface_name)
            is_up = stat.isup if stat else True
            speed = f"{stat.speed} Mbps" if stat and stat.speed > 0 else "Unknown"

            interfaces.append({
                "name": iface_name,
                "is_up": is_up,
                "speed": speed,
                "mac": mac_addr,
                "ipv4": ipv4_list,
                "ipv6": ipv6_list,
            })
    except Exception:
        pass
    return interfaces


def _get_logged_in_users():
    users = []
    try:
        for u in psutil.users():
            users.append({
                "name": u.name,
                "terminal": u.terminal or "",
                "host": u.host or "",
                "started": datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S") if u.started else "",
                "pid": getattr(u, "pid", None)
            })
    except Exception:
        pass
    return users


def _get_os_detailed_info():
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
    }
    if os.name == "nt":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            product_name, _ = winreg.QueryValueEx(key, "ProductName")
            display_version, _ = winreg.QueryValueEx(key, "DisplayVersion")
            current_build, _ = winreg.QueryValueEx(key, "CurrentBuild")
            ubr, _ = winreg.QueryValueEx(key, "UBR")
            winreg.CloseKey(key)
            info["windows_edition"] = product_name
            info["windows_display_version"] = display_version
            info["windows_build"] = f"{current_build}.{ubr}"
        except Exception:
            pass
    elif os.name == "posix":
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if line.startswith("PRETTY_NAME="):
                            info["linux_distribution"] = line.strip().split("=", 1)[1].strip('"')
        except Exception:
            pass
    return info


def collect_system_info():
    boot_iso, uptime_str, uptime_sec = _get_uptime()
    now = datetime.now()
    now_utc = datetime.now(timezone.utc)

    # Safe environment variables
    env_vars = {}
    safe_keys = [
        "COMPUTERNAME", "USERDOMAIN", "USERNAME", "USERPROFILE", "OS", "PATH",
        "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PROCESSOR_IDENTIFIER",
        "NUMBER_OF_PROCESSORS", "LOGNAME", "HOME", "SHELL", "USER", "LANG"
    ]
    for k in safe_keys:
        if k in os.environ:
            env_vars[k] = os.environ[k]

    data = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "username": getpass.getuser(),
        "is_admin": _is_admin(),
        "current_time_local": now.strftime("%Y-%m-%d %H:%M:%S"),
        "current_time_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "timezone": time.tzname[0] if time.tzname else "",
        "boot_time": boot_iso,
        "uptime": uptime_str,
        "uptime_seconds": uptime_sec,
        "os_details": _get_os_detailed_info(),
        "cpu": _get_cpu_info(),
        "memory": _get_memory_info(),
        "disks": _get_disk_partitions(),
        "network_interfaces": _get_network_interfaces(),
        "logged_in_users": _get_logged_in_users(),
        "environment": env_vars,
    }

    # Flatten top-level keys for easy backward compatibility
    data["os"] = data["os_details"].get("os", platform.system())
    data["os_version"] = data["os_details"].get("os_version", platform.version())
    data["release"] = data["os_details"].get("release", platform.release())
    data["architecture"] = data["os_details"].get("architecture", platform.machine())
    data["current_time"] = data["current_time_local"]

    return data
