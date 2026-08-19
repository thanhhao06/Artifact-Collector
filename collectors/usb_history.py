import os
import re
from utils.helpers import run_cmd


def _parse_usbstor_key_name(key_name):
    """
    Parses USBSTOR device instance string into vendor, product, revision.
    Example: Disk&Ven_SanDisk&Prod_Ultra_Fit&Rev_1.00 -> SanDisk, Ultra_Fit, 1.00
    """
    vendor = ""
    product = ""
    revision = ""
    device_type = "Disk"

    if "Disk&" in key_name or "CdRom&" in key_name:
        parts = key_name.split("&")
        for p in parts:
            if p.startswith("Ven_"):
                vendor = p[4:]
            elif p.startswith("Prod_"):
                product = p[5:]
            elif p.startswith("Rev_"):
                revision = p[4:]
    else:
        product = key_name

    return vendor, product, revision


def _get_mounted_device_mappings():
    """Reads HKLM\\SYSTEM\\MountedDevices to map serial numbers / device paths to drive letters (C:, D:, E:)."""
    mappings = {}
    if os.name != "nt":
        return mappings

    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices", 0, winreg.KEY_READ)
        count = winreg.QueryInfoKey(key)[1]
        for i in range(count):
            try:
                name, val_bytes, _ = winreg.EnumValue(key, i)
                if name.startswith(r"\DosDevices\\") or name.startswith(r"\DosDevices\?"):
                    drive_letter = name.replace(r"\DosDevices\\", "").replace(r"\DosDevices\?", "")
                    # val_bytes might contain unicode device path like _??_USBSTOR#Disk&Ven_...#{guid}
                    try:
                        val_str = val_bytes.decode("utf-16le", errors="ignore")
                        mappings[drive_letter] = val_str
                    except Exception:
                        pass
            except Exception:
                pass
        winreg.CloseKey(key)
    except Exception:
        pass
    return mappings


def _collect_windows_usb():
    devices = []
    if os.name != "nt":
        return devices

    mounted_maps = _get_mounted_device_mappings()

    try:
        import winreg
        base_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        try:
            usbstor_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            return devices

        device_types_count = winreg.QueryInfoKey(usbstor_key)[0]
        for i in range(device_types_count):
            dev_type_name = winreg.EnumKey(usbstor_key, i)
            vendor, prod, rev = _parse_usbstor_key_name(dev_type_name)

            type_key_path = f"{base_path}\\{dev_type_name}"
            try:
                type_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, type_key_path, 0, winreg.KEY_READ)
                instances_count = winreg.QueryInfoKey(type_key)[0]
                for j in range(instances_count):
                    serial_or_id = winreg.EnumKey(type_key, j)
                    inst_key_path = f"{type_key_path}\\{serial_or_id}"
                    friendly_name = ""
                    service = ""
                    container_id = ""

                    try:
                        inst_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, inst_key_path, 0, winreg.KEY_READ)
                        try:
                            friendly_name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                        except FileNotFoundError:
                            pass
                        try:
                            service, _ = winreg.QueryValueEx(inst_key, "Service")
                        except FileNotFoundError:
                            pass
                        try:
                            container_id, _ = winreg.QueryValueEx(inst_key, "ContainerID")
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(inst_key)
                    except Exception:
                        pass

                    # Look for associated drive letter in MountedDevices
                    associated_drive = ""
                    clean_serial = serial_or_id.split("&")[0]
                    for drive, path in mounted_maps.items():
                        if clean_serial.lower() in path.lower():
                            associated_drive = drive
                            break

                    devices.append({
                        "device_type": "USB Storage",
                        "vendor": vendor,
                        "product": prod,
                        "revision": rev,
                        "serial_number": serial_or_id,
                        "friendly_name": friendly_name or f"{vendor} {prod}".strip(),
                        "service": service,
                        "drive_letter": associated_drive,
                        "container_id": container_id,
                        "registry_path": inst_key_path
                    })
                winreg.CloseKey(type_key)
            except Exception:
                pass

        winreg.CloseKey(usbstor_key)
    except Exception:
        pass

    return devices


def _collect_linux_usb():
    devices = []
    res = run_cmd(["lsusb"], timeout=5)
    if res["stdout"]:
        for line in res["stdout"].splitlines():
            line = line.strip()
            # Bus 001 Device 002: ID 8087:8000 Intel Corp. Integrated Rate Matching Hub
            m = re.search(r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F:]+)\s+(.*)", line)
            if m:
                bus, dev, usb_id, desc = m.groups()
                devices.append({
                    "device_type": "USB Device",
                    "vendor": "",
                    "product": desc.strip(),
                    "revision": "",
                    "serial_number": f"Bus_{bus}_Dev_{dev}",
                    "friendly_name": desc.strip(),
                    "service": "",
                    "drive_letter": "",
                    "container_id": usb_id,
                    "registry_path": line
                })
    return devices


def collect_usb_history():
    """Collects USB storage history, serial numbers, vendor details, and drive mappings."""
    if os.name == "nt":
        return _collect_windows_usb()
    else:
        return _collect_linux_usb()
