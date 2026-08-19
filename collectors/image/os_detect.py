from collectors.image.filesystem_scan import detect_linux_root, detect_windows_root


def detect_os_family(fs):
    windows_root = detect_windows_root(fs)
    if windows_root:
        return {
            "os_family": "windows",
            "root_path": windows_root,
        }

    linux_root = detect_linux_root(fs)
    if linux_root:
        return {
            "os_family": "linux",
            "root_path": linux_root,
        }

    return {
        "os_family": "unknown",
        "root_path": None,
    }
