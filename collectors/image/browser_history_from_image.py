import os
import re

from collectors.image.utils_image import path_exists, list_dir_names, read_file_bytes, write_extracted_file


def _sanitize_filename(value):
    value = str(value)
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value.strip("._") or "file"


def _collect_chromium_profiles(fs, root_path):
    rows = []
    if not path_exists(fs, root_path):
        return rows
    for name in list_dir_names(fs, root_path):
        if name == "Default" or name.startswith("Profile "):
            history_path = f"{root_path}/{name}/History"
            if path_exists(fs, history_path):
                rows.append({"profile_name": name, "history_path": history_path})
    if not rows and path_exists(fs, f"{root_path}/Default/History"):
        rows.append({"profile_name": "Default", "history_path": f"{root_path}/Default/History"})
    return rows


def _windows_browser_candidates(profile_path):
    return [
        {"browser": "Chrome", "root": f"{profile_path}/AppData/Local/Google/Chrome/User Data", "type": "chromium"},
        {"browser": "Edge", "root": f"{profile_path}/AppData/Local/Microsoft/Edge/User Data", "type": "chromium"},
        {"browser": "Chromium", "root": f"{profile_path}/AppData/Local/Chromium/User Data", "type": "chromium"},
        {"browser": "Firefox", "root": f"{profile_path}/AppData/Roaming/Mozilla/Firefox/Profiles", "type": "firefox"},
    ]


def _linux_browser_candidates(profile_path):
    return [
        {"browser": "Chrome", "root": f"{profile_path}/.config/google-chrome", "type": "chromium"},
        {"browser": "Chromium", "root": f"{profile_path}/.config/chromium", "type": "chromium"},
        {"browser": "Edge", "root": f"{profile_path}/.config/microsoft-edge", "type": "chromium"},
        {"browser": "Firefox", "root": f"{profile_path}/.mozilla/firefox", "type": "firefox"},
    ]


def collect_browser_history_from_image(fs, users, output_dir, os_family="windows"):
    extracted = []
    if not users:
        return extracted
    normalized_os = (os_family or "windows").lower()

    for user in users:
        username = user.get("username", "unknown")
        profile_path = user.get("profile_path", "")
        if not profile_path:
            continue
        browser_roots = _linux_browser_candidates(profile_path) if normalized_os == "linux" else _windows_browser_candidates(profile_path)

        for browser_entry in browser_roots:
            browser_name = browser_entry["browser"]
            root_path = browser_entry["root"]
            browser_type = browser_entry["type"]
            if browser_type == "chromium":
                for profile in _collect_chromium_profiles(fs, root_path):
                    source_path = profile["history_path"]
                    profile_name = profile["profile_name"]
                    data = read_file_bytes(fs, source_path, max_size=64 * 1024 * 1024)
                    if not data:
                        continue
                    out_name = _sanitize_filename(f"{normalized_os}_{username}_{browser_name}_{profile_name}_History.sqlite")
                    _, relpath = write_extracted_file(output_dir, out_name, data)
                    extracted.append({
                        "username": username,
                        "browser": browser_name,
                        "source_path": source_path,
                        "profile_name": profile_name,
                        "extracted_file": relpath,
                        "os_family": normalized_os,
                    })
            else:
                if not path_exists(fs, root_path):
                    continue
                for profile_name in list_dir_names(fs, root_path):
                    source_path = f"{root_path}/{profile_name}/places.sqlite"
                    if not path_exists(fs, source_path):
                        continue
                    data = read_file_bytes(fs, source_path, max_size=64 * 1024 * 1024)
                    if not data:
                        continue
                    out_name = _sanitize_filename(f"{normalized_os}_{username}_{browser_name}_{profile_name}_places.sqlite")
                    _, relpath = write_extracted_file(output_dir, out_name, data)
                    extracted.append({
                        "username": username,
                        "browser": browser_name,
                        "source_path": source_path,
                        "profile_name": profile_name,
                        "extracted_file": relpath,
                        "os_family": normalized_os,
                    })
    return extracted
