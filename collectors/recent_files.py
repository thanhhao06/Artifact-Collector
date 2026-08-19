import os
from datetime import datetime
from utils.helpers import format_file_size


def _collect_windows_recent_files(limit=150):
    recent_items = []
    if os.name != "nt":
        return recent_items

    user_profile = os.environ.get("USERPROFILE", "")
    recent_dir = os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Recent")

    if os.path.exists(recent_dir):
        try:
            entries = []
            for fname in os.listdir(recent_dir):
                if fname.lower() == "desktop.ini":
                    continue
                fpath = os.path.join(recent_dir, fname)
                try:
                    stat = os.stat(fpath)
                    entries.append((fpath, fname, stat.st_mtime, stat.st_size))
                except Exception:
                    pass

            # Sort newest first
            entries.sort(key=lambda x: x[2], reverse=True)

            for fpath, fname, mtime, size in entries[:limit]:
                iso_time = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S") if mtime > 0 else ""
                clean_name = fname[:-4] if fname.lower().endswith(".lnk") else fname

                recent_items.append({
                    "name": clean_name,
                    "filename": fname,
                    "path": fpath,
                    "size": size,
                    "size_formatted": format_file_size(size),
                    "modified_time": iso_time,
                    "type": "LNK Shortcut" if fname.lower().endswith(".lnk") else "Recent Item"
                })
        except Exception:
            pass

    return recent_items


def _collect_linux_recent_files(limit=100):
    recent_items = []
    xbel_path = os.path.expanduser("~/.local/share/recently-used.xbel")
    if os.path.exists(xbel_path):
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xbel_path)
            root = tree.getroot()
            for bookmark in root.findall(".//bookmark"):
                href = bookmark.get("href", "")
                visited = bookmark.get("visited", "") or bookmark.get("added", "")
                recent_items.append({
                    "name": os.path.basename(href),
                    "filename": os.path.basename(href),
                    "path": href,
                    "size": 0,
                    "size_formatted": "N/A",
                    "modified_time": visited,
                    "type": "XBEL Bookmark"
                })
        except Exception:
            pass
    return recent_items


def collect_recent_files():
    """Collects recent files and application shortcut artifacts."""
    if os.name == "nt":
        return _collect_windows_recent_files()
    else:
        return _collect_linux_recent_files()
