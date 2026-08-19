from collectors.image.utils_image import safe_decode


def collect_event_logs(fs, windows_root):
    results = []
    logs_dir = f"{windows_root}/System32/winevt/Logs"

    try:
        directory = fs.open_dir(logs_dir)
    except Exception:
        return results

    for entry in directory:
        try:
            name = safe_decode(entry.info.name.name)
            if name in [".", ".."]:
                continue
            if name.lower().endswith(".evtx"):
                size = getattr(entry.info.meta, "size", 0) if entry.info.meta else 0
                results.append({
                    "event_log_file": name,
                    "path_in_image": f"{logs_dir}/{name}",
                    "size": size
                })
        except Exception:
            continue

    return results
