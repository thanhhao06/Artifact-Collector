from collectors.image.utils_image import safe_decode


def collect_prefetch_files(fs, windows_root):
    results = []
    prefetch_dir = f"{windows_root}/Prefetch"

    try:
        directory = fs.open_dir(prefetch_dir)
    except Exception:
        return results

    for entry in directory:
        try:
            name = safe_decode(entry.info.name.name)
            if name in [".", ".."]:
                continue
            if name.lower().endswith(".pf"):
                size = getattr(entry.info.meta, "size", 0) if entry.info.meta else 0
                results.append({
                    "prefetch_file": name,
                    "path_in_image": f"{prefetch_dir}/{name}",
                    "size": size
                })
        except Exception:
            continue

    return results
