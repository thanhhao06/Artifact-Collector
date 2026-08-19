from collectors.image.utils_image import safe_decode


def collect_recent_files(fs, users):
    results = []

    for user in users:
        username = user["username"]
        recent_dir = f"{user['profile_path']}/AppData/Roaming/Microsoft/Windows/Recent"

        try:
            directory = fs.open_dir(recent_dir)
        except Exception:
            continue

        for entry in directory:
            try:
                name = safe_decode(entry.info.name.name)
                if name in [".", ".."]:
                    continue
                size = getattr(entry.info.meta, "size", 0) if entry.info.meta else 0
                results.append({
                    "username": username,
                    "recent_name": name,
                    "path_in_image": f"{recent_dir}/{name}",
                    "size": size
                })
            except Exception:
                continue

    return results
