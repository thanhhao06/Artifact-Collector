def collect_registry_hives(fs, windows_root):
    results = []
    config_dir = f"{windows_root}/System32/config"

    hive_names = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"]

    for hive in hive_names:
        path = f"{config_dir}/{hive}"
        try:
            f = fs.open(path)
            size = getattr(f.info.meta, "size", 0)
            results.append({
                "hive_name": hive,
                "path_in_image": path,
                "size": size,
                "status": "found"
            })
        except Exception:
            results.append({
                "hive_name": hive,
                "path_in_image": path,
                "size": 0,
                "status": "not_found"
            })

    return results
