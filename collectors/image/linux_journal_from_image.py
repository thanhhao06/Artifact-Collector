from collectors.image.utils_image import list_dir_names, path_exists, read_file_bytes, sha256_hex, write_extracted_file


def collect_linux_journal_artifacts(fs, output_dir=None):
    rows = []
    base = "/var/log/journal"
    if not path_exists(fs, base):
        return rows
    for machine_id in list_dir_names(fs, base):
        subdir = f"{base}/{machine_id}"
        if not path_exists(fs, subdir):
            continue
        for name in list_dir_names(fs, subdir):
            if not name.endswith(".journal"):
                continue
            path = f"{subdir}/{name}"
            data = read_file_bytes(fs, path, max_size=8 * 1024 * 1024)
            if not data:
                continue
            extracted_file = ""
            if output_dir:
                _, extracted_file = write_extracted_file(output_dir, path.strip("/").replace("/", "_"), data)
            rows.append({
                "source": path,
                "size_bytes": len(data),
                "sha256": sha256_hex(data),
                "extracted_file": extracted_file,
            })
    return rows
