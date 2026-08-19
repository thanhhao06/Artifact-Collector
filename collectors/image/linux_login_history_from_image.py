from collectors.image.utils_image import read_file_bytes, write_extracted_file, sha256_hex


LOGIN_FILES = [
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/run/utmp",
]


def collect_linux_login_history(fs, output_dir=None):
    rows = []
    for path in LOGIN_FILES:
        data = read_file_bytes(fs, path, max_size=5 * 1024 * 1024)
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
