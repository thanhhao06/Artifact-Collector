from collectors.image.utils_image import list_dir_names, path_exists, read_file_bytes, sha256_hex, write_extracted_file


SUSPICIOUS_DIRS = ["/tmp", "/dev/shm", "/var/tmp"]
SUSPICIOUS_SUFFIXES = [".sh", ".py", ".pl", ".service", ".timer", ".socket", ".desktop"]
SUSPICIOUS_NAMES = ["rc.local", "authorized_keys", "id_rsa", "id_ed25519"]


def collect_linux_suspicious_files(fs, users, output_dir=None):
    rows = []
    candidate_dirs = list(SUSPICIOUS_DIRS)
    for user in users:
        candidate_dirs.extend([
            f"{user['profile_path']}/.config/autostart",
            f"{user['profile_path']}/.bashrc",
            f"{user['profile_path']}/.profile",
            f"{user['profile_path']}/.zshrc",
        ])
    candidate_dirs.extend(["/etc/rc.local"])

    seen = set()
    for path in candidate_dirs:
        if path in seen:
            continue
        seen.add(path)
        if not path_exists(fs, path):
            continue
        if path.endswith((".bashrc", ".profile", ".zshrc", "rc.local")):
            data = read_file_bytes(fs, path, max_size=512 * 1024)
            if not data:
                continue
            extracted_file = ""
            if output_dir:
                _, extracted_file = write_extracted_file(output_dir, path.strip("/").replace("/", "_"), data)
            rows.append({
                "source": path,
                "reason": "startup_script_or_shell_rc",
                "sha256": sha256_hex(data),
                "size_bytes": len(data),
                "extracted_file": extracted_file,
            })
            continue
        for name in list_dir_names(fs, path):
            if any(name.endswith(suf) for suf in SUSPICIOUS_SUFFIXES) or any(tok in name for tok in SUSPICIOUS_NAMES):
                full_path = f"{path}/{name}"
                data = read_file_bytes(fs, full_path, max_size=2 * 1024 * 1024)
                if not data:
                    continue
                extracted_file = ""
                if output_dir:
                    _, extracted_file = write_extracted_file(output_dir, full_path.strip("/").replace("/", "_"), data)
                rows.append({
                    "source": full_path,
                    "reason": "suspicious_name_or_location",
                    "sha256": sha256_hex(data),
                    "size_bytes": len(data),
                    "extracted_file": extracted_file,
                })
    return rows
