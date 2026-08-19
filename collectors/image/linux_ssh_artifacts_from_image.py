from collectors.image.utils_image import list_dir_names, path_exists, read_file_bytes, read_text_file, sha256_hex, write_extracted_file


SSH_FILES = [
    ("authorized_keys", True),
    ("known_hosts", True),
    ("config", True),
    ("id_rsa", False),
    ("id_rsa.pub", True),
    ("id_ed25519", False),
    ("id_ed25519.pub", True),
]


SYSTEM_SSH_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
]


def _artifact_row(owner, source, content, data, classification, extracted_file=""):
    return {
        "owner": owner,
        "source": source,
        "classification": classification,
        "content": content,
        "sha256": sha256_hex(data),
        "extracted_file": extracted_file,
    }


def collect_linux_ssh_artifacts(fs, users, output_dir=None):
    rows = []

    for path in SYSTEM_SSH_FILES:
        content = read_text_file(fs, path, max_size=1024 * 1024)
        if content:
            rows.append(_artifact_row("system", path, content, content.encode("utf-8", errors="ignore"), "ssh_config"))

    search_dirs = ["/dev/shm", "/tmp", "/var/tmp"]
    for search_dir in search_dirs:
        for name in list_dir_names(fs, search_dir):
            if name.startswith("id_") or name.endswith(".pub") or "authorized_keys" in name:
                path = f"{search_dir}/{name}"
                data = read_file_bytes(fs, path, max_size=1024 * 1024)
                if not data:
                    continue
                content = data.decode("utf-8", errors="ignore")
                extracted_file = ""
                if output_dir:
                    _, extracted_file = write_extracted_file(output_dir, f"ssh_temp_{name}", data)
                rows.append(_artifact_row("system", path, content, data, "ssh_temp_artifact", extracted_file))

    for user in users:
        username = user["username"]
        profile_path = user["profile_path"]
        ssh_dir = f"{profile_path}/.ssh"
        if not path_exists(fs, ssh_dir):
            continue
        for name, is_text in SSH_FILES:
            path = f"{ssh_dir}/{name}"
            data = read_file_bytes(fs, path, max_size=1024 * 1024)
            if not data:
                continue
            content = data.decode("utf-8", errors="ignore") if is_text else ""
            extracted_file = ""
            if output_dir:
                _, extracted_file = write_extracted_file(output_dir, f"{username}_{name}", data)
            rows.append(_artifact_row(username, path, content, data, "user_ssh_artifact", extracted_file))

    return rows
