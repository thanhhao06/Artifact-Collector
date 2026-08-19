from collectors.image.utils_image import read_file_bytes, write_extracted_file, sha256_hex

HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".mysql_history",
]


def _clean_shell_history(text):
    if not text:
        return ""
    cleaned = text.replace("\x00", "")
    lines = [line for line in cleaned.splitlines() if line.strip()]
    return "\n".join(lines) + ("\n" if lines else "")


def collect_linux_shell_history(fs, users, output_dir=None):
    rows = []
    for user in users:
        username = user["username"]
        profile_path = user["profile_path"]
        for filename in HISTORY_FILES:
            path = f"{profile_path}/{filename}"
            data = read_file_bytes(fs, path, max_size=1024 * 1024)
            if not data:
                continue
            content = _clean_shell_history(data.decode("utf-8", errors="ignore"))
            if not content:
                continue
            relpath = ""
            if output_dir:
                _, relpath = write_extracted_file(output_dir, f"{username}_{filename}", data)
            rows.append({
                "username": username,
                "source": path,
                "content": content,
                "sha256": sha256_hex(data),
                "extracted_file": relpath,
            })
    return rows
