from collectors.image.utils_image import list_dir_names, path_exists, read_text_file


SYSTEMD_DIRS = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
]


def _collect_units_in_dir(fs, base_dir, owner):
    rows = []
    if not path_exists(fs, base_dir):
        return rows
    for name in list_dir_names(fs, base_dir):
        if not any(name.endswith(ext) for ext in [".service", ".timer", ".mount", ".path", ".socket", ".target"]):
            continue
        path = f"{base_dir}/{name}"
        content = read_text_file(fs, path, max_size=512 * 1024)
        if content:
            rows.append({
                "owner": owner,
                "source": path,
                "unit_name": name,
                "content": content,
            })
    return rows


def collect_linux_systemd_persistence(fs, users, output_dir=None):
    rows = []
    for base_dir in SYSTEMD_DIRS:
        rows.extend(_collect_units_in_dir(fs, base_dir, "system"))
    for user in users:
        base_dir = f"{user['profile_path']}/.config/systemd/user"
        rows.extend(_collect_units_in_dir(fs, base_dir, user["username"]))
    return rows
