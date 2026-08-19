from collectors.image.utils_image import list_dir_names, path_exists, read_text_file


def collect_linux_sudo_artifacts(fs):
    rows = []
    for path in ["/etc/sudoers"]:
        content = read_text_file(fs, path, max_size=512 * 1024)
        if content:
            rows.append({"source": path, "content": content})

    sudoers_d = "/etc/sudoers.d"
    if path_exists(fs, sudoers_d):
        for name in list_dir_names(fs, sudoers_d):
            path = f"{sudoers_d}/{name}"
            content = read_text_file(fs, path, max_size=512 * 1024)
            if content:
                rows.append({"source": path, "content": content})
    return rows
