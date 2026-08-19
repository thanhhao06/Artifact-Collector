from collectors.image.utils_image import list_dir_names, read_text_file

CRON_PATHS = [
    "/etc/crontab",
    "/etc/anacrontab",
]


def collect_linux_cron_jobs(fs, users):
    rows = []
    for path in CRON_PATHS:
        content = read_text_file(fs, path, max_size=1024 * 1024)
        if content:
            rows.append({"source": path, "owner": "system", "content": content})

    for name in list_dir_names(fs, "/etc/cron.d"):
        path = f"/etc/cron.d/{name}"
        content = read_text_file(fs, path, max_size=1024 * 1024)
        if content:
            rows.append({"source": path, "owner": "system", "content": content})

    for user in users:
        username = user["username"]
        for path in [f"/var/spool/cron/crontabs/{username}", f"/var/spool/cron/{username}"]:
            content = read_text_file(fs, path, max_size=1024 * 1024)
            if content:
                rows.append({"source": path, "owner": username, "content": content})

    return rows
