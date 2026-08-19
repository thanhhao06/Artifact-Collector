from collectors.image.utils_image import read_text_file


PACKAGE_LOGS = [
    "/var/log/apt/history.log",
    "/var/log/apt/term.log",
    "/var/log/dpkg.log",
    "/var/log/yum.log",
    "/var/log/dnf.log",
]


def collect_linux_package_history(fs):
    rows = []
    for path in PACKAGE_LOGS:
        content = read_text_file(fs, path, max_size=2 * 1024 * 1024)
        if content:
            rows.append({
                "source": path,
                "content": content[-50000:],
            })
    return rows

