import re


def _append(rows, timestamp, source, artifact_type, user, summary, extra=None):
    row = {
        "timestamp": timestamp or "",
        "source": source or "",
        "artifact_type": artifact_type,
        "user": user or "",
        "summary": summary or "",
    }
    if extra:
        row.update(extra)
    rows.append(row)


LOG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^ ]+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")


def build_timeline(**datasets):
    rows = []

    for item in datasets.get("browser_history", []):
        _append(rows, item.get("timestamp"), item.get("source_file"), "browser_history", item.get("username"), item.get("url"), {"browser": item.get("browser", "")})

    for item in datasets.get("linux_shell_history", []):
        for line in str(item.get("content", "")).splitlines():
            if line.strip():
                _append(rows, "", item.get("source"), "shell_history", item.get("username"), line.strip())

    for item in datasets.get("linux_cron", []):
        preview = " | ".join([line.strip() for line in str(item.get("content", "")).splitlines()[:3] if line.strip()])
        _append(rows, "", item.get("source"), "cron", item.get("owner"), preview)

    for item in datasets.get("linux_logs", []):
        for line in str(item.get("snippet", "")).splitlines():
            m = LOG_TS_RE.search(line)
            _append(rows, m.group(1) if m else "", item.get("source"), "log", "", line[:500])

    for item in datasets.get("linux_ssh_artifacts", []):
        _append(rows, "", item.get("source"), "ssh_artifact", item.get("owner"), item.get("classification"), {"sha256": item.get("sha256", "")})

    for item in datasets.get("linux_systemd", []):
        _append(rows, "", item.get("source"), "systemd", item.get("owner"), item.get("unit_name"))

    for item in datasets.get("linux_login_history", []):
        _append(rows, "", item.get("source"), "login_history", "", f"binary login record file ({item.get('size_bytes', 0)} bytes)")

    for item in datasets.get("linux_sudo", []):
        _append(rows, "", item.get("source"), "sudo", "", "sudo configuration")

    for item in datasets.get("linux_package_history", []):
        preview = str(item.get("content", "")).splitlines()[:3]
        _append(rows, "", item.get("source"), "package_history", "", " | ".join(preview))

    for item in datasets.get("linux_suspicious_files", []):
        _append(rows, "", item.get("source"), "suspicious_file", "", item.get("reason"), {"sha256": item.get("sha256", "")})

    rows.sort(key=lambda x: (x.get("timestamp") == "", x.get("timestamp", ""), x.get("artifact_type", ""), x.get("source", "")))
    return rows
