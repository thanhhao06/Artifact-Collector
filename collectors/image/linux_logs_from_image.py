import re

from collectors.image.utils_image import read_text_file

LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
]

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^ ]+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")


def collect_linux_log_snippets(fs):
    rows = []
    for path in LOG_PATHS:
        content = read_text_file(fs, path, max_size=2 * 1024 * 1024)
        if content:
            snippet = content[-20000:]
            first_ts = ""
            for line in snippet.splitlines():
                m = _TS_RE.search(line)
                if m:
                    first_ts = m.group(1)
                    break
            rows.append({
                "source": path,
                "snippet": snippet,
                "first_timestamp_hint": first_ts,
            })
    return rows
