import re
from datetime import datetime


def _add_event(events, timestamp, category, source, user, action, extra=None):
    if not timestamp:
        return
    ev = {
        "timestamp": str(timestamp),
        "category": category,
        "source": source,
        "user": user or "",
        "action": action,
    }
    if extra and isinstance(extra, dict):
        ev.update(extra)
    events.append(ev)


def build_master_timeline(**datasets):
    events = []

    # 1. Processes creation
    processes = datasets.get("processes", [])
    if isinstance(processes, list):
        for p in processes:
            ts = p.get("create_time")
            if ts:
                _add_event(
                    events, ts, "Process Execution", "Live Process",
                    p.get("username"),
                    f"Process launched: {p.get('name')} (PID {p.get('pid')})",
                    {"cmdline": p.get("cmdline", ""), "sha256": p.get("sha256", "")}
                )

    # 2. Event logs
    event_logs = datasets.get("event_logs", [])
    if isinstance(event_logs, list):
        for el in event_logs:
            ts = el.get("timestamp")
            if ts:
                _add_event(
                    events, ts, "Security Event", f"Event Log {el.get('event_id')}",
                    "",
                    f"{el.get('category')}: {el.get('summary', '')[:200]}",
                    {"event_id": el.get("event_id"), "level": el.get("level")}
                )

    # 3. Browser History & Downloads
    browser_data = datasets.get("browser_history", {})
    if isinstance(browser_data, dict):
        for h in browser_data.get("history", []):
            ts = h.get("timestamp")
            if ts:
                _add_event(
                    events, ts, "Web Activity", f"{h.get('browser')} History",
                    h.get("profile"),
                    f"Visited: {h.get('title') or h.get('url')}",
                    {"url": h.get("url"), "visit_count": h.get("visit_count")}
                )
        for d in browser_data.get("downloads", []):
            ts = d.get("timestamp")
            if ts:
                _add_event(
                    events, ts, "File Download", f"{d.get('browser')} Download",
                    d.get("profile"),
                    f"Downloaded file: {d.get('filename')} ({d.get('size_formatted')}) from {d.get('url')}",
                    {"target_path": d.get("target_path")}
                )
    elif isinstance(browser_data, list):
        for item in browser_data:
            ts = item.get("timestamp")
            if ts:
                _add_event(
                    events, ts, "Web Activity", item.get("browser", "Browser"),
                    item.get("username") or item.get("profile", ""),
                    f"Visited: {item.get('url')}",
                    {"title": item.get("title", "")}
                )

    # 4. Recent Files
    recent_files = datasets.get("recent_files", [])
    if isinstance(recent_files, list):
        for r in recent_files:
            ts = r.get("modified_time")
            if ts:
                _add_event(
                    events, ts, "File Activity", "Recent Files",
                    "",
                    f"Accessed: {r.get('filename')} ({r.get('type')})",
                    {"path": r.get("path")}
                )

    # 5. Execution History (Prefetch / BAM)
    exec_history = datasets.get("execution_history", [])
    if isinstance(exec_history, list):
        for item in exec_history:
            ts = item.get("last_execution_time")
            if ts:
                _add_event(
                    events, ts, "Program Execution", f"Execution ({item.get('source')})",
                    "",
                    f"Executed: {item.get('application')}",
                    {"path": item.get("file_path"), "hash": item.get("prefetch_hash")}
                )

    # 6. Linux Logs & Shell History (Image mode)
    linux_logs = datasets.get("linux_logs", [])
    if isinstance(linux_logs, list):
        ts_re = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^ ]+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")
        for item in linux_logs:
            for line in str(item.get("snippet", "")).splitlines():
                m = ts_re.search(line)
                if m:
                    _add_event(events, m.group(1), "Linux Log", item.get("source", "Log"), "", line[:300])

    # Sort chronological (newest first or oldest first)
    events.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    return events
