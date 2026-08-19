import os
import json


def _format_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=False)
    return str(value)


def _build_notes(mode, summary_data):
    notes = []
    if mode == "file":
        notes.append("File mode performs offline triage against a disk image.")
        notes.append("Live artifacts such as current processes and current network connections are not available offline.")
        notes.append("Offline artifacts can include browser history, cron or scheduled task data, logs, registry hives, prefetch files, shell history, SSH artifacts, systemd persistence, package history, and suspicious-file extraction depending on the operating system.")
        if summary_data.get("linux_cron_jobs_count", 0) or summary_data.get("linux_log_snippets_count", 0) or summary_data.get("linux_shell_history_count", 0):
            notes.append("Linux artifacts were detected in this image.")
        if summary_data.get("scheduled_tasks_count", 0) or summary_data.get("prefetch_count", 0) or summary_data.get("registry_hives_count", 0):
            notes.append("Windows artifacts were detected in this image.")
        if summary_data.get("findings_count", 0):
            notes.append("Review findings.json and timeline.csv first for the highest-value triage summary.")
    elif mode == "local":
        notes.append("Local mode performs live triage on the current host.")
        notes.append("Results depend on the current operating system and the privileges of the running user.")
    return notes


def write_summary_report(output_dir, mode, summary_data):
    report_path = os.path.join(output_dir, "summary_report.txt")
    lines = []
    lines.append("Artifact Collector - Summary Report")
    lines.append("=" * 60)
    lines.append(f"Mode: {mode}")
    lines.append("")
    for key, value in summary_data.items():
        lines.append(f"{key}:")
        lines.append(_format_value(value))
        lines.append("")
    notes = _build_notes(mode, summary_data)
    if notes:
        lines.append("[Notes]")
        for note in notes:
            lines.append(f"- {note}")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
