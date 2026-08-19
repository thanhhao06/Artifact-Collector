import os
import csv
import io
import platform
import subprocess
from utils.helpers import run_cmd


def _parse_windows_tasks_csv(csv_text):
    tasks = []
    if not csv_text:
        return tasks

    try:
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            task_name = row.get("TaskName", "") or row.get("Task to Run", "")
            action = row.get("Task To Run", "") or row.get("Action", "") or row.get("Task to Run", "")
            next_run = row.get("Next Run Time", "")
            last_run = row.get("Last Run Time", "")
            status = row.get("Status", "") or row.get("Scheduled Task State", "")
            author = row.get("Author", "")

            is_suspicious = any(p in action.lower() for p in [r"\temp", r"\downloads", "powershell", "wscript", "cscript", "mshta", "-enc", "bitsadmin", "certutil"])

            tasks.append({
                "task_name": task_name,
                "action": action,
                "status": status,
                "next_run_time": next_run,
                "last_run_time": last_run,
                "author": author,
                "is_suspicious": is_suspicious
            })
    except Exception:
        pass
    return tasks


def _collect_windows_tasks():
    cmd = ["schtasks", "/query", "/fo", "csv", "/v"]
    result = run_cmd(cmd, timeout=20)
    parsed_tasks = _parse_windows_tasks_csv(result["stdout"])

    return {
        "os_family": "windows",
        "tasks": parsed_tasks,
        "raw_csv": result["stdout"],
        "return_code": result["return_code"],
        "stderr": result["stderr"],
    }


def _collect_linux_tasks():
    systemwide = run_cmd(["systemctl", "list-timers", "--all", "--no-pager"])
    user_crontab = run_cmd(["crontab", "-l"])
    etc_crontab = run_cmd(["cat", "/etc/crontab"])

    combined_text = []
    tasks = []
    for item in [systemwide, user_crontab, etc_crontab]:
        stdout = item.get("stdout", "")
        if stdout:
            combined_text.append(stdout)
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    tasks.append({
                        "task_name": line[:50],
                        "action": line,
                        "status": "Enabled",
                        "next_run_time": "",
                        "last_run_time": "",
                        "author": "system",
                        "is_suspicious": any(p in line for p in ["/tmp", "/dev/shm", "curl", "wget", "nc", "bash -i"])
                    })

    return {
        "os_family": "linux",
        "tasks": tasks,
        "raw_csv": "",
        "raw_text": "\n\n".join(combined_text),
        "return_code": 0 if any(item["return_code"] == 0 for item in [systemwide, user_crontab, etc_crontab]) else -1,
        "stderr": "",
    }


def collect_scheduled_tasks():
    system_name = platform.system().lower()

    if system_name == "windows":
        return _collect_windows_tasks()

    if system_name == "linux":
        return _collect_linux_tasks()

    return {
        "os_family": system_name or "unknown",
        "tasks": [],
        "raw_csv": "",
        "raw_text": "",
        "return_code": -1,
        "stderr": f"Unsupported platform: {platform.system()}",
    }
