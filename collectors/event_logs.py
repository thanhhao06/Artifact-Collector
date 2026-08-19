import os
import re
from datetime import datetime
from utils.helpers import run_cmd

LOGON_TYPES = {
    "2": "Interactive (Console)",
    "3": "Network (SMB/RPC)",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials (RunAs)",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def _query_wevtutil_events(log_name, xpath_query, max_count=50):
    events = []
    if os.name != "nt":
        return events

    cmd = [
        "wevtutil", "qe", log_name,
        f"/q:{xpath_query}",
        f"/c:{max_count}",
        "/rd:true",
        "/f:text"
    ]
    res = run_cmd(cmd, timeout=12)
    if not res["stdout"]:
        return events

    current_event = {}
    for line in res["stdout"].splitlines():
        line = line.strip()
        if line.startswith("Event["):
            if current_event:
                events.append(current_event)
                current_event = {}
        elif ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip().replace(" ", "_").lower()
            val = parts[1].strip()
            if key:
                current_event[key] = val

    if current_event:
        events.append(current_event)

    return events


def _query_powershell_winevents(max_per_query=30):
    """Fallback / high-detail parser using PowerShell Get-WinEvent when available."""
    events = []
    if os.name != "nt":
        return events

    ps_script = f"""
    $events = @()
    $ids = @(4624, 4625, 4688, 7045, 1102, 104, 4104, 4720, 4732)
    try {{
        $raw = Get-WinEvent -FilterHashtable @{{LogName=@('Security','System','Microsoft-Windows-PowerShell/Operational'); Id=$ids}} -MaxEvents {max_per_query * 3} -ErrorAction SilentlyContinue
        foreach ($e in $raw) {{
            $msg = $e.Message -replace "`r`n", " " -replace "`n", " "
            if ($msg.Length -gt 400) {{ $msg = $msg.Substring(0, 400) + "..." }}
            [PSCustomObject]@{{
                Id = $e.Id
                ProviderName = $e.ProviderName
                TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                LevelDisplayName = $e.LevelDisplayName
                Message = $msg
            }}
        }} | ConvertTo-Json -Compress
    }} catch {{}}
    """
    res = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=15)
    if res["stdout"] and res["stdout"].startswith(("[", "{")):
        try:
            import json
            parsed = json.loads(res["stdout"])
            if isinstance(parsed, dict):
                parsed = [parsed]
            for item in parsed:
                event_id = str(item.get("Id", ""))
                category = "General"
                threat = "low"
                if event_id in ["1102", "104"]:
                    category = "Log Cleared / Tampering"
                    threat = "high"
                elif event_id == "4625":
                    category = "Failed Logon (Potential Brute-force)"
                    threat = "medium"
                elif event_id == "7045":
                    category = "New Service Installed (Persistence)"
                    threat = "medium"
                elif event_id == "4104":
                    category = "PowerShell Script Block Execution"
                    threat = "medium"
                elif event_id in ["4720", "4732"]:
                    category = "Account / Group Management"
                    threat = "medium"
                elif event_id == "4624":
                    category = "Successful Logon"
                    threat = "info"
                elif event_id == "4688":
                    category = "Process Creation"
                    threat = "info"

                events.append({
                    "event_id": event_id,
                    "timestamp": item.get("TimeCreated", ""),
                    "category": category,
                    "severity": threat,
                    "provider": item.get("ProviderName", ""),
                    "level": item.get("LevelDisplayName", ""),
                    "summary": item.get("Message", "")
                })
        except Exception:
            pass

    return events


def collect_live_event_logs():
    """Collects high-priority security event logs on live Windows systems."""
    if os.name != "nt":
        return []

    events = _query_powershell_winevents()
    if not events:
        # Fallback to wevtutil
        raw_sec = _query_wevtutil_events("Security", "*[System[(EventID=4624 or EventID=4625 or EventID=1102)]]", max_count=30)
        for ev in raw_sec:
            eid = ev.get("event_id", "") or ev.get("id", "")
            events.append({
                "event_id": eid,
                "timestamp": ev.get("date", "") or ev.get("timecreated", ""),
                "category": "Security Event",
                "severity": "high" if eid == "1102" else ("medium" if eid == "4625" else "info"),
                "provider": "Microsoft-Windows-Security-Auditing",
                "level": "Information",
                "summary": str(ev)
            })

    return events
