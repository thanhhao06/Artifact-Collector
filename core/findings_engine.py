import re


def _create_finding(fid, severity, tactic, technique, title, description, evidence, recommendation=""):
    return {
        "id": f"FIND-{fid:03d}",
        "severity": severity.lower(),
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "title": title,
        "description": description,
        "evidence": str(evidence),
        "recommendation": recommendation,
    }


def analyze_all_findings(**datasets):
    findings = []
    fid = 1

    # 1. PROCESSES ANALYSIS
    processes = datasets.get("processes", [])
    if isinstance(processes, list):
        for p in processes:
            name = p.get("name", "")
            cmdline = p.get("cmdline", "")
            exe = p.get("exe", "")
            pid = p.get("pid", "")
            threat_reasons = p.get("threat_reasons", [])

            # Temp execution
            if p.get("is_suspicious") and threat_reasons:
                for reason in threat_reasons:
                    sev = "high" if any(k in reason.lower() for k in ["shadow", "payload", "reverse", "masquerading"]) else "medium"
                    tech = "T1059.001" if "powershell" in reason.lower() else ("T1204" if "temp" in reason.lower() else "T1218")
                    findings.append(_create_finding(
                        fid, sev, "Execution", tech,
                        f"Suspicious Process Behavior: {name}",
                        reason,
                        f"PID {pid} ({name}) - Exe: {exe} | Cmd: {cmdline}",
                        "Analyze process tree, dump process memory, and inspect parent process."
                    ))
                    fid += 1

            # Vssadmin shadow deletion
            if "vssadmin" in cmdline.lower() and "delete shadows" in cmdline.lower():
                findings.append(_create_finding(
                    fid, "critical", "Defense Evasion / Impact", "T1490",
                    "Volume Shadow Copies Deletion (Ransomware Indicator)",
                    "A process attempted to delete volume shadow copies to prevent file recovery.",
                    f"PID {pid} | Cmd: {cmdline}",
                    "Isolate machine immediately, verify disk backup integrity, and inspect ransomware binaries."
                ))
                fid += 1

    # 2. EVENT LOGS ANALYSIS
    event_logs = datasets.get("event_logs", [])
    if isinstance(event_logs, list):
        failed_logons = 0
        for ev in event_logs:
            eid = str(ev.get("event_id", ""))
            summary = str(ev.get("summary", ""))

            # Audit Log cleared (1102 / 104)
            if eid in ["1102", "104"]:
                findings.append(_create_finding(
                    fid, "high", "Defense Evasion", "T1070.001",
                    "Security Audit Log or System Log Was Cleared",
                    "An event indicates the security audit log or system event log was explicitly cleared.",
                    f"Event ID {eid} | Time: {ev.get('timestamp')} | {summary}",
                    "Identify the user account that initiated log clearing and cross-reference with surrounding logs."
                ))
                fid += 1

            # Failed logon count
            if eid == "4625":
                failed_logons += 1

            # Service installation (7045)
            if eid == "7045":
                findings.append(_create_finding(
                    fid, "medium", "Persistence", "T1543.003",
                    "New Windows Service Installed",
                    "A new service was created on the system.",
                    f"Time: {ev.get('timestamp')} | {summary}",
                    "Review service binary path, creator account, and startup type."
                ))
                fid += 1

            # PowerShell Scriptblock (4104)
            if eid == "4104" and any(k in summary.lower() for k in ["downloadstring", "frombase64string", "iex", "invoke-expression"]):
                findings.append(_create_finding(
                    fid, "high", "Execution", "T1059.001",
                    "Suspicious PowerShell ScriptBlock Logged",
                    "PowerShell executed script block containing download cradles or Base64 decoding functions.",
                    f"Time: {ev.get('timestamp')} | {summary[:300]}...",
                    "Deobfuscate the script block payload and trace outbound C2 communication."
                ))
                fid += 1

        if failed_logons >= 3:
            findings.append(_create_finding(
                fid, "medium", "Credential Access", "T1110",
                f"Multiple Failed Logon Attempts Detected ({failed_logons} events)",
                "Multiple failed authentication attempts were recorded, which may indicate password spraying or brute force.",
                f"Total failed logon events: {failed_logons}",
                "Review source IP addresses and targeted usernames."
            ))
            fid += 1

    # 3. PERSISTENCE & AUTORUNS
    persistence = datasets.get("persistence", [])
    if isinstance(persistence, list):
        for item in persistence:
            if item.get("is_suspicious"):
                cat = item.get("category", "")
                cmd = item.get("command", "")
                loc = item.get("location", "")
                findings.append(_create_finding(
                    fid, "high" if "hijack" in cat.lower() else "medium", "Persistence", "T1547.001",
                    f"Suspicious Autorun / Persistence: {item.get('entry_name')}",
                    f"Persistence entry in '{cat}' contains suspicious scripts, temp directories, or hijack mechanisms.",
                    f"Location: {loc} | Value: {cmd}",
                    "Inspect binary on disk, check digital signature, and remove unauthorized entry."
                ))
                fid += 1

    # 4. SERVICES
    services = datasets.get("services", [])
    if isinstance(services, list):
        for s in services:
            if s.get("unquoted_path_vuln"):
                findings.append(_create_finding(
                    fid, "medium", "Privilege Escalation", "T1574.009",
                    f"Unquoted Service Path Vulnerability: {s.get('name')}",
                    "Service executable path contains spaces and lacks quotation marks, enabling local privilege escalation.",
                    f"Service: {s.get('display_name')} | Path: {s.get('path_name')}",
                    "Wrap the service binary path in double quotes in the Windows Registry."
                ))
                fid += 1
            elif s.get("is_suspicious"):
                findings.append(_create_finding(
                    fid, "high", "Persistence", "T1543.003",
                    f"Suspicious Service Binary Path: {s.get('name')}",
                    "Service references binaries residing in temporary or user-writable folders.",
                    f"Service: {s.get('display_name')} | Path: {s.get('path_name')}",
                    "Examine the service binary and verify authorization."
                ))
                fid += 1

    # 5. SCHEDULED TASKS
    tasks_data = datasets.get("scheduled_tasks", {})
    task_list = tasks_data.get("tasks", []) if isinstance(tasks_data, dict) else (tasks_data if isinstance(tasks_data, list) else [])
    for t in task_list:
        if t.get("is_suspicious"):
            findings.append(_create_finding(
                fid, "medium", "Persistence", "T1053.005",
                f"Suspicious Scheduled Task Action: {t.get('task_name')}",
                "Scheduled task executes scripts or binaries from temporary or non-standard paths.",
                f"Task: {t.get('task_name')} | Action: {t.get('action')}",
                "Review task author, triggers, and execution arguments."
            ))
            fid += 1

    # 6. NETWORK & LISTENING PORTS
    net_data = datasets.get("network_connections", {})
    connections = net_data.get("connections", []) if isinstance(net_data, dict) else (net_data if isinstance(net_data, list) else [])
    for c in connections:
        risk = c.get("risk_notes", "")
        if risk:
            findings.append(_create_finding(
                fid, "low", "Initial Access / Exposure", "T1071",
                f"Sensitive Network Port Active: {c.get('process_name') or 'System'}",
                f"Network socket is interacting with a sensitive service port: {risk}",
                f"Proto: {c.get('protocol')} | Local: {c.get('local_address')} | Remote: {c.get('remote_address')} | Status: {c.get('status')}",
                "Verify whether exposure on this port is legitimate and restricted by firewall."
            ))
            fid += 1

    # 7. USB DEVICES
    usb_devices = datasets.get("usb_devices", [])
    if isinstance(usb_devices, list) and len(usb_devices) > 0:
        findings.append(_create_finding(
            fid, "info", "Initial Access / Exfiltration", "T1052.001",
            f"USB Storage Device History Detected ({len(usb_devices)} devices)",
            "System contains records of external USB storage devices being attached.",
            f"Recent devices: " + ", ".join([d.get("friendly_name") or d.get("product") or d.get("serial_number") for d in usb_devices[:3]]),
            "Correlate USB serial numbers with physical hardware and user access records."
        ))
        fid += 1

    # 8. LINUX ARTIFACTS (From Disk Image or Live Linux)
    for item in datasets.get("linux_ssh_artifacts", []):
        source = item.get("source", "")
        if any(p in source for p in ["/dev/shm/", "/tmp/", "/var/tmp/"]):
            findings.append(_create_finding(
                fid, "high", "Credential Access", "T1552.004",
                "SSH Key Material Stored in Temporary Directory",
                "SSH private key or credential artifact found in volatile / user-writable temp path.",
                f"Source: {source}",
                "Determine how key was placed and revoke affected certificates/keys."
            ))
            fid += 1

    for item in datasets.get("linux_suspicious_files", []):
        findings.append(_create_finding(
            fid, "medium", "Execution", "T1204",
            "Suspicious Startup or Temporary Executable",
            "Suspicious executable or script detected in volatile Linux directories.",
            f"Source: {item.get('source')}",
            "Inspect binary file format and correlate with shell history."
        ))
        fid += 1

    # 8. POWERSHELL & SHELL TERMINAL HISTORY
    ps_history = datasets.get("powershell_history", [])
    if isinstance(ps_history, list):
        for item in ps_history:
            if item.get("is_suspicious"):
                cmd = item.get("command", "")
                user = item.get("user", "")
                sev = "critical" if any(k in cmd.lower() for k in ["mimikatz", "delete shadows", "vssadmin"]) else "high"
                tech = "T1059.001"
                findings.append(_create_finding(
                    fid, sev, "Execution", tech,
                    f"Suspicious Terminal Command Logged ({user})",
                    "A command in PSReadLine / Shell history contains known malicious keywords or download cradles.",
                    f"User: {user} | Line {item.get('line_number')}: {cmd[:300]}",
                    "Investigate user account, correlate with surrounding execution timestamps, and inspect dropped payloads."
                ))
                fid += 1

    # 9. EXECUTION EVIDENCE (Prefetch / BAM)
    exec_history = datasets.get("execution_history", [])
    if isinstance(exec_history, list):
        for item in exec_history:
            if item.get("is_suspicious"):
                app = item.get("application", "")
                src = item.get("source", "")
                fpath = item.get("file_path", "")
                findings.append(_create_finding(
                    fid, "medium", "Execution", "T1204",
                    f"Evidence of Suspicious Program Execution ({src}): {app}",
                    "Execution artifact indicates suspicious or temporary binary was executed.",
                    f"App: {app} | Path: {fpath} | Last Run: {item.get('last_execution_time')}",
                    "Inspect binary on disk, check digital signature, and correlate with timeline."
                ))
                fid += 1

    # Deduplicate findings by (title, evidence)
    deduped = []
    seen = set()
    for f in findings:
        key = (f["title"], f["evidence"])
        if key not in seen:
            deduped.append(f)
            seen.add(key)

    return deduped
