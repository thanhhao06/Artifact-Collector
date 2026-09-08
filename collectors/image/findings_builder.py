def _finding(severity, category, title, evidence, recommendation="", mitre_technique=""):
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "mitre_technique": mitre_technique,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def build_findings(**datasets):
    findings = []

    # 1. Linux / Image Shell Command History Analysis
    for item in datasets.get("linux_shell_history", []):
        cmd = str(item.get("command") or item.get("content") or "").strip()
        user = item.get("user") or item.get("username") or "unknown"
        line = item.get("line_number", "")
        loc_str = f"User: {user} | Line: {line}" if line else f"User: {user}"

        if not cmd:
            continue

        cmd_lower = cmd.lower()

        # Rule: Sudoers file modification / visudo (Privilege Escalation)
        if "visudo" in cmd_lower or "sudoers" in cmd_lower:
            findings.append(_finding(
                "high",
                "privilege_escalation",
                "Sudoers configuration modification attempted (visudo)",
                f"{loc_str} -> `{cmd}`",
                "Inspect /etc/sudoers and /etc/sudoers.d/ for unauthorized privilege delegations or NOPASSWD entries.",
                mitre_technique="T1548.003 (Sudo and Sudo Caching)"
            ))

        # Rule: Sensitive directory hopping / Path traversal into root/desktop
        if "../root" in cmd_lower or "myfirsthack" in cmd_lower or "../desktop" in cmd_lower:
            findings.append(_finding(
                "medium",
                "discovery",
                "Sensitive root / user workspace directory traversal",
                f"{loc_str} -> `{cmd}`",
                "Review files in referenced user directories to identify targeted evidence or compromised assets.",
                mitre_technique="T1083 (File and Directory Discovery)"
            ))

        # Rule: Log inspection / Anti-forensics recon
        if "/var/log" in cmd_lower or "auth.log" in cmd_lower or "syslog" in cmd_lower:
            findings.append(_finding(
                "low",
                "defense_evasion",
                "System log directory inspection / targeting",
                f"{loc_str} -> `{cmd}`",
                "Check for missing, truncated, or cleared log files in /var/log/.",
                mitre_technique="T1070.002 (Clear Linux Logs)"
            ))

        # Rule: CTF / Suspicious echo strings
        if "scream cake" in cmd_lower or "hint" in cmd_lower or "flag{" in cmd_lower or "c2" in cmd_lower:
            findings.append(_finding(
                "critical",
                "indicator_of_compromise",
                "Suspicious challenge flag / attacker breadcrumb in shell history",
                f"{loc_str} -> `{cmd}`",
                "Correlate the message payload with adversary actions and exercise objectives.",
                mitre_technique="T1027 (Indicator of Compromise)"
            ))

        # Rule: Package installation via sudo / package manager
        if "apt install" in cmd_lower or "apt-get install" in cmd_lower or "dpkg -i" in cmd_lower or "yum install" in cmd_lower:
            findings.append(_finding(
                "medium",
                "execution",
                "Software package installation via elevated package manager",
                f"{loc_str} -> `{cmd}`",
                "Verify if installed package was authorized or used as offensive tooling.",
                mitre_technique="T1059.004 (Unix Shell Execution)"
            ))

        # Rule: Network reconnaissance / Interface probing
        if any(tool in cmd_lower for tool in ["ifconfig", "ip a", "ifng", "netstat", "ss -", "nmap", "arp -a", "route"]):
            findings.append(_finding(
                "info",
                "discovery",
                "Network configuration & interface reconnaissance",
                f"{loc_str} -> `{cmd}`",
                "Review active network sockets and firewall rules.",
                mitre_technique="T1016 (System Network Configuration Discovery)"
            ))

        # Rule: SSH key usage or lateral movement
        if "ssh -i" in cmd_lower or "root@localhost" in cmd_lower or "ssh-keygen" in cmd_lower:
            findings.append(_finding(
                "high",
                "credential_access",
                "Shell history shows SSH private key utilization / local hopping",
                f"{loc_str} -> `{cmd}`",
                "Review referenced SSH key material and compare against authorized keys.",
                mitre_technique="T1552.004 (Private Keys)"
            ))

        # Rule: Ingress Tool Transfer / Downloaders
        if any(dl in cmd_lower for dl in ["curl ", "wget ", "nc -", "netcat", "socat", "python -c", "bash -i"]):
            findings.append(_finding(
                "high",
                "command_and_control",
                "Remote network downloader or interactive reverse shell syntax",
                f"{loc_str} -> `{cmd}`",
                "Inspect network destinations, downloaded payloads, and hash values.",
                mitre_technique="T1105 (Ingress Tool Transfer)"
            ))

    # 2. Linux Logs
    for item in datasets.get("linux_logs", []):
        snippet = str(item.get("snippet", ""))
        source = item.get("source", "")
        if "Accepted publickey for root from 127.0.0.1" in snippet or "Accepted password for root" in snippet:
            findings.append(_finding(
                "high",
                "lateral_movement",
                "Root SSH login detected",
                f"{source}: {snippet[:200]}",
                "Correlate with shell history, SSH keys, and authorized_keys entries.",
                mitre_technique="T1021.004 (SSH)"
            ))
        if "Server listening on 0.0.0.0 port 22" in snippet:
            findings.append(_finding(
                "info",
                "exposure",
                "SSH service listening on all interfaces (0.0.0.0:22)",
                f"{source}: {snippet[:200]}",
                "Validate intended exposure and sshd_config hardening settings.",
                mitre_technique="T1046 (Network Service Discovery)"
            ))

    # 3. SSH Artifacts & Carved Keys
    for item in datasets.get("linux_ssh_artifacts", []):
        source = item.get("source") or item.get("path") or item.get("name") or ""
        name = item.get("name", "")
        if "key" in name.lower() or "pem" in name.lower() or "rsa" in name.lower() or item.get("type") == "SSH Private Key":
            findings.append(_finding(
                "high",
                "credential_access",
                "SSH Private Key extracted from forensic image",
                f"Artifact: {source}",
                "Ensure private keys are rotated and assess potential unauthorized remote access.",
                mitre_technique="T1552.004 (Private Keys)"
            ))
        if source.endswith("authorized_keys"):
            findings.append(_finding(
                "medium",
                "persistence",
                "SSH authorized_keys file discovered",
                source,
                "Review public keys for unauthorized access credentials.",
                mitre_technique="T1098.004 (SSH Authorized Keys)"
            ))

    # 4. Systemd Persistence
    for item in datasets.get("linux_systemd", []):
        unit = item.get("unit_name", "")
        content = str(item.get("content", ""))
        source = item.get("source", "")
        if "/tmp/" in content or "/dev/shm/" in content or "/var/tmp/" in content:
            findings.append(_finding(
                "high",
                "persistence",
                "Systemd unit references volatile or temporary executable path",
                f"{unit}: {source}",
                "Inspect the unit payload and referenced binary or shell script.",
                mitre_technique="T1543.002 (Systemd Service)"
            ))

    # 5. Suspicious Files & Cron Jobs
    for item in datasets.get("linux_suspicious_files", []):
        findings.append(_finding(
            "medium",
            "execution",
            "Suspicious executable or script in startup/temp location",
            item.get("source", ""),
            "Review file hashes against threat intelligence repositories.",
            mitre_technique="T1059 (Command and Scripting Interpreter)"
        ))

    for item in datasets.get("linux_cron", []):
        content = str(item.get("content", ""))
        source = item.get("source", "")
        if "/tmp" in content or "curl" in content or "wget" in content or "python" in content:
            findings.append(_finding(
                "high",
                "persistence",
                "Suspicious scheduled cron job execution discovered",
                f"{source}: {content[:150]}",
                "Audit crontab entries and restrict cron scheduling permissions.",
                mitre_technique="T1053.003 (Cron)"
            ))

    # 6. Carved Databases & Artifacts
    for item in datasets.get("ad1_artifacts", []):
        art_type = item.get("type", "")
        name = item.get("name", "")
        if art_type == "Linux Password Hashes":
            findings.append(_finding(
                "critical",
                "credential_access",
                "Linux /etc/shadow password hash database recovered",
                f"Artifact: {name}",
                "Check for weak passwords and identify compromised system accounts.",
                mitre_technique="T1003.008 (/etc/passwd and /etc/shadow)"
            ))
        elif art_type == "Browser / App Database":
            findings.append(_finding(
                "low",
                "collection",
                f"Carved application/browser database ({name})",
                f"Database file: {name}",
                "Inspect database tables for extracted browser history, cookies, and stored sessions.",
                mitre_technique="T1217 (Browser Information Discovery)"
            ))

    # Deduplicate findings
    deduped = []
    seen = set()
    for finding in findings:
        key = (finding["title"], finding["evidence"])
        if key not in seen:
            deduped.append(finding)
            seen.add(key)

    # Sort findings by severity priority
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    deduped.sort(key=lambda x: sev_order.get(x.get("severity", "info"), 5))

    return deduped
