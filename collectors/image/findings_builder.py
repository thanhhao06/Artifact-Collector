def _finding(severity, category, title, evidence, recommendation=""):
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def build_findings(**datasets):
    findings = []

    for item in datasets.get("linux_shell_history", []):
        content = str(item.get("content", ""))
        if "ssh -i" in content and "root@localhost" in content:
            findings.append(_finding(
                "high",
                "credential_access",
                "Shell history shows SSH private key use toward root@localhost",
                f"{item.get('username')}: {item.get('source')}",
                "Review the referenced key material and correlate with SSH authentication logs.",
            ))

    for item in datasets.get("linux_logs", []):
        snippet = str(item.get("snippet", ""))
        if "Accepted publickey for root from 127.0.0.1" in snippet:
            findings.append(_finding(
                "high",
                "lateral_movement",
                "Root SSH login via public key from localhost detected",
                item.get("source", ""),
                "Correlate with shell history, SSH keys, and authorized_keys entries.",
            ))
        if "Server listening on 0.0.0.0 port 22" in snippet:
            findings.append(_finding(
                "info",
                "exposure",
                "SSH service listening on all interfaces",
                item.get("source", ""),
                "Validate intended exposure and hardening.",
            ))

    for item in datasets.get("linux_ssh_artifacts", []):
        source = item.get("source", "")
        if source.startswith("/dev/shm/") or source.startswith("/tmp/") or source.startswith("/var/tmp/"):
            findings.append(_finding(
                "high",
                "credential_access",
                "SSH-related artifact stored in temporary directory",
                source,
                "Review extracted file and determine whether key material was staged transiently.",
            ))
        if source.endswith("authorized_keys"):
            findings.append(_finding(
                "medium",
                "persistence",
                "authorized_keys present",
                source,
                "Review for unauthorized keys.",
            ))

    for item in datasets.get("linux_systemd", []):
        unit = item.get("unit_name", "")
        content = str(item.get("content", ""))
        if "/tmp/" in content or "/dev/shm/" in content or "/var/tmp/" in content:
            findings.append(_finding(
                "high",
                "persistence",
                "Systemd unit references temporary path",
                f"{unit}: {item.get('source', '')}",
                "Inspect the unit payload and referenced binary/script.",
            ))

    for item in datasets.get("linux_suspicious_files", []):
        findings.append(_finding(
            "medium",
            "execution",
            "Suspicious startup or temp-path file detected",
            item.get("source", ""),
            "Review extracted file contents and correlate with logs.",
        ))

    for item in datasets.get("linux_package_history", []):
        content = str(item.get("content", "")).lower()
        if "openssh" in content or "netcat" in content or "socat" in content:
            findings.append(_finding(
                "info",
                "tooling",
                "Package history references remote access tooling",
                item.get("source", ""),
                "Confirm whether installation time aligns with investigation timeline.",
            ))

    deduped = []
    seen = set()
    for finding in findings:
        key = (finding["title"], finding["evidence"])
        if key not in seen:
            deduped.append(finding)
            seen.add(key)
    return deduped
