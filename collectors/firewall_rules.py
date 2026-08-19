import os
from utils.helpers import run_cmd

EXPOSED_PORTS = {"3389", "445", "135", "139", "5985", "5986", "22", "23", "21", "1433", "3306", "5432", "4444", "8080"}


def _collect_windows_firewall_rules():
    rules = []
    if os.name != "nt":
        return rules

    ps_script = """
    try {
        Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue | Select-Object -First 100 Name, DisplayName, DisplayGroup, Action, Profile, Description | ConvertTo-Json -Compress
    } catch {}
    """
    res = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=12)
    if res["stdout"] and res["stdout"].startswith(("[", "{")):
        try:
            import json
            parsed = json.loads(res["stdout"])
            if isinstance(parsed, dict):
                parsed = [parsed]
            for item in parsed:
                disp_name = item.get("DisplayName", "")
                name = item.get("Name", "")
                action = item.get("Action", "")
                profile = str(item.get("Profile", ""))

                is_sensitive = any(p in disp_name.lower() or p in name.lower() for p in ["remote desktop", "rdp", "smb", "file sharing", "winrm", "powershell", "wmic", "ssh", "telnet"])

                rules.append({
                    "name": name,
                    "display_name": disp_name,
                    "direction": "Inbound",
                    "action": "Allow" if action == 2 or str(action) == "Allow" else str(action),
                    "profile": profile,
                    "is_sensitive": is_sensitive,
                })
        except Exception:
            pass

    return rules


def _collect_linux_firewall():
    rules = []
    res = run_cmd(["iptables", "-L", "-n", "-v"], timeout=5)
    if res["stdout"]:
        for line in res["stdout"].splitlines():
            line = line.strip()
            if line and not line.startswith("Chain") and not line.startswith("pkts"):
                parts = line.split()
                if len(parts) >= 8:
                    rules.append({
                        "name": f"{parts[2]} {parts[7]}",
                        "display_name": line[:80],
                        "direction": "Inbound",
                        "action": parts[2],
                        "profile": "System iptables",
                        "is_sensitive": False
                    })
    return rules


def collect_firewall_rules():
    """Collects active firewall rules and incoming port exposure policies."""
    if os.name == "nt":
        return _collect_windows_firewall_rules()
    else:
        return _collect_linux_firewall()
