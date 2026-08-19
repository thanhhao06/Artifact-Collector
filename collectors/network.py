import os
import re
import socket
import psutil
from utils.helpers import run_cmd

HIGH_RISK_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit Default",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    7001: "WebLogic",
    8080: "HTTP Proxy/Dev",
    8443: "HTTPS Dev",
    8888: "HTTP Alt",
    9001: "Tor / Remote Shell",
    27017: "MongoDB",
}


def _get_dns_cache():
    dns_entries = []
    if os.name == "nt":
        res = run_cmd(["ipconfig", "/displaydns"], timeout=10)
        if res["stdout"]:
            current_entry = {}
            for line in res["stdout"].splitlines():
                line = line.strip()
                if "Record Name" in line:
                    if current_entry.get("record_name"):
                        dns_entries.append(current_entry)
                        current_entry = {}
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current_entry["record_name"] = parts[1].strip()
                elif "Record Type" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current_entry["record_type"] = parts[1].strip()
                elif "Time To Live" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current_entry["ttl"] = parts[1].strip()
                elif any(k in line for k in ["A (Host) Record", "AAAA Record", "CNAME Record", "PTR Record"]):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current_entry["data"] = parts[1].strip()
            if current_entry.get("record_name"):
                dns_entries.append(current_entry)
    else:
        # On Linux, inspect /etc/hosts as baseline
        if os.path.exists("/etc/hosts"):
            try:
                with open("/etc/hosts", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_entries.append({
                                    "record_name": " ".join(parts[1:]),
                                    "record_type": "HOSTS",
                                    "ttl": "Static",
                                    "data": parts[0]
                                })
            except Exception:
                pass
    return dns_entries


def _get_arp_table():
    arp_entries = []
    res = run_cmd(["arp", "-a"], timeout=5)
    if res["stdout"]:
        current_interface = "Default"
        for line in res["stdout"].splitlines():
            line = line.strip()
            if "Interface:" in line:
                m = re.search(r"Interface:\s*([^\s]+)", line)
                if m:
                    current_interface = m.group(1)
            else:
                parts = line.split()
                if len(parts) >= 3:
                    ip, mac, arp_type = parts[0], parts[1], parts[2]
                    # Validate basic IPv4 or MAC format
                    if "." in ip and ("-" in mac or ":" in mac):
                        arp_entries.append({
                            "interface": current_interface,
                            "ip_address": ip,
                            "mac_address": mac,
                            "type": arp_type
                        })
    return arp_entries


def collect_network_connections():
    connections = []
    proc_cache = {}

    for conn in psutil.net_connections(kind="inet"):
        try:
            laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            local_port = conn.laddr.port if conn.laddr else None
            remote_port = conn.raddr.port if conn.raddr else None

            process_name = ""
            process_exe = ""
            process_user = ""
            if conn.pid:
                if conn.pid not in proc_cache:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_cache[conn.pid] = {
                            "name": p.name(),
                            "exe": p.exe(),
                            "user": p.username()
                        }
                    except Exception:
                        proc_cache[conn.pid] = {"name": "", "exe": "", "user": ""}
                cached = proc_cache[conn.pid]
                process_name = cached["name"]
                process_exe = cached["exe"]
                process_user = cached["user"]

            proto = "TCP" if conn.type == socket.SOCK_STREAM else ("UDP" if conn.type == socket.SOCK_DGRAM else str(conn.type))
            family = "IPv4" if conn.family == socket.AF_INET else ("IPv6" if conn.family == getattr(socket, "AF_INET6", 23) else str(conn.family))

            # Service risk analysis
            risk_notes = []
            if local_port in HIGH_RISK_PORTS and conn.status == "LISTEN":
                risk_notes.append(f"Listening on sensitive service port {local_port} ({HIGH_RISK_PORTS[local_port]})")
            if remote_port in HIGH_RISK_PORTS and conn.status == "ESTABLISHED":
                risk_notes.append(f"Outbound connection to sensitive service port {remote_port} ({HIGH_RISK_PORTS[remote_port]})")

            connections.append({
                "pid": conn.pid,
                "process_name": process_name,
                "process_exe": process_exe,
                "username": process_user,
                "protocol": proto,
                "family": family,
                "local_address": laddr_str,
                "local_port": local_port,
                "remote_address": raddr_str,
                "remote_port": remote_port,
                "status": conn.status or "UDP_OPEN",
                "risk_notes": " | ".join(risk_notes)
            })
        except Exception:
            continue

    return {
        "connections": connections,
        "dns_cache": _get_dns_cache(),
        "arp_table": _get_arp_table(),
    }
