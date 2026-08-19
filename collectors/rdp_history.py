import os
import re
from pathlib import Path


def _collect_windows_remote_sessions():
    sessions = []
    if os.name != "nt":
        return sessions

    try:
        import winreg

        # 1. RDP MRU & Servers
        rdp_base = r"Software\Microsoft\Terminal Server Client"
        try:
            rdp_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rdp_base, 0, winreg.KEY_READ)

            # Check Default MRU
            try:
                def_key = winreg.OpenKey(rdp_key, "Default", 0, winreg.KEY_READ)
                count = winreg.QueryInfoKey(def_key)[1]
                for i in range(count):
                    try:
                        vname, vdata, _ = winreg.EnumValue(def_key, i)
                        if vname.startswith("MRU") and vdata:
                            sessions.append({
                                "client": "Remote Desktop (RDP)",
                                "category": "RDP MRU History",
                                "target_host": str(vdata),
                                "username": "",
                                "protocol": "RDP (Port 3389)",
                                "extra_details": f"Registry: {rdp_base}\\Default\\{vname}"
                            })
                    except Exception:
                        pass
                winreg.CloseKey(def_key)
            except Exception:
                pass

            # Check Servers
            try:
                srv_key = winreg.OpenKey(rdp_key, "Servers", 0, winreg.KEY_READ)
                sub_count = winreg.QueryInfoKey(srv_key)[0]
                for j in range(sub_count):
                    try:
                        server_name = winreg.EnumKey(srv_key, j)
                        s_key = winreg.OpenKey(srv_key, server_name, 0, winreg.KEY_READ)
                        user_hint = ""
                        try:
                            user_hint, _ = winreg.QueryValueEx(s_key, "UsernameHint")
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(s_key)

                        sessions.append({
                            "client": "Remote Desktop (RDP)",
                            "category": "RDP Saved Server",
                            "target_host": server_name,
                            "username": str(user_hint or ""),
                            "protocol": "RDP (Port 3389)",
                            "extra_details": f"Registry: {rdp_base}\\Servers\\{server_name}"
                        })
                    except Exception:
                        pass
                winreg.CloseKey(srv_key)
            except Exception:
                pass

            winreg.CloseKey(rdp_key)
        except Exception:
            pass

        # 2. PuTTY Sessions
        putty_base = r"Software\SimonTatham\PuTTY\Sessions"
        try:
            putty_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, putty_base, 0, winreg.KEY_READ)
            putty_count = winreg.QueryInfoKey(putty_key)[0]
            for k in range(putty_count):
                try:
                    session_name = winreg.EnumKey(putty_key, k)
                    sess_key = winreg.OpenKey(putty_key, session_name, 0, winreg.KEY_READ)
                    host = ""
                    port = 22
                    user = ""
                    proto = "SSH"
                    try:
                        host, _ = winreg.QueryValueEx(sess_key, "HostName")
                    except FileNotFoundError:
                        pass
                    try:
                        port, _ = winreg.QueryValueEx(sess_key, "PortNumber")
                    except FileNotFoundError:
                        pass
                    try:
                        user, _ = winreg.QueryValueEx(sess_key, "UserName")
                    except FileNotFoundError:
                        pass
                    try:
                        proto, _ = winreg.QueryValueEx(sess_key, "Protocol")
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(sess_key)

                    if host:
                        sessions.append({
                            "client": "PuTTY SSH",
                            "category": "Saved Session",
                            "target_host": f"{host}:{port}",
                            "username": str(user),
                            "protocol": str(proto).upper(),
                            "extra_details": f"Session Name: {session_name}"
                        })
                except Exception:
                    pass
            winreg.CloseKey(putty_key)
        except Exception:
            pass

        # 3. FileZilla Recent Servers
        user_profile = os.environ.get("USERPROFILE", "")
        fz_recent = os.path.join(user_profile, "AppData", "Roaming", "FileZilla", "recentservers.xml")
        if os.path.isfile(fz_recent):
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(fz_recent)
                root = tree.getroot()
                for srv in root.findall(".//Server"):
                    host = srv.findtext("Host", "")
                    port = srv.findtext("Port", "21")
                    user = srv.findtext("User", "")
                    proto = srv.findtext("Protocol", "FTP")
                    if host:
                        sessions.append({
                            "client": "FileZilla",
                            "category": "Recent FTP/SFTP Server",
                            "target_host": f"{host}:{port}",
                            "username": user,
                            "protocol": proto,
                            "extra_details": f"Source: {fz_recent}"
                        })
            except Exception:
                pass

        # 4. AnyDesk & TeamViewer Configs
        anydesk_conf = os.path.join(user_profile, "AppData", "Roaming", "AnyDesk", "user.conf")
        if os.path.isfile(anydesk_conf):
            try:
                with open(anydesk_conf, "r", errors="ignore") as f:
                    for line in f:
                        if "ad.session.recent" in line or "ad.roster.items" in line:
                            sessions.append({
                                "client": "AnyDesk Remote Control",
                                "category": "Recent Remote Connection",
                                "target_host": line.strip()[:100],
                                "username": "",
                                "protocol": "AnyDesk Proprietary",
                                "extra_details": f"Source: {anydesk_conf}"
                            })
            except Exception:
                pass

    except Exception:
        pass

    return sessions


def _collect_linux_remote_sessions():
    sessions = []
    # Known hosts
    known_hosts = os.path.expanduser("~/.ssh/known_hosts")
    if os.path.isfile(known_hosts):
        try:
            with open(known_hosts, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        host = parts[0].split(",")[0]
                        sessions.append({
                            "client": "OpenSSH",
                            "category": "SSH Known Host",
                            "target_host": host,
                            "username": "",
                            "protocol": "SSH (Port 22)",
                            "extra_details": f"Source: {known_hosts}"
                        })
        except Exception:
            pass

    return sessions


def collect_rdp_history():
    """Collects remote desktop (RDP), SSH, FTP, and remote management session history."""
    if os.name == "nt":
        return _collect_windows_remote_sessions()
    else:
        return _collect_linux_remote_sessions()
