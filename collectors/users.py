import os
from utils.helpers import run_cmd


def _collect_windows_users():
    users = []
    if os.name != "nt":
        return users

    # Get Local Administrators list
    admin_members = set()
    res_admin = run_cmd(["net", "localgroup", "administrators"], timeout=5)
    if res_admin["stdout"]:
        lines = res_admin["stdout"].splitlines()
        capture = False
        for line in lines:
            if "---" in line:
                capture = True
                continue
            if "The command completed" in line:
                break
            if capture and line.strip():
                admin_members.add(line.strip().lower())

    # Get local users via PowerShell or fallback
    ps_cmd = """
    try {
        Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon, Description, SID | ConvertTo-Json -Compress
    } catch {}
    """
    res = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], timeout=10)
    if res["stdout"] and res["stdout"].startswith(("[", "{")):
        try:
            import json
            parsed = json.loads(res["stdout"])
            if isinstance(parsed, dict):
                parsed = [parsed]
            for u in parsed:
                uname = str(u.get("Name", ""))
                is_adm = uname.lower() in admin_members or "admin" in uname.lower()
                pw_last_set = str(u.get("PasswordLastSet") or "")
                last_logon = str(u.get("LastLogon") or "")

                users.append({
                    "username": uname,
                    "enabled": u.get("Enabled", True),
                    "is_admin": is_adm,
                    "password_required": u.get("PasswordRequired", True),
                    "password_last_set": pw_last_set,
                    "last_logon": last_logon,
                    "description": str(u.get("Description") or ""),
                    "sid": str(u.get("SID", {}).get("Value", u.get("SID", ""))),
                })
        except Exception:
            pass

    if not users:
        # Fallback to net user
        res_nu = run_cmd(["net", "user"], timeout=5)
        if res_nu["stdout"]:
            lines = res_nu["stdout"].splitlines()
            capture = False
            for line in lines:
                if "---" in line:
                    capture = True
                    continue
                if "The command completed" in line:
                    break
                if capture:
                    for u in line.split():
                        if u.strip():
                            users.append({
                                "username": u.strip(),
                                "enabled": True,
                                "is_admin": u.strip().lower() in admin_members,
                                "password_required": True,
                                "password_last_set": "",
                                "last_logon": "",
                                "description": "",
                                "sid": ""
                            })
    return users


def _collect_linux_users():
    users = []
    sudo_members = set()

    if os.path.exists("/etc/group"):
        try:
            with open("/etc/group", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 4 and parts[0] in ["sudo", "wheel", "admin", "root"]:
                        members = parts[3].split(",")
                        for m in members:
                            if m:
                                sudo_members.add(m.strip())
        except Exception:
            pass

    if os.path.exists("/etc/passwd"):
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        uname = parts[0]
                        uid = parts[2]
                        gid = parts[3]
                        desc = parts[4]
                        home = parts[5]
                        shell = parts[6]
                        is_adm = (uname in sudo_members) or (uid == "0")

                        users.append({
                            "username": uname,
                            "enabled": shell not in ["/bin/false", "/usr/sbin/nologin", "/sbin/nologin"],
                            "is_admin": is_adm,
                            "password_required": True,
                            "password_last_set": "",
                            "last_logon": "",
                            "description": f"UID: {uid}, GID: {gid}, Home: {home}, Shell: {shell}",
                            "sid": uid
                        })
        except Exception:
            pass

    return users


def collect_users():
    """Collects local user accounts, administrative privileges, and security state."""
    if os.name == "nt":
        return _collect_windows_users()
    else:
        return _collect_linux_users()
