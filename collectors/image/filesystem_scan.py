from collectors.image.utils_image import safe_decode


def _safe_decode_name(name_obj):
    try:
        if isinstance(name_obj, bytes):
            return name_obj.decode("utf-8", errors="ignore")
        return str(name_obj)
    except Exception:
        return ""


def list_partitions(img):
    import pytsk3

    partitions = []
    try:
        volume = pytsk3.Volume_Info(img)
    except Exception:
        return partitions

    for part in volume:
        desc = _safe_decode_name(part.desc)
        partitions.append({
            "addr": getattr(part, "addr", None),
            "start": getattr(part, "start", None),
            "len": getattr(part, "len", None),
            "desc": desc,
            "flags": getattr(part, "flags", None),
        })
    return partitions


def open_filesystems(img):
    import pytsk3

    filesystems = []
    try:
        volume = pytsk3.Volume_Info(img)
        for part in volume:
            desc = _safe_decode_name(part.desc).lower()
            if "unallocated" in desc:
                continue
            if getattr(part, "len", 0) <= 0:
                continue

            offset = part.start * 512
            try:
                fs = pytsk3.FS_Info(img, offset=offset)
                filesystems.append({
                    "partition_addr": getattr(part, "addr", None),
                    "partition_desc": _safe_decode_name(part.desc),
                    "offset": offset,
                    "fs": fs,
                })
            except Exception:
                continue
    except Exception:
        try:
            fs = pytsk3.FS_Info(img)
            filesystems.append({
                "partition_addr": None,
                "partition_desc": "single filesystem",
                "offset": 0,
                "fs": fs,
            })
        except Exception:
            pass

    return filesystems


def path_exists(fs, path):
    try:
        fs.open(path)
        return True
    except Exception:
        return False


def _walk_dirs(fs, current_path="/", depth=0, max_depth=4):
    results = []
    if depth > max_depth:
        return results

    try:
        directory = fs.open_dir(current_path)
    except Exception:
        return results

    for entry in directory:
        try:
            name = safe_decode(entry.info.name.name)
            if name in [".", ".."]:
                continue

            meta = entry.info.meta
            if not meta or getattr(meta, "type", None) != 2:
                continue

            full_path = f"{current_path}/{name}".replace("//", "/")
            results.append(full_path)
            results.extend(_walk_dirs(fs, full_path, depth + 1, max_depth))
        except Exception:
            continue

    return results


def detect_windows_root(fs):
    direct_candidates = ["/Windows", "/WINDOWS", "/windows", "/WINNT"]
    for candidate in direct_candidates:
        try:
            fs.open(candidate)
            return candidate
        except Exception:
            pass

    all_dirs = _walk_dirs(fs, "/", depth=0, max_depth=3)

    for path in all_dirs:
        low = path.lower()
        if low.endswith("/windows") or low == "/windows":
            return path

    return None


def detect_linux_root(fs):
    strong_indicators = ["/etc", "/var", "/home", "/usr", "/bin"]
    if all(path_exists(fs, path) for path in ["/etc", "/usr"]):
        if any(path_exists(fs, path) for path in ["/home", "/var", "/bin"]):
            return "/"

    all_dirs = set(_walk_dirs(fs, "/", depth=0, max_depth=2))
    for candidate in ["/rootfs", "/linux", "/mnt/root"]:
        if candidate in all_dirs and all(path_exists(fs, f"{candidate}{suffix}") for suffix in ["/etc", "/usr"]):
            return candidate

    if sum(1 for path in strong_indicators if path_exists(fs, path)) >= 3:
        return "/"

    return None


def list_windows_user_profiles(fs):
    users = []
    try:
        users_dir = fs.open_dir("/Users")
    except Exception:
        return users

    for entry in users_dir:
        try:
            name = _safe_decode_name(entry.info.name.name)
            if name in [".", "..", "All Users", "Default", "Default User", "Public", "desktop.ini"]:
                continue
            meta = getattr(entry.info, "meta", None)
            if meta and getattr(meta, "type", None) == 2:
                users.append({
                    "username": name,
                    "profile_path": f"/Users/{name}",
                })
        except Exception:
            continue

    return users


def list_linux_user_profiles(fs):
    users = []

    try:
        home_dir = fs.open_dir("/home")
        for entry in home_dir:
            try:
                name = _safe_decode_name(entry.info.name.name)
                if name in [".", ".."]:
                    continue
                meta = getattr(entry.info, "meta", None)
                if meta and getattr(meta, "type", None) == 2:
                    users.append({
                        "username": name,
                        "profile_path": f"/home/{name}",
                    })
            except Exception:
                continue
    except Exception:
        pass

    if path_exists(fs, "/root"):
        users.append({
            "username": "root",
            "profile_path": "/root",
        })

    deduped = []
    seen = set()
    for user in users:
        key = (user["username"], user["profile_path"])
        if key not in seen:
            deduped.append(user)
            seen.add(key)

    return deduped


def list_user_profiles(fs, os_family="windows"):
    if os_family == "linux":
        return list_linux_user_profiles(fs)
    return list_windows_user_profiles(fs)


def collect_filesystem_artifacts(image_path, image_handle=None):
    if image_handle is None:
        return {"partitions": [], "filesystems": [{"artifact_type": "error", "note": "image_handle is required"}]}

    img = image_handle["img"]

    partitions = list_partitions(img)
    filesystems = open_filesystems(img)

    results = []

    for fs_entry in filesystems:
        fs = fs_entry["fs"]
        windows_root = detect_windows_root(fs)
        linux_root = detect_linux_root(fs)
        os_family = "windows" if windows_root else "linux" if linux_root else "unknown"
        users = list_user_profiles(fs, os_family=os_family if os_family in ["windows", "linux"] else "windows") if os_family != "unknown" else []

        results.append({
            "artifact_type": "filesystem",
            "partition_addr": fs_entry["partition_addr"],
            "partition_desc": fs_entry["partition_desc"],
            "offset": fs_entry["offset"],
            "os_family": os_family,
            "windows_root": windows_root or "",
            "linux_root": linux_root or "",
            "user_count": len(users),
            "usernames": ", ".join([u["username"] for u in users]),
            "users": users,
        })

    if not results:
        results.append({
            "artifact_type": "filesystem",
            "status": "no_supported_filesystem_found",
            "image_path": image_path,
        })

    return {
        "partitions": partitions,
        "filesystems": results,
    }
