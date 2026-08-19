def _safe_decode(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _meta_type_to_name(meta_type):
    try:
        import pytsk3
        mapping = {
            getattr(pytsk3, "TSK_FS_META_TYPE_REG", None): "file",
            getattr(pytsk3, "TSK_FS_META_TYPE_DIR", None): "dir",
            getattr(pytsk3, "TSK_FS_META_TYPE_LNK", None): "symlink",
            getattr(pytsk3, "TSK_FS_META_TYPE_FIFO", None): "fifo",
            getattr(pytsk3, "TSK_FS_META_TYPE_CHR", None): "char",
            getattr(pytsk3, "TSK_FS_META_TYPE_BLK", None): "block",
            getattr(pytsk3, "TSK_FS_META_TYPE_SOCK", None): "socket",
            getattr(pytsk3, "TSK_FS_META_TYPE_SHAD", None): "shadow",
            getattr(pytsk3, "TSK_FS_META_TYPE_WHT", None): "whiteout",
            getattr(pytsk3, "TSK_FS_META_TYPE_VIRT", None): "virtual",
        }
        if meta_type in mapping and mapping[meta_type]:
            return mapping[meta_type]
    except Exception:
        pass
    return {
        1: "file",
        2: "dir",
        3: "fifo",
        4: "char",
        5: "block",
        6: "symlink",
        7: "socket",
        8: "shadow",
        9: "whiteout",
        10: "virtual",
    }.get(meta_type, "unknown")


def _read_symlink_target(fs, path, max_size=4096):
    try:
        file_obj = fs.open(path)
        data = file_obj.read_random(0, max_size)
        return _safe_decode(data).strip("\x00").strip()
    except Exception:
        return ""


def list_root_entries(fs):
    results = []
    try:
        root_dir = fs.open_dir("/")
    except Exception as exc:
        return [{"name": "", "type": "error", "error": str(exc), "size": 0}]

    for entry in root_dir:
        try:
            name = _safe_decode(entry.info.name.name)
            if name in [".", ".."]:
                continue
            meta = getattr(entry.info, "meta", None)
            size = getattr(meta, "size", 0) if meta else 0
            meta_type = getattr(meta, "type", None) if meta else None
            entry_type = _meta_type_to_name(meta_type)
            row = {"name": name, "type": entry_type, "size": size}
            if entry_type == "symlink":
                target = _read_symlink_target(fs, f"/{name}")
                if target:
                    row["link_target"] = target
            results.append(row)
        except Exception:
            continue
    return results
