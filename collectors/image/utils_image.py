import hashlib
import os


def safe_decode(data):
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    return str(data)


def get_meta_size(file_obj):
    try:
        meta = getattr(file_obj.info, "meta", None)
        if meta is not None:
            return getattr(meta, "size", 0) or 0
    except Exception:
        pass
    return 0


def read_file_bytes(fs, path, max_size=5 * 1024 * 1024):
    try:
        f = fs.open(path)
    except Exception:
        return b""
    size = get_meta_size(f)
    to_read = min(size, max_size) if size else max_size
    try:
        return f.read_random(0, to_read)
    except Exception:
        return b""


def read_text_file(fs, path, max_size=1024 * 1024):
    data = read_file_bytes(fs, path, max_size=max_size)
    if not data:
        return ""
    return data.decode("utf-8", errors="ignore")


def list_dir_names(fs, path):
    names = []
    try:
        directory = fs.open_dir(path)
        for entry in directory:
            try:
                name = safe_decode(entry.info.name.name)
                if name not in [".", ".."]:
                    names.append(name)
            except Exception:
                continue
    except Exception:
        pass
    return names


def path_exists(fs, path):
    try:
        fs.open(path)
        return True
    except Exception:
        pass
    try:
        fs.open_dir(path)
        return True
    except Exception:
        pass
    return False


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def sanitize_filename(value):
    keep = []
    for ch in safe_decode(value):
        if ch.isalnum() or ch in "._-":
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep).strip("._") or "file"


def write_extracted_file(output_dir, relative_name, data):
    extracted_dir = ensure_dir(os.path.join(output_dir, "extracted"))
    final_name = sanitize_filename(relative_name)
    out_path = os.path.join(extracted_dir, final_name)
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path, os.path.relpath(out_path, output_dir)


def sha256_hex(data):
    if data is None:
        data = b""
    return hashlib.sha256(data).hexdigest()
