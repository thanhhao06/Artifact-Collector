import os

from collectors.image.utils_image import read_file_bytes, list_dir_names, safe_decode


def _walk_tasks(fs, base_path, current_path, depth=0, max_depth=10):
    if depth > max_depth:
        return []

    results = []
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
            full_path = f"{current_path}/{name}".replace("//", "/")

            if meta and getattr(meta, "type", None) == 2:
                results.extend(_walk_tasks(fs, base_path, full_path, depth + 1, max_depth))
            else:
                results.append(full_path)
        except Exception:
            continue

    return results


def collect_scheduled_tasks_from_image(fs, windows_root, output_dir):
    task_root = f"{windows_root}/System32/Tasks"
    findings = []

    task_paths = _walk_tasks(fs, task_root, task_root)

    for idx, task_path in enumerate(task_paths):
        try:
            data = read_file_bytes(fs, task_path, max_size=1024 * 1024)
            out_name = f"task_{idx}.xml"
            out_path = os.path.join(output_dir, out_name)

            with open(out_path, "wb") as f:
                f.write(data)

            findings.append({
                "task_path_in_image": task_path,
                "extracted_file": out_name,
                "status": "extracted"
            })
        except Exception:
            continue

    return findings
