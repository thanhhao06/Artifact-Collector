import os
import json
from datetime import datetime, timezone
from utils.helpers import calculate_file_hash, format_file_size


def generate_evidence_manifest(output_dir, case_info=None):
    """
    Generates a cryptographic manifest (manifest.json and checksums.sha256)
    for all collected files to ensure forensic integrity and chain of custody.
    """
    case_info = case_info or {}
    files_manifest = []
    sha256_lines = []

    for root, dirs, files in os.walk(output_dir):
        # Ignore system hidden dirs
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for fname in sorted(files):
            if fname in ["manifest.json", "checksums.sha256"] or fname.startswith(".") or fname.endswith(".pyc") or fname.endswith("-wal") or fname.endswith("-shm") or fname.endswith("-journal"):
                continue

            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, output_dir).replace("\\", "/")

            if os.path.isfile(full_path):
                try:
                    size_bytes = os.path.getsize(full_path)
                    sha256_hash = calculate_file_hash(full_path, "sha256")
                    md5_hash = calculate_file_hash(full_path, "md5")

                    files_manifest.append({
                        "relative_path": rel_path,
                        "file_name": fname,
                        "size_bytes": size_bytes,
                        "size_formatted": format_file_size(size_bytes),
                        "sha256": sha256_hash,
                        "md5": md5_hash,
                    })

                    if sha256_hash:
                        sha256_lines.append(f"{sha256_hash}  {rel_path}")
                except (OSError, IOError):
                    continue

    manifest_data = {
        "tool_name": "Artifact Collector",
        "tool_type": "Forensic Triage Engine",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "case_metadata": {
            "case_id": case_info.get("case_id", "CASE-TRIAGE-01"),
            "examiner": case_info.get("examiner", "Forensic Investigator"),
            "evidence_id": case_info.get("evidence_id", "EVID-001"),
            "notes": case_info.get("notes", "Automated Forensic Triage Collection"),
        },
        "total_files_collected": len(files_manifest),
        "files": files_manifest,
    }

    # Write manifest.json
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=4, ensure_ascii=False)

    # Write checksums.sha256
    checksums_path = os.path.join(output_dir, "checksums.sha256")
    with open(checksums_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sha256_lines) + "\n")

    return manifest_data
