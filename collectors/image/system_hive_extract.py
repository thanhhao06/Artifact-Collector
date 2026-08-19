import os

from collectors.image.utils_image import read_file_bytes


def extract_system_hive(fs, windows_root, output_dir):
    hive_path = f"{windows_root}/System32/config/SYSTEM"
    try:
        data = read_file_bytes(fs, hive_path, max_size=100 * 1024 * 1024)
        out_name = "SYSTEM.hive"
        out_path = os.path.join(output_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(data)
        return {
            "path_in_image": hive_path,
            "extracted_file": out_name,
            "status": "extracted"
        }
    except Exception as e:
        return {
            "path_in_image": hive_path,
            "status": "error",
            "error": str(e)
        }
