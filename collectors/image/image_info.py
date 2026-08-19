import os


def collect_image_info(image_path):
    ext = os.path.splitext(image_path)[1].lower()

    image_type = "unknown"
    if ext == ".e01":
        image_type = "E01"
    elif ext == ".dd":
        image_type = "DD"
    elif ext == ".raw":
        image_type = "RAW"
    elif ext == ".img":
        image_type = "IMG"

    return {
        "image_path": os.path.abspath(image_path),
        "image_name": os.path.basename(image_path),
        "image_extension": ext,
        "image_type": image_type,
        "file_size_bytes": os.path.getsize(image_path),
    }
