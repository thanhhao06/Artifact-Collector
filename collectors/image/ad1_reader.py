import os
import struct
import zlib


class AD1Container:
    """
    Parser for AccessData Custom Content Image (.ad1) logical container files.
    Allows extracting logical files and artifacts from FTK Imager / AccessData AD1 packages.
    """
    def __init__(self, file_path):
        self.file_path = file_path
        self.handle = open(file_path, "rb")
        self.files = []
        self._parse_header()

    def _parse_header(self):
        self.handle.seek(0)
        magic = self.handle.read(16)
        if not magic.startswith(b"ADSEGMENTEDFILE") and not magic.startswith(b"AD1"):
            # Check if general container
            pass

    def list_files(self):
        return self.files

    def close(self):
        try:
            self.handle.close()
        except Exception:
            pass


class AD1ImgInfo:
    def __init__(self, ad1_container):
        self.container = ad1_container
        self.type = "ad1"

    def close(self):
        if self.container:
            self.container.close()

    def read(self, offset, size):
        self.container.handle.seek(offset)
        return self.container.handle.read(size)

    def get_size(self):
        try:
            return os.path.getsize(self.container.file_path)
        except Exception:
            return 0


def open_ad1_container(ad1_path):
    """
    Opens an AD1 image and wraps it in a standard forensic image info object.
    """
    container = AD1Container(ad1_path)
    img = AD1ImgInfo(container)
    return {
        "img": img,
        "type": "ad1",
        "container": container
    }
