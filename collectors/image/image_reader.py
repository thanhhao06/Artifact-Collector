import os


class EWFImgInfo:
    def __init__(self, ewf_handle, pytsk3_module):
        self._ewf_handle = ewf_handle
        self._pytsk3 = pytsk3_module
        self._img_info = pytsk3_module.Img_Info.__new__(pytsk3_module.Img_Info)

    def close(self):
        try:
            self._ewf_handle.close()
        except Exception:
            pass

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()


def _open_raw_or_dd(image_path):
    import pytsk3
    img = pytsk3.Img_Info(image_path)
    return {
        "img": img,
        "type": "raw"
    }


def _open_e01(image_path):
    import pytsk3
    import pyewf

    filenames = pyewf.glob(image_path)
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)

    class EWFImg(pytsk3.Img_Info):
        def __init__(self, ewf_handle):
            self._ewf_handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._ewf_handle.close()

        def read(self, offset, size):
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self):
            return self._ewf_handle.get_media_size()

    img = EWFImg(ewf_handle)
    return {
        "img": img,
        "type": "e01",
        "ewf_handle": ewf_handle
    }


def open_image(image_path):
    ext = os.path.splitext(image_path)[1].lower()

    if ext in [".raw", ".dd", ".img"]:
        return _open_raw_or_dd(image_path)

    if ext == ".e01":
        return _open_e01(image_path)

    raise ValueError(f"Unsupported image format: {ext}")
