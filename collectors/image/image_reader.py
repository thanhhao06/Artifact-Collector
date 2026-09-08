import os
import glob


class EWFImgInfo:
    def __init__(self, ewf_handle, pytsk3_module):
        self._ewf_handle = ewf_handle
        self._pytsk3 = pytsk3_module

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


def _open_raw_or_split(image_path):
    """
    Opens Raw (.raw, .dd, .img, .bin, .iso, .dmg) or Split Raw (.001, .d01, .raw.001) disk images.
    """
    import pytsk3

    # Check for split segments (e.g. image.001, image.002 or image.d01, image.d02)
    base, ext = os.path.splitext(image_path)
    if ext.lower() in [".001", ".d01"]:
        # Find all split segments in directory
        parent = os.path.dirname(image_path) or "."
        prefix = os.path.basename(base)
        segments = sorted(glob.glob(os.path.join(parent, f"{prefix}.*")))
        if len(segments) > 1:
            try:
                # pytsk3 Img_Info can take a list of segment filenames or single path
                img = pytsk3.Img_Info(image_path)
                return {"img": img, "type": "split_raw", "segments": segments}
            except Exception:
                pass

    img = pytsk3.Img_Info(image_path)
    return {
        "img": img,
        "type": "raw"
    }


def _open_e01(image_path):
    """
    Opens Expert Witness Format (.E01, .Ex01, .s01) disk images using pyewf.
    """
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
            try:
                self._ewf_handle.close()
            except Exception:
                pass

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


def _open_ad1(image_path):
    """
    Opens AccessData Custom Content Image (.ad1, .ad2) logical container files.
    """
    from collectors.image.ad1_reader import open_ad1_container
    return open_ad1_container(image_path)


def _open_vmdk_or_vhd(image_path):
    """
    Opens Virtual Machine Disk Images (.vmdk, .vhd, .vhdx).
    """
    import pytsk3
    try:
        # PyTSK3 supports raw VMDK/VHD images directly
        img = pytsk3.Img_Info(image_path)
        return {"img": img, "type": "virtual_disk"}
    except Exception as e:
        raise ValueError(f"Could not open virtual disk image {image_path}: {e}")


def _open_aff(image_path):
    """
    Opens Advanced Forensic Format (.aff, .aff4) disk images.
    """
    import pytsk3
    try:
        import pyaff
        aff_handle = pyaff.handle()
        aff_handle.open(image_path)

        class AFFImg(pytsk3.Img_Info):
            def __init__(self, aff_handle):
                self._aff_handle = aff_handle
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def close(self):
                self._aff_handle.close()

            def read(self, offset, size):
                self._aff_handle.seek(offset)
                return self._aff_handle.read(size)

            def get_size(self):
                return self._aff_handle.get_media_size()

        img = AFFImg(aff_handle)
        return {"img": img, "type": "aff", "aff_handle": aff_handle}
    except ImportError:
        img = pytsk3.Img_Info(image_path)
        return {"img": img, "type": "aff"}


def open_image(image_path):
    """
    Unified opener for all standard digital forensic image and evidence container formats:
    - Expert Witness Format (.E01, .Ex01, .s01)
    - AccessData Custom Content Logical Images (.ad1, .ad2)
    - Raw & Split Images (.raw, .dd, .img, .001, .d01, .bin, .iso, .dmg)
    - Virtual Machine Disks (.vmdk, .vhd, .vhdx)
    - Advanced Forensic Format (.aff, .aff4)
    """
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Evidence image file does not exist: {image_path}")

    ext = os.path.splitext(image_path)[1].lower()

    # EWF / EnCase
    if ext in [".e01", ".ex01", ".s01", ".e02", ".e03", ".ex02"]:
        return _open_e01(image_path)

    # AccessData AD1
    if ext in [".ad1", ".ad2"]:
        return _open_ad1(image_path)

    # Virtual Disks
    if ext in [".vmdk", ".vhd", ".vhdx"]:
        return _open_vmdk_or_vhd(image_path)

    # AFF
    if ext in [".aff", ".aff4"]:
        return _open_aff(image_path)

    # Raw, DD, Split segments (.001, .d01, .img, .bin, .iso, .dmg, etc.)
    if ext in [".raw", ".dd", ".img", ".001", ".d01", ".bin", ".iso", ".dmg", ""]:
        return _open_raw_or_split(image_path)

    # Fallback to Raw PyTSK3 reader
    try:
        return _open_raw_or_split(image_path)
    except Exception:
        raise ValueError(f"Unsupported forensic image format: {ext} for file {image_path}")
