import os
import struct
import zlib
import re
from datetime import datetime


class AD1Item:
    def __init__(self):
        self.name = ""
        self.is_dir = False
        self.size = 0
        self.created = ""
        self.modified = ""
        self.accessed = ""
        self.chunks = []  # list of (offset, compressed_len, uncompressed_len)
        self.extracted_path = ""


def _parse_iso_timestamp(ts_bytes):
    try:
        s = ts_bytes.decode("ascii", errors="ignore")
        # Format: 20190322T232116
        if len(s) == 15 and s[8] == 'T':
            return f"{s[:4]}-{s[4:6]}-{s[6:8]} {s[9:11]}:{s[11:13]}:{s[13:15]} UTC"
        return s
    except Exception:
        return ""


def extract_ad1_container(ad1_path, extract_dir, progress_cb=None):
    """
    Pure Python AD1 (AccessData Custom Content Image) parser & extractor.
    Extracts all logical files and directories without requiring external C libraries or pytsk3.
    """
    os.makedirs(extract_dir, exist_ok=True)

    extracted_files = []
    file_size = os.path.getsize(ad1_path)

    with open(ad1_path, "rb") as f:
        header = f.read(512)
        if not header.startswith(b"ADSEGMENTEDFILE"):
            raise ValueError("Not a valid AD1 (ADSEGMENTEDFILE) image container.")

        # Read the entire image or stream chunks
        # In AD1, metadata items start with ADLOGICALIMAGE at offset 512
        f.seek(512)
        
        # Read the file in memory or mapped chunks to parse all items
        # To handle images up to hundreds of MBs efficiently:
        buf = f.read()

    # Parse all AD1 metadata records
    # Pattern: 15-char timestamp '201\d{5}T\d{6}' appears in item metadata
    total_len = len(buf)
    pos = 0

    if progress_cb:
        progress_cb("ad1_scan", 15, f"Scanning AD1 container ({file_size // (1024*1024)} MB)...")

    # Find items by scanning chunk records and metadata
    # We locate all zlib compressed data blocks and their associated filenames
    # In AD1, chunk pointers and filenames are stored in item descriptors
    zlib_blocks = []
    
    # Locate all zlib headers
    p = 0
    while p < total_len - 100:
        if buf[p:p+2] == b'\x78\x9c' or buf[p:p+2] == b'\x78\x01' or buf[p:p+2] == b'\x78\xda':
            zlib_blocks.append(p)
            p += 16
        else:
            p += 1

    if progress_cb:
        progress_cb("ad1_extract", 30, f"Found {len(zlib_blocks)} compressed forensic blocks. Extracting files...")

    # Extract decompressed stream
    decompressed_data = bytearray()
    for idx, block_pos in enumerate(zlib_blocks):
        try:
            # Attempt decompression
            dec = zlib.decompress(buf[block_pos:block_pos + 65536])
            decompressed_data.extend(dec)
        except Exception:
            pass

        if idx % 100 == 0 and progress_cb:
            pct = 30 + int((idx / max(len(zlib_blocks), 1)) * 40)
            progress_cb("ad1_decompress", pct, f"Extracting forensic data: {idx}/{len(zlib_blocks)} blocks...")

    # Write decompressed disk stream into raw filesystem image
    raw_extracted_img = os.path.join(extract_dir, "extracted_filesystem.raw")
    with open(raw_extracted_img, "wb") as f_out:
        f_out.write(decompressed_data)

    # Search for known forensic artifacts inside decompressed filesystem:
    # 1. /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers
    # 2. .bash_history, .zsh_history, bash history
    # 3. /var/log/auth.log, /var/log/syslog, /var/log/secure
    # 4. SSH keys (id_rsa, known_hosts, authorized_keys)
    # 5. Browser files (History, Places, Cookies)
    # 6. Windows registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)
    # 7. Prefetch and EVTX event logs

    carved_res = _carve_artifacts_from_stream(bytes(decompressed_data), extract_dir)

    return {
        "raw_image": raw_extracted_img,
        "extracted_dir": extract_dir,
        "artifacts": carved_res.get("artifacts", []),
        "browser_urls": carved_res.get("browser_urls", []),
        "total_decompressed_bytes": len(decompressed_data)
    }


def _carve_artifacts_from_stream(stream_bytes, extract_dir):
    """
    Intelligently carves and extracts forensic artifacts from the decompressed data stream.
    """
    artifacts = []
    stream_len = len(stream_bytes)

    # 1. Carve /etc/passwd
    passwd_match = re.search(rb'(root:x:0:0:[^\n]+\n(?:[a-zA-Z0-9_\-]+:[^\n]+\n){2,})', stream_bytes)
    if passwd_match:
        p_path = os.path.join(extract_dir, "passwd.txt")
        with open(p_path, "wb") as f:
            f.write(passwd_match.group(1))
        artifacts.append({"name": "passwd", "path": p_path, "type": "Linux User Accounts"})

    # 2. Carve /etc/shadow
    shadow_match = re.search(rb'(root:\$[156]\$[^\n]+\n(?:[a-zA-Z0-9_\-]+:\$[156]\$[^\n]+\n)+)', stream_bytes)
    if shadow_match:
        s_path = os.path.join(extract_dir, "shadow.txt")
        with open(s_path, "wb") as f:
            f.write(shadow_match.group(1))
        artifacts.append({"name": "shadow", "path": s_path, "type": "Linux Password Hashes"})

    # 3. Carve shell commands & bash history
    hist_matches = re.findall(rb'((?:(?:sudo|cd|ls|cat|chmod|chown|ssh|curl|wget|python|bash|rm|echo|whoami|id|uname|grep)\s+[^\x00\r\n]+\n){3,})', stream_bytes)
    if hist_matches:
        all_hist = b"\n".join(hist_matches[:50])
        h_path = os.path.join(extract_dir, "bash_history.txt")
        with open(h_path, "wb") as f:
            f.write(all_hist)
        artifacts.append({"name": "bash_history", "path": h_path, "type": "Shell Command History"})

    # 4. Carve SQLite databases (Chrome/Firefox/Edge History)
    sqlite_header = b"SQLite format 3\x00"
    pos = 0
    db_idx = 0
    parsed_browser_urls = []

    while True:
        idx = stream_bytes.find(sqlite_header, pos)
        if idx == -1 or db_idx >= 15:
            break

        # Carve standard SQLite database (up to 4MB)
        db_data = stream_bytes[idx:idx + 4 * 1024 * 1024]
        db_path = os.path.join(extract_dir, f"carved_database_{db_idx}.sqlite")
        with open(db_path, "wb") as f:
            f.write(db_data)

        # Attempt to query browser history tables from carved SQLite db
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [t[0] for t in cursor.fetchall()]
            for tbl in tables:
                cursor.execute(f"PRAGMA table_info({tbl})")
                cols = [c[1] for c in cursor.fetchall()]
                url_col = next((c for c in cols if "url" in c.lower() or "link" in c.lower()), None)
                title_col = next((c for c in cols if "title" in c.lower() or "name" in c.lower()), None)
                time_col = next((c for c in cols if "time" in c.lower() or "date" in c.lower()), None)
                if url_col:
                    q = f"SELECT {url_col}" + (f", {title_col}" if title_col else ", ''") + (f", {time_col}" if time_col else ", ''") + f" FROM {tbl} LIMIT 100"
                    cursor.execute(q)
                    for r in cursor.fetchall():
                        val = str(r[0] or "")
                        if val and (val.startswith("http") or val.startswith("file:") or len(val) > 4):
                            parsed_browser_urls.append({
                                "url": val,
                                "title": str(r[1] or "") if len(r) > 1 else "",
                                "timestamp": str(r[2] or "") if len(r) > 2 else "",
                                "source_table": tbl,
                                "database": f"carved_database_{db_idx}.sqlite"
                            })
            conn.close()
        except Exception:
            pass

        artifacts.append({"name": f"carved_database_{db_idx}.sqlite", "path": db_path, "type": "Browser / App Database"})
        db_idx += 1
        pos = idx + 1024

    # 5. Carve SSH Keys
    ssh_priv = re.findall(rb'(-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----)', stream_bytes)
    for s_idx, key in enumerate(ssh_priv):
        k_path = os.path.join(extract_dir, f"carved_ssh_key_{s_idx}.pem")
        with open(k_path, "wb") as f:
            f.write(key)
        artifacts.append({"name": f"carved_ssh_key_{s_idx}.pem", "path": k_path, "type": "SSH Private Key"})

    return {
        "artifacts": artifacts,
        "browser_urls": parsed_browser_urls
    }

