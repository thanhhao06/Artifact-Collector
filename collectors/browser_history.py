import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from utils.helpers import webkit_timestamp_to_iso, firefox_prtime_to_iso, format_file_size


def _read_sqlite_safely(db_path, query_func):
    """Copies locked SQLite database to a temporary location and runs query_func(cursor)."""
    if not os.path.exists(db_path):
        return []

    temp_dir = tempfile.mkdtemp()
    temp_db = os.path.join(temp_dir, "browser_artifact.sqlite")
    results = []

    try:
        shutil.copy2(db_path, temp_db)
        # Also copy WAL and SHM if present
        for ext in ["-wal", "-shm"]:
            wal_source = db_path + ext
            if os.path.exists(wal_source):
                shutil.copy2(wal_source, temp_db + ext)

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        results = query_func(cursor)
        conn.close()
    except Exception:
        pass
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return results


def _query_chromium_history(cursor, browser_name, profile_name):
    rows = []
    try:
        query = """
        SELECT url, title, visit_count, typed_count, last_visit_time
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT 250
        """
        cursor.execute(query)
        for r in cursor.fetchall():
            url, title, visit_count, typed_count, raw_time = r[0], r[1], r[2], r[3], r[4]
            iso_time = webkit_timestamp_to_iso(raw_time)
            rows.append({
                "type": "history",
                "browser": browser_name,
                "profile": profile_name,
                "url": url or "",
                "title": title or "",
                "visit_count": visit_count or 0,
                "typed_count": typed_count or 0,
                "timestamp": iso_time,
                "timestamp_raw": raw_time,
            })
    except Exception:
        pass
    return rows


def _query_chromium_downloads(cursor, browser_name, profile_name):
    downloads = []
    try:
        # Chromium downloads table
        query = """
        SELECT current_path, target_path, start_time, received_bytes, total_bytes, tab_url, referrer
        FROM downloads
        ORDER BY start_time DESC
        LIMIT 100
        """
        cursor.execute(query)
        for r in cursor.fetchall():
            target_path = r[1] or r[0] or ""
            raw_time = r[2] or 0
            iso_time = webkit_timestamp_to_iso(raw_time)
            total_bytes = r[4] or 0
            downloads.append({
                "type": "download",
                "browser": browser_name,
                "profile": profile_name,
                "filename": os.path.basename(target_path),
                "target_path": target_path,
                "url": r[5] or "",
                "referrer": r[6] or "",
                "size_formatted": format_file_size(total_bytes),
                "total_bytes": total_bytes,
                "timestamp": iso_time,
                "timestamp_raw": raw_time,
            })
    except Exception:
        pass
    return downloads


def _query_firefox_places(cursor, browser_name, profile_name):
    rows = []
    try:
        query = """
        SELECT p.url, p.title, COALESCE(p.visit_count, 0), COALESCE(p.typed, 0), COALESCE(MAX(h.visit_date), 0)
        FROM moz_places p
        LEFT JOIN moz_historyvisits h ON p.id = h.place_id
        WHERE p.url NOT LIKE 'place:%'
        GROUP BY p.id, p.url, p.title, p.visit_count, p.typed
        ORDER BY MAX(h.visit_date) DESC
        LIMIT 250
        """
        cursor.execute(query)
        for r in cursor.fetchall():
            url, title, visit_count, typed_count, raw_time = r[0], r[1], r[2], r[3], r[4]
            iso_time = firefox_prtime_to_iso(raw_time)
            rows.append({
                "type": "history",
                "browser": browser_name,
                "profile": profile_name,
                "url": url or "",
                "title": title or "",
                "visit_count": visit_count or 0,
                "typed_count": typed_count or 0,
                "timestamp": iso_time,
                "timestamp_raw": raw_time,
            })
    except Exception:
        pass
    return rows


def _find_chromium_profiles(user_data_dir):
    """Finds all profile directories (Default, Profile 1, Profile 2, etc.) within a User Data directory."""
    profiles = []
    if not os.path.isdir(user_data_dir):
        return profiles

    # Check Default
    default_dir = os.path.join(user_data_dir, "Default")
    if os.path.isdir(default_dir):
        profiles.append(("Default", default_dir))

    # Check numbered profiles
    try:
        for entry in os.listdir(user_data_dir):
            entry_path = os.path.join(user_data_dir, entry)
            if os.path.isdir(entry_path) and (entry.startswith("Profile ") or entry in ["System Profile", "Guest Profile"]):
                profiles.append((entry, entry_path))
    except Exception:
        pass

    return profiles


def collect_browser_history():
    all_history = []
    all_downloads = []

    if os.name == "nt":
        user_profile = os.environ.get("USERPROFILE", "")
        local_app_data = os.path.join(user_profile, "AppData", "Local")
        roaming_app_data = os.path.join(user_profile, "AppData", "Roaming")

        chromium_browsers = [
            ("Google Chrome", os.path.join(local_app_data, "Google", "Chrome", "User Data")),
            ("Microsoft Edge", os.path.join(local_app_data, "Microsoft", "Edge", "User Data")),
            ("Brave", os.path.join(local_app_data, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Opera Stable", os.path.join(roaming_app_data, "Opera Software", "Opera Stable")),
            ("Opera GX", os.path.join(roaming_app_data, "Opera Software", "Opera GX Stable")),
            ("Vivaldi", os.path.join(local_app_data, "Vivaldi", "User Data")),
        ]

        for b_name, base_dir in chromium_browsers:
            if not os.path.exists(base_dir):
                continue
            # For Opera, base_dir itself might contain History directly
            if os.path.isfile(os.path.join(base_dir, "History")):
                hist_file = os.path.join(base_dir, "History")
                all_history.extend(_read_sqlite_safely(hist_file, lambda c: _query_chromium_history(c, b_name, "Default")))
                all_downloads.extend(_read_sqlite_safely(hist_file, lambda c: _query_chromium_downloads(c, b_name, "Default")))
            else:
                for prof_name, prof_dir in _find_chromium_profiles(base_dir):
                    hist_file = os.path.join(prof_dir, "History")
                    if os.path.isfile(hist_file):
                        all_history.extend(_read_sqlite_safely(hist_file, lambda c: _query_chromium_history(c, b_name, prof_name)))
                        all_downloads.extend(_read_sqlite_safely(hist_file, lambda c: _query_chromium_downloads(c, b_name, prof_name)))

        # Firefox
        ff_profiles_dir = os.path.join(roaming_app_data, "Mozilla", "Firefox", "Profiles")
        if os.path.isdir(ff_profiles_dir):
            try:
                for entry in os.listdir(ff_profiles_dir):
                    places_file = os.path.join(ff_profiles_dir, entry, "places.sqlite")
                    if os.path.isfile(places_file):
                        all_history.extend(_read_sqlite_safely(places_file, lambda c: _query_firefox_places(c, "Firefox", entry)))
            except Exception:
                pass

    else:
        # Linux
        home = str(Path.home())
        linux_chromium = [
            ("Google Chrome", os.path.join(home, ".config", "google-chrome")),
            ("Chromium", os.path.join(home, ".config", "chromium")),
            ("Microsoft Edge", os.path.join(home, ".config", "microsoft-edge")),
            ("Brave", os.path.join(home, ".config", "BraveSoftware", "Brave-Browser")),
            ("Opera", os.path.join(home, ".config", "opera")),
        ]
        for b_name, base_dir in linux_chromium:
            if not os.path.exists(base_dir):
                continue
            for prof_name, prof_dir in _find_chromium_profiles(base_dir):
                hist_file = os.path.join(prof_dir, "History")
                if os.path.isfile(hist_file):
                    all_history.extend(_read_sqlite_safely(hist_file, lambda c: _query_chromium_history(c, b_name, prof_name)))
                    all_downloads.extend(_read_sqlite_safely(hist_file, lambda c: _query_chromium_downloads(c, b_name, prof_name)))

        # Firefox Linux
        ff_dir = os.path.join(home, ".mozilla", "firefox")
        if os.path.isdir(ff_dir):
            try:
                for entry in os.listdir(ff_dir):
                    places_file = os.path.join(ff_dir, entry, "places.sqlite")
                    if os.path.isfile(places_file):
                        all_history.extend(_read_sqlite_safely(places_file, lambda c: _query_firefox_places(c, "Firefox", entry)))
            except Exception:
                pass

    # Sort history records chronologically (newest first)
    all_history.sort(key=lambda x: x.get("timestamp_raw") or 0, reverse=True)
    all_downloads.sort(key=lambda x: x.get("timestamp_raw") or 0, reverse=True)

    return {
        "history": all_history,
        "downloads": all_downloads,
        "total_records": len(all_history) + len(all_downloads)
    }
