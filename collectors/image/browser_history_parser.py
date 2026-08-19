import datetime as _dt
import os
import sqlite3


def _chrome_ts_to_iso(value):
    try:
        v = int(value)
        if v <= 0:
            return ""
        epoch = _dt.datetime(1601, 1, 1)
        ts = epoch + _dt.timedelta(microseconds=v)
        return ts.isoformat() + "Z"
    except Exception:
        return ""


def _firefox_ts_to_iso(value):
    try:
        v = int(value)
        if v <= 0:
            return ""
        if v > 10**15:
            ts = _dt.datetime.utcfromtimestamp(v / 1_000_000)
        else:
            ts = _dt.datetime.utcfromtimestamp(v / 1000)
        return ts.isoformat() + "Z"
    except Exception:
        return ""


def parse_browser_history_file(history_file, browser_name, username):
    rows = []
    if not os.path.exists(history_file):
        return rows

    browser_key = str(browser_name).lower()
    query = """
        SELECT url, title, visit_count, last_visit_time
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT 500
    """
    converter = _chrome_ts_to_iso

    if browser_key == "firefox":
        query = """
            SELECT p.url, p.title, COALESCE(p.visit_count, 0), COALESCE(MAX(h.visit_date), 0)
            FROM moz_places p
            LEFT JOIN moz_historyvisits h ON p.id = h.place_id
            GROUP BY p.id, p.url, p.title, p.visit_count
            ORDER BY MAX(h.visit_date) DESC
            LIMIT 500
        """
        converter = _firefox_ts_to_iso

    try:
        conn = sqlite3.connect(history_file)
        cur = conn.cursor()
        cur.execute(query)
        for row in cur.fetchall():
            rows.append({
                "username": username,
                "browser": browser_name,
                "url": row[0],
                "title": row[1],
                "visit_count": row[2],
                "last_visit_time_raw": row[3],
                "timestamp": converter(row[3]),
                "source_file": os.path.basename(history_file),
            })
        conn.close()
    except Exception:
        pass

    return rows

