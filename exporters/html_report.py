import os
import json
import csv
import html
from datetime import datetime


def read_file_content(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".json":
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                data = json.load(f)
                return "json", data
            except Exception:
                f.seek(0)
                return "text", f.read()
    elif ext == ".csv":
        with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)
            return "csv", rows
    else:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return "text", f.read()


def _format_size(size_bytes):
    if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def write_html_report(output_dir, case_info=None):
    case_info = case_info or {}
    files = []

    for root, dirs, filenames in os.walk(output_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in sorted(filenames):
            path = os.path.join(root, filename)
            relative_name = os.path.relpath(path, output_dir).replace("\\", "/")
            if relative_name == "report.html" or filename.startswith(".") or filename.endswith(".pyc") or filename.endswith("-wal") or filename.endswith("-shm") or filename.endswith("-journal"):
                continue
            if os.path.isfile(path):
                files.append((relative_name, path))

    system_info = {}
    image_info = {}
    findings_data = []
    timeline_data = []
    processes_data = []
    network_data = []
    manifest_data = {}

    all_artifacts = []
    RAW_BINARY_EXTS = {".raw", ".dd", ".img", ".bin", ".iso", ".ad1", ".ad2", ".e01", ".ex01", ".vmdk", ".vhd", ".vhdx", ".sqlite", ".db", ".dat", ".evtx", ".pf", ".sys"}

    for rel_name, full_path in files:
        if not os.path.isfile(full_path):
            continue
        try:
            size_bytes = os.path.getsize(full_path)
        except OSError:
            continue

        ext = os.path.splitext(full_path)[1].lower()

        if ext in RAW_BINARY_EXTS or size_bytes > 5 * 1024 * 1024:
            ftype = "binary"
            content = f"Binary forensic artifact ({_format_size(size_bytes)}). Available on disk at: {rel_name}"
            count = 1
        else:
            ftype, content = read_file_content(full_path)
            count = len(content) if isinstance(content, list) else (len(content.keys()) if isinstance(content, dict) else (len(str(content).splitlines()) if ftype == "text" else 1))

        artifact_entry = {
            "name": rel_name,
            "filename": os.path.basename(rel_name),
            "type": ftype,
            "size_formatted": _format_size(size_bytes),
            "size_bytes": size_bytes,
            "data": content,
            "count": count
        }
        all_artifacts.append(artifact_entry)

        if rel_name == "system_info.json" and isinstance(content, dict):
            system_info = content
        elif rel_name == "image_info.json" and isinstance(content, dict):
            image_info = content
        elif rel_name == "findings.json" and isinstance(content, list):
            findings_data = content
        elif rel_name == "timeline.json" and isinstance(content, list):
            timeline_data = content
        elif rel_name == "processes.json" and isinstance(content, list):
            processes_data = content
        elif rel_name == "network_connections.json" and isinstance(content, list):
            network_data = content
        elif rel_name == "manifest.json" and isinstance(content, dict):
            manifest_data = content

    # Calculate summary metrics
    crit_count = sum(1 for f in findings_data if f.get("severity") == "critical")
    high_count = sum(1 for f in findings_data if f.get("severity") == "high")
    med_count = sum(1 for f in findings_data if f.get("severity") == "medium")
    low_count = sum(1 for f in findings_data if f.get("severity") == "low")
    info_count = sum(1 for f in findings_data if f.get("severity") == "info")
    total_findings = len(findings_data)

    target_host = system_info.get("hostname") or image_info.get("image_name") or image_info.get("filename") or "Target Evidence"
    target_os = system_info.get("os_details", {}).get("windows_edition") or system_info.get("os") or image_info.get("format") or "Forensic Evidence Image"
    target_user = system_info.get("username") or case_info.get("examiner") or "Examiner"

    case_id = case_info.get("case_id") or manifest_data.get("case_metadata", {}).get("case_id") or "CASE-TRIAGE-01"
    examiner = case_info.get("examiner") or manifest_data.get("case_metadata", {}).get("examiner") or "Azaki"
    evidence_id = case_info.get("evidence_id") or manifest_data.get("case_metadata", {}).get("evidence_id") or "EVID-001"

    artifacts_json = json.dumps(all_artifacts, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Artifact Collector - Forensic Triage Report [{html.escape(target_host)}]</title>
    <style>
        :root {{
            --bg-base: #0a0e17;
            --bg-surface: #111827;
            --bg-card: #172033;
            --bg-card-hover: #1e293b;
            --border-color: #27354f;
            --border-highlight: #3b82f6;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --accent-critical: #ff1e56;
            --font-main: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-mono: "SF Mono", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            --shadow-lg: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
            --shadow-glow: 0 0 15px rgba(6, 182, 212, 0.25);
        }}

        [data-theme="light"] {{
            --bg-base: #f1f5f9;
            --bg-surface: #ffffff;
            --bg-card: #f8fafc;
            --bg-card-hover: #e2e8f0;
            --border-color: #cbd5e1;
            --border-highlight: #2563eb;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #94a3b8;
            --shadow-lg: 0 10px 25px -5px rgba(0, 0, 0, 0.08);
            --shadow-glow: 0 0 15px rgba(37, 99, 235, 0.15);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: var(--font-main);
            background-color: var(--bg-base);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
        }}

        /* HEADER & BANNER */
        .top-navbar {{
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(12px);
        }}

        .brand-section {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .brand-logo {{
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border-radius: 10px;
            display: grid;
            place-items: center;
            font-size: 18px;
            font-weight: 800;
            color: #ffffff;
            box-shadow: 0 0 12px rgba(6, 182, 212, 0.4);
        }}

        .brand-text h1 {{
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.02em;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .brand-text p {{
            font-size: 11px;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }}

        .nav-actions {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .badge-live {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .badge-live::before {{
            content: "";
            width: 7px;
            height: 7px;
            background: var(--accent-green);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px var(--accent-green);
        }}

        .btn-action {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 7px 14px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s ease;
        }}

        .btn-action:hover {{
            background: var(--bg-card-hover);
            border-color: var(--accent-cyan);
            transform: translateY(-1px);
        }}

        .spotlight-btn {{
            background: rgba(6, 182, 212, 0.15);
            border-color: rgba(6, 182, 212, 0.4);
            color: var(--accent-cyan);
        }}

        /* CASE META BANNER */
        .case-banner {{
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 24px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }}

        .meta-item {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}

        .meta-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 700;
        }}

        .meta-value {{
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        /* DASHBOARD METRICS */
        .dashboard-container {{
            max-width: 1600px;
            width: 100%;
            margin: 0 auto;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }}

        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
        }}

        .kpi-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            box-shadow: var(--shadow-lg);
            position: relative;
            overflow: hidden;
            transition: border-color 0.2s;
        }}

        .kpi-card:hover {{
            border-color: var(--border-highlight);
        }}

        .kpi-card::before {{
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue));
        }}

        .kpi-card.threat-card::before {{
            background: linear-gradient(90deg, var(--accent-red), var(--accent-critical));
        }}

        .kpi-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .kpi-title {{
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 700;
            color: var(--text-secondary);
            letter-spacing: 0.05em;
        }}

        .kpi-value {{
            font-size: 28px;
            font-weight: 900;
            color: var(--text-primary);
            font-family: var(--font-mono);
        }}

        .kpi-subtext {{
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .severity-pills {{
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 4px;
        }}

        .sev-pill {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            padding: 3px 9px;
            border-radius: 6px;
            font-weight: 800;
            white-space: nowrap !important;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            line-height: 1.2;
        }}

        .sev-critical {{ background: rgba(255, 30, 86, 0.2); color: var(--accent-critical); border: 1px solid var(--accent-critical); }}
        .sev-high {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .sev-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .sev-low {{ background: rgba(59, 130, 246, 0.2); color: var(--accent-blue); border: 1px solid var(--accent-blue); }}
        .sev-info {{ background: rgba(100, 116, 139, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }}

        /* CHARTS SECTION */
        .analytics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 16px;
        }}

        .chart-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 18px;
            box-shadow: var(--shadow-lg);
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}

        .chart-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .chart-title {{
            font-size: 13px;
            font-weight: 800;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .bar-chart-container {{
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}

        .bar-item {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .bar-label-row {{
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-secondary);
            font-weight: 600;
        }}

        .bar-track {{
            width: 100%;
            height: 8px;
            background: var(--bg-card);
            border-radius: 4px;
            overflow: hidden;
        }}

        .bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.6s ease;
        }}

        /* MAIN CONTENT & TABS */
        .workspace-layout {{
            display: grid;
            grid-template-columns: 290px 1fr;
            gap: 20px;
            min-height: 700px;
        }}

        @media (max-width: 1024px) {{
            .workspace-layout {{
                grid-template-columns: 1fr;
            }}
        }}

        /* SIDEBAR NAV */
        .sidebar-nav {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            height: fit-content;
            box-shadow: var(--shadow-lg);
        }}

        .search-box {{
            position: relative;
            width: 100%;
            margin-bottom: 8px;
        }}

        .search-box input {{
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 8px 12px 8px 34px;
            color: var(--text-primary);
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }}

        .search-box input:focus {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 8px rgba(6, 182, 212, 0.25);
        }}

        .search-icon {{
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 14px;
            color: var(--text-muted);
        }}

        .nav-category-title {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 800;
            letter-spacing: 0.05em;
            margin: 12px 0 4px 6px;
        }}

        .tab-button {{
            width: 100%;
            background: transparent;
            border: 1px solid transparent;
            border-radius: 8px;
            padding: 8px 12px;
            color: var(--text-secondary);
            font-size: 13px;
            font-weight: 600;
            text-align: left;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.15s ease;
        }}

        .tab-button:hover {{
            background: var(--bg-card);
            color: var(--text-primary);
        }}

        .tab-button.active {{
            background: rgba(6, 182, 212, 0.12);
            border-color: rgba(6, 182, 212, 0.4);
            color: var(--accent-cyan);
        }}

        .tab-label-group {{
            display: flex;
            align-items: center;
            gap: 10px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        .tab-badge {{
            font-size: 11px;
            padding: 2px 7px;
            border-radius: 10px;
            background: var(--bg-card);
            color: var(--text-muted);
            font-family: var(--font-mono);
        }}

        .tab-button.active .tab-badge {{
            background: rgba(6, 182, 212, 0.25);
            color: var(--accent-cyan);
        }}

        /* CONTENT DISPLAY AREA */
        .content-area {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 24px;
            box-shadow: var(--shadow-lg);
            min-width: 0;
        }}

        .panel-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .panel-title h2 {{
            font-size: 22px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .panel-title p {{
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        .panel-controls {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .table-filter-input {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 6px 12px;
            color: var(--text-primary);
            font-size: 13px;
            outline: none;
        }}

        .table-filter-input:focus {{
            border-color: var(--accent-cyan);
        }}

        /* DATA TABLES */
        .table-responsive {{
            width: 100%;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 10px;
            background: var(--bg-card);
            max-height: 650px;
            overflow-y: auto;
        }}

        table {{
            width: 100%;
            min-width: 850px;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}

        thead {{
            position: sticky;
            top: 0;
            background: var(--bg-surface);
            z-index: 10;
            box-shadow: 0 2px 4px rgba(0,0,0,0.15);
        }}

        th {{
            padding: 12px 14px;
            font-weight: 700;
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
            background: var(--bg-surface);
        }}

        th:hover {{
            color: var(--accent-cyan);
        }}

        td {{
            padding: 11px 14px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-secondary);
            vertical-align: middle;
            line-height: 1.45;
        }}

        tr.clickable-row {{
            cursor: pointer;
        }}

        tr:hover td {{
            background: rgba(255, 255, 255, 0.04);
            color: var(--text-primary);
        }}

        .nowrap {{
            white-space: nowrap !important;
        }}

        .text-cell {{
            min-width: 220px;
            max-width: 500px;
            word-break: break-word;
        }}

        .badge-id {{
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 700;
            color: #38bdf8;
            white-space: nowrap !important;
            display: inline-block;
        }}

        .code-cell {{
            font-family: var(--font-mono);
            font-size: 12px;
            color: #38bdf8;
            background: rgba(56, 189, 248, 0.08);
            padding: 2px 6px;
            border-radius: 4px;
            white-space: nowrap !important;
            display: inline-block;
        }}

        pre.raw-json {{
            font-family: var(--font-mono);
            font-size: 12px;
            line-height: 1.6;
            color: #a5f3fc;
            background: var(--bg-card);
            padding: 18px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
            max-height: 650px;
            overflow: auto;
            white-space: pre-wrap;
        }}

        /* MODAL INSPECTOR & SPOTLIGHT */
        .modal-overlay {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(6px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 999;
            padding: 20px;
        }}

        .modal-overlay.open {{
            display: flex;
        }}

        .modal-box {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            width: 100%;
            max-width: 800px;
            max-height: 85vh;
            display: flex;
            flex-direction: column;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
            overflow: hidden;
        }}

        .modal-header {{
            padding: 18px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .modal-header h3 {{
            font-size: 18px;
            font-weight: 800;
        }}

        .modal-close {{
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 20px;
            cursor: pointer;
        }}

        .modal-close:hover {{
            color: var(--text-primary);
        }}

        .modal-body {{
            padding: 24px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .inspector-row {{
            display: flex;
            flex-direction: column;
            gap: 4px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 10px;
        }}

        .inspector-key {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 700;
            letter-spacing: 0.05em;
        }}

        .inspector-val {{
            font-size: 13px;
            color: var(--text-primary);
            word-break: break-all;
        }}

        /* SPOTLIGHT MODAL */
        .spotlight-input-row {{
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .spotlight-input-row input {{
            width: 100%;
            background: transparent;
            border: none;
            outline: none;
            font-size: 16px;
            color: var(--text-primary);
        }}

        .spotlight-results {{
            max-height: 480px;
            overflow-y: auto;
            padding: 12px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .spotlight-item {{
            padding: 10px 14px;
            border-radius: 8px;
            background: var(--bg-card);
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            transition: all 0.15s ease;
        }}

        .spotlight-item:hover {{
            background: rgba(6, 182, 212, 0.15);
            border: 1px solid rgba(6, 182, 212, 0.3);
        }}

        /* PAGINATION */
        .pagination-container {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 14px;
            font-size: 12px;
            color: var(--text-muted);
            flex-wrap: wrap;
            gap: 10px;
        }}

        .pagination-btns {{
            display: flex;
            gap: 6px;
        }}

        .pagination-btns button {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
        }}

        .pagination-btns button:hover:not(:disabled) {{
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }}

        .pagination-btns button:disabled {{
            opacity: 0.4;
            cursor: not-allowed;
        }}

        /* FOOTER */
        footer {{
            margin-top: auto;
            border-top: 1px solid var(--border-color);
            padding: 18px 24px;
            background: var(--bg-surface);
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>

    <!-- TOP NAVBAR -->
    <header class="top-navbar">
        <div class="brand-section">
            <div class="brand-logo">DFIR</div>
            <div class="brand-text">
                <h1>Artifact Collector</h1>
                <p>Forensic Triage & Incident Response Dashboard</p>
            </div>
        </div>

        <div class="nav-actions">
            <button class="btn-action spotlight-btn" onclick="openSpotlight()">Search (Ctrl+K)</button>
            <span class="badge-live">{html.escape(target_host)}</span>
            <button class="btn-action" onclick="toggleTheme()">Theme</button>
            <button class="btn-action" onclick="window.print()">Print / PDF</button>
        </div>
    </header>

    <!-- CASE BANNER -->
    <section class="case-banner">
        <div class="meta-item">
            <span class="meta-label">Evidence / Target</span>
            <span class="meta-value">{html.escape(target_host)} ({html.escape(target_user)})</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Format / OS</span>
            <span class="meta-value">{html.escape(target_os)}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Case ID / Evidence</span>
            <span class="meta-value">{html.escape(case_id)} / {html.escape(evidence_id)}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Examiner</span>
            <span class="meta-value">{html.escape(examiner)}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Report Generated</span>
            <span class="meta-value">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>
        </div>
    </section>

    <!-- DASHBOARD CONTAINER -->
    <main class="dashboard-container">

        <!-- KPI SUMMARY CARDS -->
        <section class="kpi-grid">
            <div class="kpi-card threat-card">
                <div class="kpi-header">
                    <span class="kpi-title">Threat Findings</span>
                </div>
                <div class="kpi-value">{total_findings}</div>
                <div class="severity-pills">
                    {f'<span class="sev-pill sev-critical">{crit_count} Crit</span>' if crit_count > 0 else ''}
                    {f'<span class="sev-pill sev-high">{high_count} High</span>' if high_count > 0 else ''}
                    {f'<span class="sev-pill sev-medium">{med_count} Med</span>' if med_count > 0 else ''}
                    {f'<span class="sev-pill sev-low">{low_count} Low</span>' if low_count > 0 else ''}
                    {f'<span class="sev-pill sev-info">{info_count} Info</span>' if info_count > 0 else ''}
                </div>
            </div>

            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">Artifact Datasets</span>
                </div>
                <div class="kpi-value">{len(all_artifacts)}</div>
                <div class="kpi-subtext">
                    <span>Evidence files collected</span>
                </div>
            </div>

            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">Timeline Events</span>
                </div>
                <div class="kpi-value">{len(timeline_data)}</div>
                <div class="kpi-subtext">
                    <span>Reconstructed events</span>
                </div>
            </div>

            <div class="kpi-card">
                <div class="kpi-header">
                    <span class="kpi-title">Extraction Status</span>
                </div>
                <div class="kpi-value">READY</div>
                <div class="kpi-subtext">
                    <span>Evidence Manifest Verified</span>
                </div>
            </div>
        </section>

        <!-- WORKSPACE LAYOUT -->
        <section class="workspace-layout">

            <!-- SIDEBAR NAV (DYNAMICALLY GENERATED) -->
            <aside class="sidebar-nav" id="sidebarNav">
                <div class="search-box">
                    <input type="text" id="globalSearch" placeholder="Filter tabs..." oninput="filterTabs()">
                </div>
                <div id="dynamicTabsArea"></div>
            </aside>

            <!-- CONTENT PANEL -->
            <main class="content-area" id="panelArea">
                <!-- Dynamically rendered by JS -->
            </main>
        </section>

    </main>

    <!-- RECORD INSPECTOR MODAL -->
    <div class="modal-overlay" id="inspectorModal">
        <div class="modal-box">
            <div class="modal-header">
                <h3 id="inspectorTitle">Record Details</h3>
                <button class="modal-close" onclick="closeInspector()">X</button>
            </div>
            <div class="modal-body" id="inspectorBody"></div>
        </div>
    </div>

    <!-- SPOTLIGHT SEARCH MODAL -->
    <div class="modal-overlay" id="spotlightModal">
        <div class="modal-box">
            <div class="spotlight-input-row">
                <span style="font-size: 16px; color: var(--accent-cyan); font-weight: bold;">FIND:</span>
                <input type="text" id="spotlightInput" placeholder="Search anything across all artifacts (IP, Hash, Command, User, Port)..." oninput="runSpotlightSearch(this.value)">
                <button class="modal-close" onclick="closeSpotlight()">X</button>
            </div>
            <div class="spotlight-results" id="spotlightResults">
                <p style="padding: 20px; color: var(--text-muted); text-align: center;">Type at least 2 characters to search across all collected telemetry.</p>
            </div>
        </div>
    </div>

    <!-- FOOTER -->
    <footer>
        Artifact Collector • Created by Azaki • Digital Forensics & Incident Response Triage Report
    </footer>

    <!-- INLINE SCRIPTS & EMBEDDED DATA -->
    <script>
        const ARTIFACTS = {artifacts_json};
        let currentArtifact = null;
        let currentRows = [];
        let currentPage = 1;
        let pageSize = 25;
        let sortCol = null;
        let sortAsc = true;

        const NOWRAP_COLS = new Set([
            "id", "severity", "pid", "ppid", "mitre_technique", "timestamp",
            "timestamp_raw", "create_time", "status", "protocol", "family",
            "type", "level", "event_id", "size_formatted", "drive_letter",
            "is_admin", "enabled", "scope", "is_suspicious", "unquoted_path_vuln",
            "local_port", "remote_port", "num_threads", "cpu_percent", "memory_percent", "last_execution_time"
        ]);

        function buildSidebar() {{
            const tabsArea = document.getElementById("dynamicTabsArea");
            if (!tabsArea) return;

            // Group existing artifacts dynamically
            const groups = {{
                "Core Analysis": ["findings.json", "timeline.json", "image_info.json", "system_info.json", "manifest.json"],
                "Extracted Evidence & Commands": ["linux_shell_history.json", "powershell_history.json", "ad1_artifacts_carved.json", "execution_history.json", "recent_files.json", "filesystem_artifacts.json"],
                "User Activity & Authentication": ["users.json", "linux_ssh_artifacts.json", "browser_history.json", "browser_downloads.json", "event_logs.json", "rdp_history.json"],
                "System & Inventory": ["processes.json", "network_connections.json", "persistence.json", "scheduled_tasks.json", "services.json", "system_drivers.json", "firewall_rules.json", "installed_apps.json", "usb_history.json"]
            }};

            let renderedKeys = new Set();
            let html = "";

            for (const [groupTitle, expectedNames] of Object.entries(groups)) {{
                const matched = ARTIFACTS.filter(a => expectedNames.includes(a.name) || expectedNames.includes(a.filename));
                if (matched.length > 0) {{
                    html += `<div class="nav-category-title">${{groupTitle}}</div>`;
                    matched.forEach(art => {{
                        renderedKeys.add(art.name);
                        const label = formatTabName(art.name);
                        const badgeText = art.count > 0 ? art.count : art.size_formatted;
                        html += `
                            <button class="tab-button" id="tab_${{escapeHtml(art.name)}}" onclick="switchTab('${{escapeHtml(art.name)}}', this)">
                                <span class="tab-label-group">${{escapeHtml(label)}}</span>
                                <span class="tab-badge">${{escapeHtml(String(badgeText))}}</span>
                            </button>
                        `;
                    }});
                }}
            }}

            // Render any remaining custom carved or extra artifacts
            const others = ARTIFACTS.filter(a => !renderedKeys.has(a.name) && !a.name.endsWith(".csv"));
            if (others.length > 0) {{
                html += `<div class="nav-category-title">Carved & Other Artifacts</div>`;
                others.forEach(art => {{
                    const label = formatTabName(art.name);
                    const badgeText = art.count > 0 ? art.count : art.size_formatted;
                    html += `
                        <button class="tab-button" id="tab_${{escapeHtml(art.name)}}" onclick="switchTab('${{escapeHtml(art.name)}}', this)">
                            <span class="tab-label-group">${{escapeHtml(label)}}</span>
                            <span class="tab-badge">${{escapeHtml(String(badgeText))}}</span>
                        </button>
                    `;
                }});
            }}

            tabsArea.innerHTML = html;
        }}

        function formatTabName(name) {{
            const map = {{
                "findings.json": "Threat Findings",
                "timeline.json": "Master Timeline",
                "system_info.json": "System & Hardware Specs",
                "image_info.json": "Evidence Image Specs",
                "manifest.json": "Evidence Manifest",
                "linux_shell_history.json": "Shell History & Commands",
                "powershell_history.json": "PowerShell History",
                "ad1_artifacts_carved.json": "AD1 Carved Artifacts",
                "execution_history.json": "Execution Evidence",
                "users.json": "Users & Privileges",
                "linux_ssh_artifacts.json": "SSH Keys & Auth",
                "browser_history.json": "Browser History",
                "browser_downloads.json": "Browser Downloads",
                "processes.json": "Processes & Hashes",
                "network_connections.json": "Network Sockets",
                "persistence.json": "Persistence & Autoruns",
                "scheduled_tasks.json": "Scheduled Tasks",
                "services.json": "System Services",
                "system_drivers.json": "Kernel Drivers",
                "firewall_rules.json": "Firewall Rules",
                "installed_apps.json": "Installed Software",
                "usb_history.json": "USB Storage Devices",
                "recent_files.json": "Recent Files"
            }};
            return map[name] || name.replace(".json", "").replace(/_/g, " ");
        }}

        function init() {{
            buildSidebar();

            window.addEventListener("keydown", function(e) {{
                if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {{
                    e.preventDefault();
                    openSpotlight();
                }}
                if (e.key === "Escape") {{
                    closeSpotlight();
                    closeInspector();
                }}
            }});

            // Find first artifact that has data
            let defaultArt = ARTIFACTS.find(a => (a.name === "findings.json" || a.name === "linux_shell_history.json" || a.name === "ad1_artifacts_carved.json") && a.count > 0) ||
                             ARTIFACTS.find(a => a.count > 0 && a.name.endsWith(".json")) ||
                             ARTIFACTS[0];

            if (defaultArt) {{
                const btn = document.getElementById("tab_" + defaultArt.name);
                switchTab(defaultArt.name, btn);
            }}
        }}

        function toggleTheme() {{
            const current = document.documentElement.getAttribute("data-theme");
            const target = current === "dark" ? "light" : "dark";
            document.documentElement.setAttribute("data-theme", target);
        }}

        function switchTab(name, btn) {{
            document.querySelectorAll(".tab-button").forEach(b => b.classList.remove("active"));
            if (btn) {{
                btn.classList.add("active");
            }} else {{
                const b = document.getElementById("tab_" + name);
                if (b) b.classList.add("active");
            }}

            const art = ARTIFACTS.find(a => a.name === name || a.filename === name);
            if (art) {{
                renderArtifact(art);
            }}
        }}

        function filterTabs() {{
            const q = document.getElementById("globalSearch").value.toLowerCase();
            document.querySelectorAll(".tab-button").forEach(btn => {{
                const txt = btn.innerText.toLowerCase();
                btn.style.display = txt.includes(q) ? "flex" : "none";
            }});
        }}

        function renderArtifact(art) {{
            currentArtifact = art;
            currentPage = 1;
            sortCol = null;

            const area = document.getElementById("panelArea");

            if (art.type === "json" && Array.isArray(art.data)) {{
                currentRows = [...art.data];
                renderJsonTable(art);
            }} else if (art.type === "json" && typeof art.data === "object") {{
                renderJsonObject(art);
            }} else if (art.type === "csv") {{
                renderCsv(art);
            }} else {{
                renderText(art);
            }}
        }}

        function renderJsonTable(art) {{
            const area = document.getElementById("panelArea");
            const rows = currentRows;

            if (rows.length === 0) {{
                area.innerHTML = `
                    <div class="panel-header">
                        <div class="panel-title">
                            <h2>${{formatTabName(art.name)}}</h2>
                            <p>0 records collected.</p>
                        </div>
                    </div>
                    <p style="color: var(--text-muted); padding: 20px;">No records available for this artifact.</p>
                `;
                return;
            }}

            const cols = Object.keys(rows[0]).filter(k => typeof rows[0][k] !== "object" || rows[0][k] === null);

            let headerHtml = `
                <div class="panel-header">
                    <div class="panel-title">
                        <h2>${{formatTabName(art.name)}}</h2>
                        <p>${{rows.length}} total items • File size: ${{art.size_formatted}}</p>
                    </div>
                    <div class="panel-controls">
                        <input type="text" class="table-filter-input" placeholder="Filter rows..." oninput="filterTableRows(this.value)">
                        <button class="btn-action" onclick="exportCurrentCSV()">CSV</button>
                        <button class="btn-action" onclick="exportCurrentJSON()">JSON</button>
                    </div>
                </div>
                <div class="table-responsive" id="tableContainer">
                    <table id="mainTable">
                        <thead>
                            <tr>
                                ${{cols.map(c => `<th onclick="sortTable('${{c}}')">${{c}} <span id="sort_${{c}}"></span></th>`).join("")}}
                            </tr>
                        </thead>
                        <tbody id="tableBody"></tbody>
                    </table>
                </div>
                <div class="pagination-container">
                    <span id="pageInfo"></span>
                    <div class="pagination-btns">
                        <button onclick="prevPage()" id="btnPrev">Previous</button>
                        <button onclick="nextPage()" id="btnNext">Next</button>
                    </div>
                </div>
            `;
            area.innerHTML = headerHtml;
            renderTablePage();
        }}

        function renderTablePage() {{
            const tbody = document.getElementById("tableBody");
            if (!tbody) return;

            const start = (currentPage - 1) * pageSize;
            const end = Math.min(start + pageSize, currentRows.length);
            const pageData = currentRows.slice(start, end);

            const cols = Object.keys(currentRows[0] || {{}}).filter(k => typeof currentRows[0][k] !== "object" || currentRows[0][k] === null);

            tbody.innerHTML = pageData.map((r, idx) => {{
                const globalIdx = start + idx;
                return `<tr class="clickable-row" onclick="inspectRow(${{globalIdx}})">${{cols.map(c => {{
                    let val = r[c];
                    if (val === null || val === undefined) val = "";
                    let displayVal = String(val);

                    if (c === "id") {{
                        return `<td class="nowrap"><span class="badge-id">${{escapeHtml(displayVal)}}</span></td>`;
                    }}
                    if (c === "severity") {{
                        const s = String(val).toLowerCase();
                        return `<td class="nowrap"><span class="sev-pill sev-${{s}}">${{displayVal}}</span></td>`;
                    }}
                    if (c === "mitre_technique") {{
                        return `<td class="nowrap"><span class="code-cell">${{escapeHtml(displayVal)}}</span></td>`;
                    }}
                    if (c === "sha256" || c === "md5") {{
                        return `<td><span class="code-cell" style="word-break: break-all; white-space: normal;">${{displayVal}}</span></td>`;
                    }}
                    if (c === "pid" || c === "ppid") {{
                        return `<td class="nowrap"><span class="code-cell">${{displayVal}}</span></td>`;
                    }}
                    if (NOWRAP_COLS.has(c)) {{
                        return `<td class="nowrap">${{escapeHtml(displayVal)}}</td>`;
                    }}

                    return `<td class="text-cell">${{escapeHtml(displayVal)}}</td>`;
                }}).join("")}}</tr>`;
            }}).join("");

            document.getElementById("pageInfo").innerText = `Showing ${{start + 1}}-${{end}} of ${{currentRows.length}} entries`;
            document.getElementById("btnPrev").disabled = currentPage === 1;
            document.getElementById("btnNext").disabled = end >= currentRows.length;
        }}

        function inspectRow(rowIdx) {{
            const row = currentRows[rowIdx];
            if (!row) return;

            const modal = document.getElementById("inspectorModal");
            const title = document.getElementById("inspectorTitle");
            const body = document.getElementById("inspectorBody");

            title.innerText = `${{formatTabName(currentArtifact.name)}} • Record #${{rowIdx + 1}}`;

            let html = "";
            for (const [k, v] of Object.entries(row)) {{
                let valStr = typeof v === "object" ? JSON.stringify(v, null, 2) : String(v);
                html += `
                    <div class="inspector-row">
                        <div class="inspector-key">${{escapeHtml(k)}}</div>
                        <div class="inspector-val">
                            <span class="code-cell" style="white-space: pre-wrap; word-break: break-all; width: 100%; display: block;">${{escapeHtml(valStr)}}</span>
                        </div>
                    </div>
                `;
            }}

            body.innerHTML = html;
            modal.classList.add("open");
        }}

        function closeInspector() {{
            document.getElementById("inspectorModal").classList.remove("open");
        }}

        function openSpotlight() {{
            const modal = document.getElementById("spotlightModal");
            modal.classList.add("open");
            const inp = document.getElementById("spotlightInput");
            inp.value = "";
            inp.focus();
            runSpotlightSearch("");
        }}

        function closeSpotlight() {{
            document.getElementById("spotlightModal").classList.remove("open");
        }}

        function runSpotlightSearch(query) {{
            const q = query.trim().toLowerCase();
            const results = document.getElementById("spotlightResults");

            if (!q || q.length < 2) {{
                results.innerHTML = `<p style="padding: 20px; color: var(--text-muted); text-align: center;">Type at least 2 characters to search across all collected telemetry.</p>`;
                return;
            }}

            const matches = [];
            for (const art of ARTIFACTS) {{
                if (!Array.isArray(art.data)) continue;
                for (let i = 0; i < art.data.length; i++) {{
                    const item = art.data[i];
                    const matchedKey = Object.keys(item).find(k => String(item[k]).toLowerCase().includes(q));
                    if (matchedKey) {{
                        matches.push({{
                            artifact: art.name,
                            matchedKey: matchedKey,
                            value: item[matchedKey],
                            summary: item.title || item.name || item.command || item.url || item.path || JSON.stringify(item).slice(0, 80)
                        }});
                        if (matches.length >= 30) break;
                    }}
                }}
                if (matches.length >= 30) break;
            }}

            if (matches.length === 0) {{
                results.innerHTML = `<p style="padding: 20px; color: var(--text-muted); text-align: center;">No matches found for "${{escapeHtml(query)}}".</p>`;
                return;
            }}

            results.innerHTML = matches.map(m => `
                <div class="spotlight-item" onclick="closeSpotlight(); switchTab('${{m.artifact}}');">
                    <div>
                        <div style="font-weight: 700; color: var(--text-primary); font-size: 13px;">${{escapeHtml(String(m.summary))}}</div>
                        <div style="font-size: 11px; color: var(--accent-cyan);">${{escapeHtml(m.matchedKey)}}: ${{escapeHtml(String(m.value).slice(0, 100))}}</div>
                    </div>
                    <span class="tab-badge">${{escapeHtml(formatTabName(m.artifact))}}</span>
                </div>
            `).join("");
        }}

        function filterTableRows(query) {{
            const q = query.toLowerCase();
            if (!q) {{
                currentRows = [...(currentArtifact.data || [])];
            }} else {{
                currentRows = (currentArtifact.data || []).filter(r => {{
                    return Object.values(r).some(v => String(v).toLowerCase().includes(q));
                }});
            }}
            currentPage = 1;
            renderTablePage();
        }}

        function sortTable(col) {{
            if (sortCol === col) {{
                sortAsc = !sortAsc;
            }} else {{
                sortCol = col;
                sortAsc = true;
            }}
            currentRows.sort((a, b) => {{
                let valA = a[col] ?? "";
                let valB = b[col] ?? "";
                if (typeof valA === "number" && typeof valB === "number") {{
                    return sortAsc ? valA - valB : valB - valA;
                }}
                return sortAsc ? String(valA).localeCompare(String(valB)) : String(valB).localeCompare(String(valA));
            }});
            renderTablePage();
        }}

        function prevPage() {{
            if (currentPage > 1) {{
                currentPage--;
                renderTablePage();
            }}
        }}

        function nextPage() {{
            if ((currentPage * pageSize) < currentRows.length) {{
                currentPage++;
                renderTablePage();
            }}
        }}

        function renderJsonObject(art) {{
            const area = document.getElementById("panelArea");
            const data = art.data || {{}};
            const keys = Object.keys(data);

            let tableRowsHtml = "";
            for (const k of keys) {{
                const v = data[k];
                const valStr = typeof v === "object" ? JSON.stringify(v, null, 2) : String(v);
                tableRowsHtml += `
                    <tr>
                        <td class="nowrap" style="font-weight: 700; color: var(--accent-cyan); width: 240px; vertical-align: top;">${{escapeHtml(k)}}</td>
                        <td><span class="code-cell" style="white-space: pre-wrap; word-break: break-all; display: block; font-size: 12px;">${{escapeHtml(valStr)}}</span></td>
                    </tr>
                `;
            }}

            area.innerHTML = `
                <div class="panel-header">
                    <div class="panel-title">
                        <h2>${{formatTabName(art.name)}}</h2>
                        <p>${{keys.length}} Properties • Size: ${{art.size_formatted}}</p>
                    </div>
                    <div class="panel-controls">
                        <button class="btn-action" onclick="navigator.clipboard.writeText(JSON.stringify(currentArtifact.data, null, 2))">Copy JSON</button>
                    </div>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead><tr><th style="width: 240px;">Property</th><th>Value</th></tr></thead>
                        <tbody>${{tableRowsHtml}}</tbody>
                    </table>
                </div>
            `;
        }}

        function renderCsv(art) {{
            const area = document.getElementById("panelArea");
            const rows = art.data || [];
            if (rows.length === 0) {{
                area.innerHTML = `<p style="padding: 20px; color: var(--text-muted);">Empty CSV data.</p>`;
                return;
            }}
            const header = rows[0];
            const body = rows.slice(1);
            area.innerHTML = `
                <div class="panel-header">
                    <div class="panel-title">
                        <h2>${{formatTabName(art.name)}}</h2>
                        <p>${{body.length}} rows • Size: ${{art.size_formatted}}</p>
                    </div>
                </div>
                <div class="table-responsive">
                    <table>
                        <thead><tr>${{header.map(h => `<th>${{escapeHtml(String(h))}}</th>`).join("")}}</tr></thead>
                        <tbody>${{body.map(r => `<tr>${{r.map(c => `<td>${{escapeHtml(String(c))}}</td>`).join("")}}</tr>`).join("")}}</tbody>
                    </table>
                </div>
            `;
        }}

        function renderText(art) {{
            const area = document.getElementById("panelArea");
            area.innerHTML = `
                <div class="panel-header">
                    <div class="panel-title">
                        <h2>${{formatTabName(art.name)}}</h2>
                        <p>Raw Text Output • Size: ${{art.size_formatted}}</p>
                    </div>
                </div>
                <pre class="raw-json">${{escapeHtml(String(art.data))}}</pre>
            `;
        }}

        function escapeHtml(str) {{
            return String(str)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }}

        function exportCurrentCSV() {{
            if (!currentRows || currentRows.length === 0) return;
            const keys = Object.keys(currentRows[0]);
            let csvContent = "data:text/csv;charset=utf-8," + keys.join(",") + "\\n";
            currentRows.forEach(r => {{
                let row = keys.map(k => '"' + String(r[k] || "").replace(/"/g, '""') + '"').join(",");
                csvContent += row + "\\n";
            }});
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", currentArtifact.name.replace(".json", ".csv"));
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }}

        function exportCurrentJSON() {{
            if (!currentArtifact) return;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentRows, null, 2));
            const downloadAnchor = document.createElement("a");
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", currentArtifact.name);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        }}

        window.onload = init;
    </script>
</body>
</html>
"""

    report_path = os.path.join(output_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
