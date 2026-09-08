import os
import traceback
from datetime import datetime

from utils.helpers import ensure_output_dir, safe_write_text
from utils.logger import setup_logger

from exporters.json_exporter import export_json
from exporters.csv_exporter import export_csv
from exporters.report_writer import write_summary_report
from exporters.html_report import write_html_report

from core.findings_engine import analyze_all_findings
from core.timeline_engine import build_master_timeline
from core.manifest import generate_evidence_manifest


def _run_collector(logger, name, func, *args, default=None, progress_cb=None, pct=0, **kwargs):
    if progress_cb:
        progress_cb(name, pct, f"Running {name}...")
    try:
        result = func(*args, **kwargs)
        logger.info(f"Collector succeeded: {name}")
        if progress_cb:
            progress_cb(name, pct, f"Completed {name}")
        return {
            "collector": name,
            "status": "ok",
            "error": "",
            "result": result if result is not None else (default if default is not None else []),
        }
    except Exception as exc:
        logger.exception(f"Collector failed: {name}")
        if progress_cb:
            progress_cb(name, pct, f"Failed {name}: {exc}")
        return {
            "collector": name,
            "status": "error",
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "result": default if default is not None else [],
        }


def run_local_mode(base_output="output", modules=None, case_info=None, progress_cb=None):
    from collectors.system_info import collect_system_info
    from collectors.processes import collect_processes
    from collectors.network import collect_network_connections
    from collectors.persistence import collect_persistence
    from collectors.event_logs import collect_live_event_logs
    from collectors.usb_history import collect_usb_history
    from collectors.scheduled_tasks import collect_scheduled_tasks
    from collectors.browser_history import collect_browser_history
    from collectors.services import collect_services
    from collectors.installed_apps import collect_installed_apps
    from collectors.users import collect_users
    from collectors.recent_files import collect_recent_files

    case_info = case_info or {}
    output_dir = ensure_output_dir(base_output, prefix="local_triage")
    logger = setup_logger(output_dir)

    logger.info(f"Running in LOCAL mode. Output directory: {output_dir}")
    if progress_cb:
        progress_cb("init", 5, "Initializing local triage...")

    # Filter enabled modules if provided
    selected_mods = set(m.lower().strip() for m in modules) if modules else None

    def should_run(mod_name):
        if not selected_mods:
            return True
        return mod_name.lower() in selected_mods or "all" in selected_mods

    # 1. System Info
    system_info = {}
    if should_run("system_info") or should_run("system"):
        system_info = _run_collector(logger, "system_info", collect_system_info, default={}, progress_cb=progress_cb, pct=10)["result"]
        export_json(output_dir, "system_info.json", system_info)

    # 2. Processes
    processes = []
    if should_run("processes") or should_run("process"):
        processes = _run_collector(logger, "processes", collect_processes, default=[], progress_cb=progress_cb, pct=20)["result"]
        export_json(output_dir, "processes.json", processes)
        export_csv(output_dir, "processes.csv", processes)

    # 3. Network Connections & DNS
    net_data = {"connections": [], "dns_cache": [], "arp_table": []}
    if should_run("network"):
        net_res = _run_collector(logger, "network_connections", collect_network_connections, default={"connections": [], "dns_cache": [], "arp_table": []}, progress_cb=progress_cb, pct=30)["result"]
        if isinstance(net_res, dict):
            net_data = net_res
            export_json(output_dir, "network_connections.json", net_data.get("connections", []))
            export_csv(output_dir, "network_connections.csv", net_data.get("connections", []))
            export_json(output_dir, "dns_cache.json", net_data.get("dns_cache", []))
            export_csv(output_dir, "dns_cache.csv", net_data.get("dns_cache", []))
            export_json(output_dir, "arp_table.json", net_data.get("arp_table", []))
            export_csv(output_dir, "arp_table.csv", net_data.get("arp_table", []))
        elif isinstance(net_res, list):
            net_data["connections"] = net_res
            export_json(output_dir, "network_connections.json", net_res)
            export_csv(output_dir, "network_connections.csv", net_res)

    # 4. Persistence & Autoruns
    persistence = []
    if should_run("persistence") or should_run("autoruns"):
        persistence = _run_collector(logger, "persistence", collect_persistence, default=[], progress_cb=progress_cb, pct=40)["result"]
        export_json(output_dir, "persistence.json", persistence)
        export_csv(output_dir, "persistence.csv", persistence)

    # 5. Event Logs
    event_logs = []
    if should_run("event_logs") or should_run("logs"):
        event_logs = _run_collector(logger, "event_logs", collect_live_event_logs, default=[], progress_cb=progress_cb, pct=50)["result"]
        export_json(output_dir, "event_logs.json", event_logs)
        export_csv(output_dir, "event_logs.csv", event_logs)

    # 6. USB Storage History
    usb_devices = []
    if should_run("usb") or should_run("usb_history"):
        usb_devices = _run_collector(logger, "usb_history", collect_usb_history, default=[], progress_cb=progress_cb, pct=60)["result"]
        export_json(output_dir, "usb_history.json", usb_devices)
        export_csv(output_dir, "usb_history.csv", usb_devices)

    # 7. Scheduled Tasks
    tasks_res = {"tasks": [], "raw_csv": "", "raw_text": "", "return_code": 0}
    if should_run("scheduled_tasks") or should_run("tasks"):
        tasks_res = _run_collector(logger, "scheduled_tasks", collect_scheduled_tasks, default={"tasks": [], "raw_csv": "", "raw_text": "", "return_code": -1}, progress_cb=progress_cb, pct=70)["result"]
        task_list = tasks_res.get("tasks", []) if isinstance(tasks_res, dict) else []
        export_json(output_dir, "scheduled_tasks.json", task_list)
        export_csv(output_dir, "scheduled_tasks.csv", task_list)
        safe_write_text(
            os.path.join(output_dir, "scheduled_tasks_raw.txt"),
            tasks_res.get("raw_text") or tasks_res.get("raw_csv", ""),
        )

    # 8. Browser History & Downloads
    browser_data = {"history": [], "downloads": []}
    if should_run("browser_history") or should_run("browsers"):
        browser_res = _run_collector(logger, "browser_history", collect_browser_history, default={"history": [], "downloads": []}, progress_cb=progress_cb, pct=80)["result"]
        if isinstance(browser_res, dict):
            browser_data = browser_res
            export_json(output_dir, "browser_history.json", browser_data.get("history", []))
            export_csv(output_dir, "browser_history.csv", browser_data.get("history", []))
            export_json(output_dir, "browser_downloads.json", browser_data.get("downloads", []))
            export_csv(output_dir, "browser_downloads.csv", browser_data.get("downloads", []))
        elif isinstance(browser_res, list):
            browser_data["history"] = browser_res
            export_json(output_dir, "browser_history.json", browser_res)
            export_csv(output_dir, "browser_history.csv", browser_res)

    # 9. Services
    services = []
    if should_run("services"):
        services = _run_collector(logger, "services", collect_services, default=[], progress_cb=progress_cb, pct=85)["result"]
        export_json(output_dir, "services.json", services)
        export_csv(output_dir, "services.csv", services)

    # 10. Installed Apps
    installed_apps = []
    if should_run("installed_apps") or should_run("apps"):
        installed_apps = _run_collector(logger, "installed_apps", collect_installed_apps, default=[], progress_cb=progress_cb, pct=88)["result"]
        export_json(output_dir, "installed_apps.json", installed_apps)
        export_csv(output_dir, "installed_apps.csv", installed_apps)

    # 11. Users & Accounts
    users = []
    if should_run("users") or should_run("accounts"):
        users = _run_collector(logger, "users", collect_users, default=[], progress_cb=progress_cb, pct=90)["result"]
        export_json(output_dir, "users.json", users)
        export_csv(output_dir, "users.csv", users)

    # 12. Recent Files
    recent_files = []
    if should_run("recent_files") or should_run("recent"):
        recent_files = _run_collector(logger, "recent_files", collect_recent_files, default=[], progress_cb=progress_cb, pct=91)["result"]
        export_json(output_dir, "recent_files.json", recent_files)
        export_csv(output_dir, "recent_files.csv", recent_files)

    # 13. Terminal / PowerShell History
    from collectors.powershell_history import collect_terminal_history
    terminal_history = []
    if should_run("terminal_history") or should_run("powershell") or should_run("history"):
        terminal_history = _run_collector(logger, "powershell_history", collect_terminal_history, default=[], progress_cb=progress_cb, pct=92)["result"]
        export_json(output_dir, "powershell_history.json", terminal_history)
        export_csv(output_dir, "powershell_history.csv", terminal_history)

    # 14. Program Execution Evidence (Prefetch & BAM)
    from collectors.execution_history import collect_execution_history
    execution_history = []
    if should_run("execution_history") or should_run("prefetch") or should_run("bam"):
        execution_history = _run_collector(logger, "execution_history", collect_execution_history, default=[], progress_cb=progress_cb, pct=93)["result"]
        export_json(output_dir, "execution_history.json", execution_history)
        export_csv(output_dir, "execution_history.csv", execution_history)

    # 15. RDP & Remote Connection History
    from collectors.rdp_history import collect_rdp_history
    rdp_history = []
    if should_run("rdp") or should_run("remote"):
        rdp_history = _run_collector(logger, "rdp_history", collect_rdp_history, default=[], progress_cb=progress_cb, pct=93)["result"]
        export_json(output_dir, "rdp_history.json", rdp_history)
        export_csv(output_dir, "rdp_history.csv", rdp_history)

    # 16. Firewall Rules
    from collectors.firewall_rules import collect_firewall_rules
    firewall_rules = []
    if should_run("firewall"):
        firewall_rules = _run_collector(logger, "firewall_rules", collect_firewall_rules, default=[], progress_cb=progress_cb, pct=94)["result"]
        export_json(output_dir, "firewall_rules.json", firewall_rules)
        export_csv(output_dir, "firewall_rules.csv", firewall_rules)

    # 17. System Drivers
    from collectors.drivers import collect_system_drivers
    system_drivers = []
    if should_run("drivers"):
        system_drivers = _run_collector(logger, "system_drivers", collect_system_drivers, default=[], progress_cb=progress_cb, pct=95)["result"]
        export_json(output_dir, "system_drivers.json", system_drivers)
        export_csv(output_dir, "system_drivers.csv", system_drivers)

    # 18. Threat & Findings Analysis
    if progress_cb:
        progress_cb("threat_analysis", 96, "Running Threat Analysis Engine...")
    findings = analyze_all_findings(
        processes=processes,
        network_connections=net_data,
        persistence=persistence,
        event_logs=event_logs,
        usb_devices=usb_devices,
        scheduled_tasks=tasks_res,
        browser_history=browser_data,
        services=services,
        users=users,
        powershell_history=terminal_history,
        execution_history=execution_history,
    )
    export_json(output_dir, "findings.json", findings)
    export_csv(output_dir, "findings.csv", findings)

    # 19. Master Chronological Timeline
    if progress_cb:
        progress_cb("timeline", 97, "Building Forensic Timeline...")
    timeline = build_master_timeline(
        processes=processes,
        event_logs=event_logs,
        browser_history=browser_data,
        recent_files=recent_files,
        execution_history=execution_history,
    )
    export_json(output_dir, "timeline.json", timeline)
    export_csv(output_dir, "timeline.csv", timeline)

    # 20. Multi-Sheet Excel Report
    from exporters.excel_exporter import generate_excel_xml_report
    generate_excel_xml_report(output_dir, {
        "Executive Summary": {
            "Host": system_info.get("hostname", ""),
            "OS": system_info.get("os_details", {}).get("windows_edition") or system_info.get("os", ""),
            "User": system_info.get("username", ""),
            "Uptime": system_info.get("uptime", ""),
            "Threat Findings": len(findings),
            "Running Processes": len(processes),
            "Network Sockets": len(net_data.get("connections", [])),
            "Timeline Events": len(timeline),
        },
        "Threat Findings": findings,
        "Master Timeline": timeline,
        "Processes": processes,
        "Network Sockets": net_data.get("connections", []),
        "DNS Cache": net_data.get("dns_cache", []),
        "Persistence": persistence,
        "PowerShell History": terminal_history,
        "Execution History": execution_history,
        "RDP History": rdp_history,
        "Firewall Rules": firewall_rules,
        "System Drivers": system_drivers,
        "Services": services,
        "Installed Apps": installed_apps,
        "USB Devices": usb_devices,
        "Browser History": browser_data.get("history", []),
        "Browser Downloads": browser_data.get("downloads", []),
        "Recent Files": recent_files,
        "Users": users,
    })

    # 21. Summary Text Report
    write_summary_report(
        output_dir=output_dir,
        mode="local",
        summary_data={
            "system_info": system_info,
            "case_metadata": case_info,
            "processes_count": len(processes),
            "network_connections_count": len(net_data.get("connections", [])),
            "dns_cache_count": len(net_data.get("dns_cache", [])),
            "persistence_count": len(persistence),
            "event_logs_count": len(event_logs),
            "usb_devices_count": len(usb_devices),
            "services_count": len(services),
            "installed_apps_count": len(installed_apps),
            "users_count": len(users),
            "recent_files_count": len(recent_files),
            "rdp_history_count": len(rdp_history),
            "firewall_rules_count": len(firewall_rules),
            "system_drivers_count": len(system_drivers),
            "browser_history_count": len(browser_data.get("history", [])),
            "browser_downloads_count": len(browser_data.get("downloads", [])),
            "threat_findings_count": len(findings),
            "timeline_events_count": len(timeline),
        },
    )

    # 22. Modern Interactive HTML Report
    if progress_cb:
        progress_cb("report", 98, "Generating Modern HTML Report...")
    write_html_report(output_dir, case_info=case_info)

    # 23. Evidence Manifest & Cryptographic Hashes
    generate_evidence_manifest(output_dir, case_info=case_info)

    if progress_cb:
        progress_cb("completed", 100, f"Completed! Saved to: {output_dir}")
    logger.info(f"Completed LOCAL mode. Output: {output_dir}")
    return output_dir


def run_file_mode(base_output="output", image_path="", case_info=None, progress_cb=None):
    from collectors.image.root_listing import list_root_entries
    from collectors.image.os_detect import detect_os_family
    from collectors.image.image_info import collect_image_info
    from collectors.image.image_reader import open_image
    from collectors.image.filesystem_scan import collect_filesystem_artifacts, open_filesystems, list_user_profiles
    from collectors.image.browser_history_from_image import collect_browser_history_from_image
    from collectors.image.browser_history_parser import parse_browser_history_file

    from collectors.image.scheduled_tasks_from_image import collect_scheduled_tasks_from_image
    from collectors.image.prefetch_scan import collect_prefetch_files
    from collectors.image.event_logs_scan import collect_event_logs
    from collectors.image.registry_hives_scan import collect_registry_hives
    from collectors.image.recent_files_scan import collect_recent_files
    from collectors.image.system_hive_extract import extract_system_hive

    from collectors.image.linux_cron_from_image import collect_linux_cron_jobs
    from collectors.image.linux_logs_from_image import collect_linux_log_snippets
    from collectors.image.linux_shell_history_from_image import collect_linux_shell_history
    from collectors.image.linux_ssh_artifacts_from_image import collect_linux_ssh_artifacts
    from collectors.image.linux_systemd_from_image import collect_linux_systemd_persistence
    from collectors.image.linux_login_history_from_image import collect_linux_login_history
    from collectors.image.linux_sudo_from_image import collect_linux_sudo_artifacts
    from collectors.image.linux_package_history_from_image import collect_linux_package_history
    from collectors.image.linux_suspicious_files_from_image import collect_linux_suspicious_files
    from collectors.image.linux_journal_from_image import collect_linux_journal_artifacts
    from collectors.image.timeline_builder import build_timeline
    from collectors.image.findings_builder import build_findings

    case_info = case_info or {}
    output_dir = ensure_output_dir(base_output, prefix="image_triage")
    logger = setup_logger(output_dir)

    logger.info(f"Running in FILE mode with image: {image_path}")
    if progress_cb:
        progress_cb("init", 5, f"Opening image: {os.path.basename(image_path)}...")

    ext = os.path.splitext(image_path)[1].lower()
    if ext in [".ad1", ".ad2"]:
        return _run_ad1_mode(output_dir, image_path, case_info, logger, progress_cb)

    try:
        import pytsk3
    except ImportError:
        raise RuntimeError("The 'pytsk3' library is required to analyze raw disk images (.E01, .dd, .raw). Please install it via: pip install pytsk3 pyewf-wheels (or use .ad1 images which run natively).")

    image_info = collect_image_info(image_path)
    export_json(output_dir, "image_info.json", image_info)

    image_handle = open_image(image_path)
    fs_summary = collect_filesystem_artifacts(image_path, image_handle=image_handle)
    export_json(output_dir, "filesystem_artifacts.json", fs_summary)

    flat_fs_rows = fs_summary.get("filesystems", []) if isinstance(fs_summary, dict) else []
    export_csv(output_dir, "filesystem_artifacts.csv", flat_fs_rows)

    collector_status = []
    all_browser_rows = []
    all_browser_extracts = []
    all_tasks = []
    all_prefetch = []
    all_event_logs = []
    all_hives = []
    all_recent = []
    all_system_hive_extracts = []

    all_linux_cron = []
    all_linux_logs = []
    all_linux_shell_history = []
    all_linux_ssh_artifacts = []
    all_linux_systemd = []
    all_linux_login_history = []
    all_linux_sudo = []
    all_linux_package_history = []
    all_linux_suspicious_files = []
    all_linux_journal = []

    filesystems = open_filesystems(image_handle["img"])
    total_fs = len(filesystems)

    for fs_idx, fs_entry in enumerate(filesystems):
        fs = fs_entry["fs"]
        partition_addr = fs_entry.get("partition_addr")
        pct_base = 15 + int((fs_idx / max(total_fs, 1)) * 60)

        if progress_cb:
            progress_cb(f"fs_p{partition_addr}", pct_base, f"Analyzing partition {partition_addr}...")

        root_entries_status = _run_collector(logger, f"root_entries_p{partition_addr}", list_root_entries, fs, default=[])
        collector_status.append({k: v for k, v in root_entries_status.items() if k != "result"})
        export_json(output_dir, f"root_entries_partition_{partition_addr}.json", root_entries_status["result"])

        os_details = detect_os_family(fs)
        os_family = os_details["os_family"]
        if os_family == "unknown":
            continue

        users_status = _run_collector(logger, f"user_profiles_p{partition_addr}", list_user_profiles, fs, os_family=os_family, default=[])
        collector_status.append({k: v for k, v in users_status.items() if k != "result"})
        users = users_status["result"]

        browser_extracts_status = _run_collector(
            logger,
            f"browser_history_extract_p{partition_addr}",
            collect_browser_history_from_image,
            fs,
            users,
            output_dir,
            os_family=os_family,
            default=[],
        )
        collector_status.append({k: v for k, v in browser_extracts_status.items() if k != "result"})
        browser_extracts = browser_extracts_status["result"]
        all_browser_extracts.extend(browser_extracts)

        for item in browser_extracts:
            extracted_name = item["extracted_file"]
            browser_name = item["browser"]
            username = item["username"]
            extracted_path = os.path.join(output_dir, extracted_name)
            parse_status = _run_collector(
                logger,
                f"parse_browser_{extracted_name}",
                parse_browser_history_file,
                extracted_path,
                browser_name,
                username,
                default=[],
            )
            collector_status.append({k: v for k, v in parse_status.items() if k != "result"})
            all_browser_rows.extend(parse_status["result"])

        if os_family == "windows":
            windows_root = os_details["root_path"]
            for name, func, args, bucket in [
                ("scheduled_tasks_from_image", collect_scheduled_tasks_from_image, (fs, windows_root, output_dir), all_tasks),
                ("prefetch_scan", collect_prefetch_files, (fs, windows_root), all_prefetch),
                ("event_logs_scan", collect_event_logs, (fs, windows_root), all_event_logs),
                ("registry_hives_scan", collect_registry_hives, (fs, windows_root), all_hives),
                ("recent_files_scan", collect_recent_files, (fs, users), all_recent),
            ]:
                status = _run_collector(logger, f"{name}_p{partition_addr}", func, *args, default=[])
                collector_status.append({k: v for k, v in status.items() if k != "result"})
                bucket.extend(status["result"])

            hive_status = _run_collector(logger, f"system_hive_extract_p{partition_addr}", extract_system_hive, fs, windows_root, output_dir, default={})
            collector_status.append({k: v for k, v in hive_status.items() if k != "result"})
            all_system_hive_extracts.append(hive_status["result"])

        elif os_family == "linux":
            linux_jobs = [
                ("linux_cron_jobs", collect_linux_cron_jobs, (fs, users), all_linux_cron),
                ("linux_log_snippets", collect_linux_log_snippets, (fs,), all_linux_logs),
                ("linux_shell_history", collect_linux_shell_history, (fs, users, output_dir), all_linux_shell_history),
                ("linux_ssh_artifacts", collect_linux_ssh_artifacts, (fs, users, output_dir), all_linux_ssh_artifacts),
                ("linux_systemd_persistence", collect_linux_systemd_persistence, (fs, users, output_dir), all_linux_systemd),
                ("linux_login_history", collect_linux_login_history, (fs, output_dir), all_linux_login_history),
                ("linux_sudo_artifacts", collect_linux_sudo_artifacts, (fs,), all_linux_sudo),
                ("linux_package_history", collect_linux_package_history, (fs,), all_linux_package_history),
                ("linux_suspicious_files", collect_linux_suspicious_files, (fs, users, output_dir), all_linux_suspicious_files),
                ("linux_journal_artifacts", collect_linux_journal_artifacts, (fs, output_dir), all_linux_journal),
            ]
            for name, func, args, bucket in linux_jobs:
                status = _run_collector(logger, f"{name}_p{partition_addr}", func, *args, default=[])
                collector_status.append({k: v for k, v in status.items() if k != "result"})
                bucket.extend(status["result"])

    export_json(output_dir, "collector_status.json", collector_status)
    export_json(output_dir, "browser_history_extracted.json", all_browser_extracts)
    export_csv(output_dir, "browser_history.csv", all_browser_rows)
    export_json(output_dir, "browser_history.json", all_browser_rows)

    export_csv(output_dir, "scheduled_tasks_from_image.csv", all_tasks)
    export_json(output_dir, "scheduled_tasks_from_image.json", all_tasks)

    export_csv(output_dir, "prefetch_files.csv", all_prefetch)
    export_json(output_dir, "prefetch_files.json", all_prefetch)

    export_csv(output_dir, "event_logs.csv", all_event_logs)
    export_json(output_dir, "event_logs.json", all_event_logs)

    export_csv(output_dir, "registry_hives.csv", all_hives)
    export_json(output_dir, "registry_hives.json", all_hives)

    export_csv(output_dir, "recent_files.csv", all_recent)
    export_json(output_dir, "recent_files.json", all_recent)

    export_json(output_dir, "system_hive_extract_status.json", all_system_hive_extracts)

    export_csv(output_dir, "linux_cron_jobs.csv", all_linux_cron)
    export_json(output_dir, "linux_cron_jobs.json", all_linux_cron)

    export_csv(output_dir, "linux_log_snippets.csv", all_linux_logs)
    export_json(output_dir, "linux_log_snippets.json", all_linux_logs)

    export_csv(output_dir, "linux_shell_history.csv", all_linux_shell_history)
    export_json(output_dir, "linux_shell_history.json", all_linux_shell_history)

    export_csv(output_dir, "linux_ssh_artifacts.csv", all_linux_ssh_artifacts)
    export_json(output_dir, "linux_ssh_artifacts.json", all_linux_ssh_artifacts)

    export_csv(output_dir, "linux_systemd_persistence.csv", all_linux_systemd)
    export_json(output_dir, "linux_systemd_persistence.json", all_linux_systemd)

    export_csv(output_dir, "linux_login_history.csv", all_linux_login_history)
    export_json(output_dir, "linux_login_history.json", all_linux_login_history)

    export_csv(output_dir, "linux_sudo_artifacts.csv", all_linux_sudo)
    export_json(output_dir, "linux_sudo_artifacts.json", all_linux_sudo)

    export_csv(output_dir, "linux_package_history.csv", all_linux_package_history)
    export_json(output_dir, "linux_package_history.json", all_linux_package_history)

    export_csv(output_dir, "linux_suspicious_files.csv", all_linux_suspicious_files)
    export_json(output_dir, "linux_suspicious_files.json", all_linux_suspicious_files)

    export_csv(output_dir, "linux_journal_artifacts.csv", all_linux_journal)
    export_json(output_dir, "linux_journal_artifacts.json", all_linux_journal)

    timeline = build_timeline(
        browser_history=all_browser_rows,
        linux_logs=all_linux_logs,
        linux_shell_history=all_linux_shell_history,
        linux_cron=all_linux_cron,
        linux_ssh_artifacts=all_linux_ssh_artifacts,
        linux_systemd=all_linux_systemd,
        linux_login_history=all_linux_login_history,
        linux_sudo=all_linux_sudo,
        linux_package_history=all_linux_package_history,
        linux_suspicious_files=all_linux_suspicious_files,
    )
    export_csv(output_dir, "timeline.csv", timeline)
    export_json(output_dir, "timeline.json", timeline)

    findings = build_findings(
        browser_history=all_browser_rows,
        linux_logs=all_linux_logs,
        linux_shell_history=all_linux_shell_history,
        linux_cron=all_linux_cron,
        linux_ssh_artifacts=all_linux_ssh_artifacts,
        linux_systemd=all_linux_systemd,
        linux_login_history=all_linux_login_history,
        linux_sudo=all_linux_sudo,
        linux_package_history=all_linux_package_history,
        linux_suspicious_files=all_linux_suspicious_files,
    )
    export_csv(output_dir, "findings.csv", findings)
    export_json(output_dir, "findings.json", findings)

    write_summary_report(
        output_dir=output_dir,
        mode="file",
        summary_data={
            "image_info": image_info,
            "case_metadata": case_info,
            "browser_history_count": len(all_browser_rows),
            "scheduled_tasks_count": len(all_tasks),
            "prefetch_count": len(all_prefetch),
            "event_logs_count": len(all_event_logs),
            "registry_hives_count": len(all_hives),
            "recent_files_count": len(all_recent),
            "linux_cron_jobs_count": len(all_linux_cron),
            "linux_log_snippets_count": len(all_linux_logs),
            "linux_shell_history_count": len(all_linux_shell_history),
            "linux_ssh_artifacts_count": len(all_linux_ssh_artifacts),
            "linux_systemd_persistence_count": len(all_linux_systemd),
            "linux_login_history_count": len(all_linux_login_history),
            "linux_sudo_artifacts_count": len(all_linux_sudo),
            "linux_package_history_count": len(all_linux_package_history),
            "linux_suspicious_files_count": len(all_linux_suspicious_files),
            "linux_journal_artifacts_count": len(all_linux_journal),
            "timeline_count": len(timeline),
            "findings_count": len(findings),
            "collector_status_count": len(collector_status),
        },
    )

    write_html_report(output_dir, case_info=case_info)
    generate_evidence_manifest(output_dir, case_info=case_info)

    if progress_cb:
        progress_cb("completed", 100, f"Completed image analysis! Saved to: {output_dir}")
    logger.info(f"Completed FILE mode. Output: {output_dir}")
    return output_dir


def _run_ad1_mode(output_dir, image_path, case_info, logger, progress_cb):
    from collectors.image.image_info import collect_image_info
    from collectors.image.ad1_reader import extract_ad1_container
    from collectors.image.timeline_builder import build_timeline
    from collectors.image.findings_builder import build_findings
    from exporters.excel_exporter import generate_excel_xml_report
    from exporters.html_report import write_html_report
    from exporters.report_writer import write_summary_report
    from core.manifest import generate_evidence_manifest

    logger.info(f"Extracting AccessData AD1 logical container: {image_path}")
    if progress_cb:
        progress_cb("ad1_start", 10, "Extracting AD1 forensic container...")

    image_info = collect_image_info(image_path)
    export_json(output_dir, "image_info.json", image_info)

    extract_dir = os.path.join(output_dir, "extracted_ad1_artifacts")
    ad1_res = extract_ad1_container(image_path, extract_dir, progress_cb=progress_cb)

    artifacts = ad1_res.get("artifacts", [])
    export_json(output_dir, "ad1_artifacts_carved.json", artifacts)

    # Read extracted bash history
    shell_history = []
    bash_hist_path = os.path.join(extract_dir, "bash_history.txt")
    if os.path.isfile(bash_hist_path):
        with open(bash_hist_path, "r", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                cmd = line.strip()
                if cmd:
                    shell_history.append({"line_number": idx, "command": cmd, "user": "root"})
        export_json(output_dir, "linux_shell_history.json", shell_history)
        export_csv(output_dir, "linux_shell_history.csv", shell_history)

    # Read carved users
    users = []
    passwd_path = os.path.join(extract_dir, "passwd.txt")
    if os.path.isfile(passwd_path):
        with open(passwd_path, "r", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6:
                    users.append({
                        "username": parts[0],
                        "uid": parts[2],
                        "gid": parts[3],
                        "home": parts[5],
                        "shell": parts[6] if len(parts) > 6 else ""
                    })
        export_json(output_dir, "users.json", users)
        export_csv(output_dir, "users.csv", users)

    # Read carved SSH keys
    ssh_artifacts = [a for a in artifacts if a.get("type") == "SSH Private Key"]
    if ssh_artifacts:
        export_json(output_dir, "linux_ssh_artifacts.json", ssh_artifacts)
        export_csv(output_dir, "linux_ssh_artifacts.csv", ssh_artifacts)

    # Build Timeline & Findings
    timeline = build_timeline(linux_shell_history=shell_history, linux_ssh_artifacts=ssh_artifacts)
    export_json(output_dir, "timeline.json", timeline)
    export_csv(output_dir, "timeline.csv", timeline)

    findings = build_findings(linux_shell_history=shell_history, linux_ssh_artifacts=ssh_artifacts)
    export_json(output_dir, "findings.json", findings)
    export_csv(output_dir, "findings.csv", findings)

    # Generate multi-sheet Excel report
    generate_excel_xml_report(output_dir, {
        "Executive Summary": {
            "Container": os.path.basename(image_path),
            "Format": "AccessData AD1 Logical Container",
            "Size": f"{os.path.getsize(image_path) // (1024*1024)} MB",
            "Extracted Artifacts": len(artifacts),
            "Shell History Commands": len(shell_history),
            "Users Identified": len(users),
            "Threat Findings": len(findings),
            "Timeline Events": len(timeline),
        },
        "Threat Findings": findings,
        "Master Timeline": timeline,
        "Shell History": shell_history,
        "Users & Accounts": users,
        "Carved Artifacts": artifacts,
    })

    # Summary and HTML Report
    write_summary_report(
        output_dir=output_dir,
        mode="file",
        summary_data={
            "image_info": image_info,
            "case_metadata": case_info,
            "timeline_count": len(timeline),
            "findings_count": len(findings),
            "artifacts_count": len(artifacts),
        }
    )

    write_html_report(output_dir, case_info=case_info)
    generate_evidence_manifest(output_dir, case_info=case_info)

    if progress_cb:
        progress_cb("completed", 100, f"Completed AD1 triage! Saved to: {output_dir}")
    logger.info(f"Completed AD1 file mode. Output: {output_dir}")
    return output_dir
