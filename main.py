import argparse
import os
import sys

from core.runner import run_local_mode, run_file_mode

BANNER = r"""
   _____         __  .__  _____                 __            _________        .__  .__                 __                
  /  _  \_______/  |_|__|/ ____\____    _____/  |_          \_   ___ \  ____ |  | |  |   ____   _____/  |_  ___________ 
 /  /_\  \_  __ \   __\  \   __\\__  \ _/ ___\   __\  ______ /    \  \/ /  _ \|  | |  | _/ __ \_/ ___\   __\/  _ \_  __ \
/    |    \  | \/|  | |  ||  |   / __ \\  \___|  |   /_____/ \     \___(  <_> )  |_|  |_\  ___/\  \___|  | (  <_> )  | \/
\____|__  /__|   |__| |__||__|  (____  /\___  >__|            \______  /\____/|____/____/\___  >\___  >__|  \____/|__|   
        \/                           \/     \/                       \/                   \/     \/                   
                        >> Forensic Triage & Threat Intelligence Engine <<
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Artifact Collector - Advanced Forensic Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python main.py --gui\n"
               "  python main.py --mode local\n"
               "  python main.py --mode local --modules system,processes,network,persistence\n"
               "  python main.py --mode file --image evidence.E01 --case-id CASE-001\n"
               "  python main.py --mode file --image evidence.ad1 --case-id CASE-002\n"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the modern Graphical User Interface (GUI)"
    )
    parser.add_argument(
        "--mode",
        choices=["local", "file"],
        help="Run in local live triage mode or offline image analysis mode"
    )
    parser.add_argument(
        "--image",
        help="Path to forensic evidence or disk image (.E01, .ad1, .001, .d01, .dd, .raw, .vmdk, .vhd, etc.) when using --mode file"
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Base output directory (default: output)"
    )
    parser.add_argument(
        "--modules",
        help="Comma-separated list of modules to run (e.g. system,processes,network,persistence,logs,usb,browsers,services,apps,users,recent)"
    )
    parser.add_argument(
        "--case-id",
        default="CASE-TRIAGE-01",
        help="Case identifier for evidence manifest"
    )
    parser.add_argument(
        "--examiner",
        default=os.environ.get("USER", os.environ.get("USERNAME", "Investigator")),
        help="Forensic examiner / investigator name"
    )
    parser.add_argument(
        "--evidence-id",
        default="EVID-001",
        help="Evidence item number or barcode"
    )
    parser.add_argument(
        "--notes",
        default="Automated forensic triage acquisition",
        help="Case notes or triage reason"
    )
    return parser.parse_args()


def main():
    # If no arguments provided in interactive terminal, launch GUI by default
    if len(sys.argv) == 1:
        print(BANNER)
        print("[*] No arguments specified. Launching Desktop GUI...")
        try:
            from gui import launch_gui
            launch_gui()
            return
        except Exception as exc:
            print(f"[!] Unable to launch GUI: {exc}. Falling back to CLI help.\n")

    args = parse_args()

    if args.gui:
        from gui import launch_gui
        launch_gui()
        return

    if not args.mode:
        print(BANNER)
        print("Error: --mode (local | file) or --gui is required.")
        print("Run 'python main.py --help' for options, or 'python main.py --gui' to open the GUI.")
        sys.exit(1)

    print(BANNER)

    case_info = {
        "case_id": args.case_id,
        "examiner": args.examiner,
        "evidence_id": args.evidence_id,
        "notes": args.notes,
    }

    modules_list = [m.strip() for m in args.modules.split(",")] if args.modules else None

    if args.mode == "local":
        print(f"[*] Starting LIVE triage on local host...")
        print(f"[*] Case ID: {args.case_id} | Examiner: {args.examiner}")
        out_dir = run_local_mode(
            base_output=args.output,
            modules=modules_list,
            case_info=case_info
        )
        print(f"\n[+] Triage completed successfully! Output saved to:\n    {os.path.abspath(out_dir)}")
        print(f"[+] HTML Report generated:\n    {os.path.abspath(os.path.join(out_dir, 'report.html'))}\n")

    elif args.mode == "file":
        if not args.image:
            raise SystemExit("Error: --image is required when --mode file is used.")
        if not os.path.exists(args.image):
            raise SystemExit(f"Error: image file not found: {args.image}")

        print(f"[*] Starting OFFLINE image triage on: {args.image}...")
        print(f"[*] Case ID: {args.case_id} | Examiner: {args.examiner}")
        out_dir = run_file_mode(
            base_output=args.output,
            image_path=args.image,
            case_info=case_info
        )
        print(f"\n[+] Image triage completed successfully! Output saved to:\n    {os.path.abspath(out_dir)}")
        print(f"[+] HTML Report generated:\n    {os.path.abspath(os.path.join(out_dir, 'report.html'))}\n")


if __name__ == "__main__":
    main()
