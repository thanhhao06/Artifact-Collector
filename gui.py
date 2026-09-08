import os
import sys
import threading
import webbrowser
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.font as tkfont
from datetime import datetime

from core.runner import run_local_mode, run_file_mode


class ForensicGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Artifact Collector - Forensic Triage Suite")
        self.root.geometry("980x800")
        self.root.minsize(850, 680)

        # Detect best available font for the platform (Linux, Windows, macOS)
        self._detect_fonts()

        # Apply dark theme styling
        self._setup_styles()

        self.is_running = False
        self.latest_output_dir = ""

        # Main Layout
        self._build_ui()

    def _detect_fonts(self):
        """
        Detects clean, modern, anti-aliased sans-serif and monospace fonts across Linux, Windows, and macOS.
        """
        available = set(tkfont.families(self.root))

        # Sans-serif UI Font
        self.ui_font_family = "sans-serif"
        for font_candidate in ["Ubuntu", "DejaVu Sans", "Liberation Sans", "Segoe UI", "Inter", "Cantarell", "Noto Sans", "Helvetica Neue", "Arial"]:
            if font_candidate in available:
                self.ui_font_family = font_candidate
                break

        # Monospace Code / Log Font
        self.mono_font_family = "monospace"
        for mono_candidate in ["Ubuntu Mono", "DejaVu Sans Mono", "Liberation Mono", "Consolas", "Courier New", "Menlo"]:
            if mono_candidate in available:
                self.mono_font_family = mono_candidate
                break

        self.font_header = (self.ui_font_family, 16, "bold")
        self.font_subheader = (self.ui_font_family, 9)
        self.font_section = (self.ui_font_family, 10, "bold")
        self.font_body = (self.ui_font_family, 9)
        self.font_body_bold = (self.ui_font_family, 9, "bold")
        self.font_btn = (self.ui_font_family, 9, "bold")
        self.font_btn_primary = (self.ui_font_family, 10, "bold")
        self.font_log = (self.mono_font_family, 9)

    def _setup_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Cyberpunk Dark Palette
        self.bg_color = "#0a0e17"
        self.surface_color = "#111827"
        self.card_color = "#1e293b"
        self.border_color = "#334155"
        self.accent_color = "#06b6d4"
        self.accent_hover = "#0891b2"
        self.text_primary = "#f1f5f9"
        self.text_secondary = "#94a3b8"

        self.root.configure(bg=self.bg_color)

        style.configure(".", background=self.bg_color, foreground=self.text_primary, font=self.font_body)
        style.configure("TFrame", background=self.bg_color)
        style.configure("Surface.TFrame", background=self.surface_color)
        style.configure("Card.TFrame", background=self.card_color)

        style.configure("TLabel", background=self.bg_color, foreground=self.text_primary, font=self.font_body)
        style.configure("Surface.TLabel", background=self.surface_color, foreground=self.text_primary, font=self.font_body)
        style.configure("Header.TLabel", background=self.surface_color, foreground=self.accent_color, font=self.font_header)
        style.configure("SubHeader.TLabel", background=self.surface_color, foreground=self.text_secondary, font=self.font_subheader)
        style.configure("Section.TLabel", background=self.surface_color, foreground=self.accent_color, font=self.font_section)

        style.configure("TRadiobutton", background=self.surface_color, foreground=self.text_primary, font=self.font_body_bold)
        style.map("TRadiobutton", background=[("active", self.surface_color)], foreground=[("active", self.accent_color)])

        style.configure("TCheckbutton", background=self.surface_color, foreground=self.text_primary, font=self.font_body)
        style.map("TCheckbutton", background=[("active", self.surface_color)], foreground=[("active", self.accent_color)])

        style.configure("TEntry", fieldbackground=self.card_color, foreground=self.text_primary, insertcolor=self.text_primary, borderwidth=1)

        style.configure("Primary.TButton", background=self.accent_color, foreground="#000000", font=self.font_btn_primary, borderwidth=0, padding=8)
        style.map("Primary.TButton", background=[("active", self.accent_hover)], foreground=[("active", "#000000")])

        style.configure("Secondary.TButton", background=self.card_color, foreground=self.text_primary, font=self.font_btn, borderwidth=0, padding=6)
        style.map("Secondary.TButton", background=[("active", "#475569")])

        style.configure("TProgressbar", thickness=10, troughcolor=self.card_color, background=self.accent_color)

    def _build_ui(self):
        # 1. HEADER BAR
        header_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=(16, 14))
        header_frame.pack(fill="x", padx=12, pady=(12, 6))

        title_box = ttk.Frame(header_frame, style="Surface.TFrame")
        title_box.pack(side="left")

        ttk.Label(title_box, text="Artifact Collector", style="Header.TLabel").pack(anchor="w")
        ttk.Label(title_box, text="Digital Forensics & Incident Response Triage Engine", style="SubHeader.TLabel").pack(anchor="w")

        # Mode Selection on Right Header
        mode_box = ttk.Frame(header_frame, style="Surface.TFrame")
        mode_box.pack(side="right")

        self.mode_var = tk.StringVar(value="local")
        rb_local = ttk.Radiobutton(mode_box, text="Live System Triage", variable=self.mode_var, value="local", command=self._on_mode_change)
        rb_local.pack(side="left", padx=12)
        rb_file = ttk.Radiobutton(mode_box, text="Offline Evidence / Disk Image", variable=self.mode_var, value="file", command=self._on_mode_change)
        rb_file.pack(side="left")

        # 2. CONFIGURATION & CASE DETAILS
        config_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=14)
        config_frame.pack(fill="x", padx=12, pady=6)

        # Image path (if file mode)
        self.image_frame = ttk.Frame(config_frame, style="Surface.TFrame")
        ttk.Label(self.image_frame, text="Forensic Evidence Image (.E01, .ad1, .001, .d01, .dd, .raw, .vmdk...):", style="Surface.TLabel", font=self.font_body_bold).pack(side="left", padx=(0, 8))
        self.image_path_var = tk.StringVar()
        self.entry_image = ttk.Entry(self.image_frame, textvariable=self.image_path_var, width=50)
        self.entry_image.pack(side="left", fill="x", expand=True, padx=4)
        btn_browse_img = ttk.Button(self.image_frame, text="Browse Image...", style="Secondary.TButton", command=self._browse_image)
        btn_browse_img.pack(side="left", padx=4)

        # Case Metadata Grid
        meta_grid = ttk.Frame(config_frame, style="Surface.TFrame")
        meta_grid.pack(fill="x", pady=4)

        # Row 1: Case ID, Examiner, Evidence ID, Output Dir
        ttk.Label(meta_grid, text="Case ID:", style="Surface.TLabel").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.case_id_var = tk.StringVar(value=f"CASE-{datetime.now().strftime('%Y%m%d')}")
        ttk.Entry(meta_grid, textvariable=self.case_id_var, width=18).grid(row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(meta_grid, text="Examiner:", style="Surface.TLabel").grid(row=0, column=2, sticky="w", padx=(14, 4), pady=4)
        self.examiner_var = tk.StringVar(value=os.environ.get("USER", os.environ.get("USERNAME", "Investigator")))
        ttk.Entry(meta_grid, textvariable=self.examiner_var, width=18).grid(row=0, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(meta_grid, text="Output Directory:", style="Surface.TLabel").grid(row=0, column=4, sticky="w", padx=(14, 4), pady=4)
        self.output_dir_var = tk.StringVar(value="output")
        ttk.Entry(meta_grid, textvariable=self.output_dir_var, width=20).grid(row=0, column=5, sticky="w", padx=4, pady=4)

        # 3. MODULE SELECTION (Clean Text Without Emojis)
        mod_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=14)
        mod_frame.pack(fill="x", padx=12, pady=6)

        mod_header = ttk.Frame(mod_frame, style="Surface.TFrame")
        mod_header.pack(fill="x", pady=(0, 8))
        ttk.Label(mod_header, text="Forensic Modules Selection", style="Section.TLabel").pack(side="left")

        btn_sel_all = ttk.Button(mod_header, text="Select All", style="Secondary.TButton", command=self._select_all_mods)
        btn_sel_all.pack(side="right", padx=4)
        btn_desel_all = ttk.Button(mod_header, text="Deselect All", style="Secondary.TButton", command=self._deselect_all_mods)
        btn_desel_all.pack(side="right")

        # Modules checkboxes grid (Clean text)
        self.mod_vars = {}
        mods = [
            ("system_info", "System & Hardware Specs"),
            ("processes", "Processes, Hashes & Tree"),
            ("network", "Network Sockets, DNS & ARP"),
            ("persistence", "Persistence & Registry Autoruns"),
            ("event_logs", "Windows Security Event Logs"),
            ("usb_history", "USB Storage Devices History"),
            ("browser_history", "Browser History & Downloads"),
            ("scheduled_tasks", "Scheduled Tasks & Cron"),
            ("services", "Services & Unquoted Paths"),
            ("installed_apps", "Installed Software Inventory"),
            ("users", "Local Users & Privileges"),
            ("terminal_history", "PowerShell & Terminal History"),
            ("execution_history", "Execution Evidence (Prefetch/BAM)"),
            ("rdp", "Remote Sessions & RDP"),
            ("firewall", "Firewall Rules & Exposure"),
            ("drivers", "Kernel Drivers & Modules"),
        ]

        grid_frame = ttk.Frame(mod_frame, style="Surface.TFrame")
        grid_frame.pack(fill="x")

        for idx, (mod_id, label) in enumerate(mods):
            var = tk.BooleanVar(value=True)
            self.mod_vars[mod_id] = var
            r = idx // 3
            c = idx % 3
            cb = ttk.Checkbutton(grid_frame, text=label, variable=var)
            cb.grid(row=r, column=c, sticky="w", padx=10, pady=4)

        # 4. ACTION BUTTONS & PROGRESS
        action_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=12)
        action_frame.pack(fill="x", padx=12, pady=6)

        self.btn_run = ttk.Button(action_frame, text="Start Forensic Triage", style="Primary.TButton", command=self._start_triage)
        self.btn_run.pack(side="left", padx=4)

        self.btn_open_report = ttk.Button(action_frame, text="Open HTML Report", style="Secondary.TButton", state="disabled", command=self._open_html_report)
        self.btn_open_report.pack(side="left", padx=4)

        self.btn_open_folder = ttk.Button(action_frame, text="Open Output Folder", style="Secondary.TButton", state="disabled", command=self._open_output_folder)
        self.btn_open_folder.pack(side="left", padx=4)

        self.status_label = ttk.Label(action_frame, text="Ready", style="Surface.TLabel", font=self.font_body_bold)
        self.status_label.pack(side="right", padx=8)

        # Progress Bar
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", style="TProgressbar")
        self.progress_bar.pack(fill="x", padx=12, pady=(0, 6))

        # 5. CONSOLE LOGS & STREAM
        log_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=12)
        log_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        ttk.Label(log_frame, text="Execution Logs & Telemetry Stream", style="Section.TLabel").pack(anchor="w", pady=(0, 6))

        self.log_text = tk.Text(
            log_frame,
            bg="#050811",
            fg="#38bdf8",
            insertbackground="#38bdf8",
            font=self.font_log,
            relief="flat",
            borderwidth=1,
            wrap="word",
        )
        self.log_text.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        self.log_message("Artifact Collector Initialized. Ready for triage.")

    def _on_mode_change(self):
        mode = self.mode_var.get()
        if mode == "file":
            self.image_frame.pack(fill="x", pady=(0, 8), before=self.image_frame.master.winfo_children()[1])
        else:
            self.image_frame.pack_forget()

    def _browse_image(self):
        filetypes = [
            ("All Forensic Evidence & Disk Images", "*.E01 *.e01 *.Ex01 *.ex01 *.ad1 *.AD1 *.001 *.d01 *.d02 *.dd *.raw *.img *.vmdk *.vhd *.vhdx *.aff *.aff4 *.dmg *.bin *.iso *.s01"),
            ("Expert Witness Images (*.E01, *.Ex01, *.s01)", "*.E01 *.e01 *.Ex01 *.ex01 *.s01 *.S01"),
            ("AccessData Custom Content (*.ad1, *.ad2)", "*.ad1 *.AD1 *.ad2 *.AD2"),
            ("Raw & Split Disk Images (*.dd, *.raw, *.img, *.001, *.d01)", "*.dd *.raw *.img *.001 *.d01 *.d02 *.bin *.iso *.dmg"),
            ("Virtual Machine Disks (*.vmdk, *.vhd, *.vhdx)", "*.vmdk *.vhd *.vhdx"),
            ("Advanced Forensic Format (*.aff, *.aff4)", "*.aff *.aff4"),
            ("All Files (*.*)", "*.*")
        ]
        f = filedialog.askopenfilename(title="Select Forensic Evidence / Disk Image", filetypes=filetypes)
        if f:
            self.image_path_var.set(f)

    def _select_all_mods(self):
        for v in self.mod_vars.values():
            v.set(True)

    def _deselect_all_mods(self):
        for v in self.mod_vars.values():
            v.set(False)

    def log_message(self, msg):
        now = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{now}] {msg}\n")
        self.log_text.see(tk.END)

    def _progress_callback(self, module_name, percent, message):
        self.root.after(0, self._update_progress, percent, message)

    def _update_progress(self, percent, message):
        self.progress_bar["value"] = percent
        self.status_label.config(text=f"{percent}% - {message}")
        self.log_message(message)

    def _enable_action_buttons(self, enable=True):
        state_str = "normal" if enable else "disabled"
        state_ttk = ["!disabled"] if enable else ["disabled"]
        for btn in [self.btn_open_report, self.btn_open_folder]:
            try:
                btn.state(state_ttk)
            except Exception:
                pass
            try:
                btn.config(state=state_str)
            except Exception:
                pass

    def _start_triage(self):
        if self.is_running:
            return

        mode = self.mode_var.get()
        case_id = self.case_id_var.get().strip() or f"CASE-{datetime.now().strftime('%Y%m%d')}"
        examiner = self.examiner_var.get().strip() or "Investigator"
        output_dir = self.output_dir_var.get().strip() or "output"

        case_info = {
            "case_id": case_id,
            "examiner": examiner,
            "evidence_id": f"EVID-{datetime.now().strftime('%H%M%S')}"
        }

        # Check selected modules
        selected_mods = [mod for mod, var in self.mod_vars.items() if var.get()]
        if not selected_mods and mode == "local":
            messagebox.showwarning("No Modules", "Please select at least one forensic module to collect.")
            return

        image_path = ""
        if mode == "file":
            image_path = self.image_path_var.get().strip()
            if not image_path or not os.path.isfile(image_path):
                messagebox.showerror("Invalid Image", "Please select a valid forensic evidence / disk image file.")
                return

        self.is_running = True
        self.btn_run.config(state="disabled")
        self._enable_action_buttons(False)
        self.progress_bar["value"] = 0
        self.log_message(f"Starting {mode.upper()} triage session for Case: {case_id}...")

        # Run background thread
        thread = threading.Thread(
            target=self._run_worker,
            args=(mode, output_dir, case_info, selected_mods, image_path),
            daemon=True
        )
        thread.start()

    def _run_worker(self, mode, base_output, case_info, selected_mods, image_path):
        out = ""
        try:
            if mode == "local":
                out = run_local_mode(
                    base_output=base_output,
                    case_info=case_info,
                    selected_modules=selected_mods,
                    progress_cb=self._progress_callback
                )
            else:
                out = run_file_mode(
                    base_output=base_output,
                    image_path=image_path,
                    case_info=case_info,
                    progress_cb=self._progress_callback
                )

            self.latest_output_dir = out
            self.root.after(0, self._on_triage_success, out)
        except Exception as e:
            self.root.after(0, self._on_triage_error, str(e), out)

    def _on_triage_success(self, out_dir):
        self.is_running = False
        self.btn_run.config(state="normal")
        self._enable_action_buttons(True)
        self.progress_bar["value"] = 100
        self.status_label.config(text="Completed Successfully!")
        self.log_message(f"Triage successfully finished! Output generated at: {out_dir}")
        messagebox.showinfo("Success", f"Forensic triage completed successfully!\n\nOutput saved to:\n{out_dir}\n\nYou can click 'Open HTML Report' or 'Open Output Folder' to review results.")

    def _on_triage_error(self, err_msg, out_dir=""):
        self.is_running = False
        self.btn_run.config(state="normal")
        if out_dir and os.path.isdir(out_dir):
            self.latest_output_dir = out_dir
            self._enable_action_buttons(True)
        self.status_label.config(text="Error occurred.")
        self.log_message(f"ERROR: {err_msg}")
        messagebox.showerror("Execution Error", f"An error occurred during triage:\n{err_msg}")

    def _is_wsl(self):
        if sys.platform.startswith("linux"):
            if os.path.exists("/proc/version"):
                try:
                    with open("/proc/version", "r") as f:
                        if "microsoft" in f.read().lower():
                            return True
                except Exception:
                    pass
            return "WSL_DISTRO_NAME" in os.environ or "WSL_INTEROP" in os.environ
        return False

    def _open_cross_platform(self, target_path, is_dir=False):
        abs_path = os.path.abspath(target_path)
        if self._is_wsl():
            try:
                win_path = subprocess.check_output(["wslpath", "-w", abs_path], text=True, stderr=subprocess.DEVNULL).strip()
                if is_dir:
                    subprocess.Popen(["explorer.exe", win_path])
                else:
                    subprocess.Popen(["cmd.exe", "/c", "start", "", win_path])
                return True
            except Exception as e:
                self.log_message(f"WSL open notice: {e}")

        if sys.platform == "win32":
            try:
                os.startfile(abs_path)
                return True
            except Exception:
                if not is_dir:
                    webbrowser.open(f"file://{abs_path}")
                    return True
        elif sys.platform == "darwin":
            try:
                subprocess.Popen(["open", abs_path])
                return True
            except Exception:
                pass
        else:
            try:
                if is_dir:
                    subprocess.Popen(["xdg-open", abs_path])
                else:
                    if not webbrowser.open(f"file://{abs_path}"):
                        subprocess.Popen(["xdg-open", abs_path])
                return True
            except Exception:
                pass
        return False

    def _open_html_report(self):
        if not self.latest_output_dir:
            messagebox.showinfo("Notice", "No triage output directory found yet. Run triage first.")
            return
        report_path = os.path.join(self.latest_output_dir, "report.html")
        if os.path.isfile(report_path):
            self.log_message(f"Opening HTML Report: {report_path}")
            success = self._open_cross_platform(report_path, is_dir=False)
            if not success:
                messagebox.showwarning("Open Failed", f"Could not launch browser automatically.\nReport file is at:\n{report_path}")
        else:
            messagebox.showwarning("Report Not Found", f"report.html was not found in:\n{self.latest_output_dir}")

    def _open_output_folder(self):
        if not self.latest_output_dir or not os.path.isdir(self.latest_output_dir):
            messagebox.showinfo("Notice", "Output directory does not exist yet. Run triage first.")
            return
        abs_path = os.path.abspath(self.latest_output_dir)
        self.log_message(f"Opening Output Directory: {abs_path}")
        success = self._open_cross_platform(abs_path, is_dir=True)
        if not success:
            messagebox.showwarning("Open Failed", f"Could not open file manager automatically.\nFolder is located at:\n{abs_path}")


def launch_gui():
    root = tk.Tk()
    app = ForensicGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
