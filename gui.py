import os
import sys
import threading
import webbrowser
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

from core.runner import run_local_mode, run_file_mode


class ForensicGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Artifact Collector 2.0 - Forensic Triage Suite")
        self.root.geometry("960x780")
        self.root.minsize(800, 650)

        # Apply dark theme styling
        self._setup_styles()

        self.is_running = False
        self.latest_output_dir = ""

        # Main Layout
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        # Dark palette
        self.bg_color = "#0f172a"
        self.surface_color = "#1e293b"
        self.card_color = "#334155"
        self.accent_color = "#06b6d4"
        self.accent_hover = "#0891b2"
        self.text_primary = "#f8fafc"
        self.text_secondary = "#94a3b8"

        self.root.configure(bg=self.bg_color)

        style.configure(".", background=self.bg_color, foreground=self.text_primary, font=("Segoe UI", 9))
        style.configure("TFrame", background=self.bg_color)
        style.configure("Surface.TFrame", background=self.surface_color)
        style.configure("Card.TFrame", background=self.card_color)

        style.configure("TLabel", background=self.bg_color, foreground=self.text_primary, font=("Segoe UI", 9))
        style.configure("Surface.TLabel", background=self.surface_color, foreground=self.text_primary)
        style.configure("Header.TLabel", background=self.surface_color, foreground=self.accent_color, font=("Segoe UI", 16, "bold"))
        style.configure("SubHeader.TLabel", background=self.surface_color, foreground=self.text_secondary, font=("Segoe UI", 9))
        style.configure("Section.TLabel", background=self.surface_color, foreground=self.accent_color, font=("Segoe UI", 10, "bold"))

        style.configure("TRadiobutton", background=self.surface_color, foreground=self.text_primary, font=("Segoe UI", 10, "bold"))
        style.map("TRadiobutton", background=[("active", self.surface_color)], foreground=[("active", self.accent_color)])

        style.configure("TCheckbutton", background=self.surface_color, foreground=self.text_primary, font=("Segoe UI", 9))
        style.map("TCheckbutton", background=[("active", self.surface_color)], foreground=[("active", self.accent_color)])

        style.configure("TEntry", fieldbackground=self.card_color, foreground=self.text_primary, insertcolor=self.text_primary, borderwidth=1)

        style.configure("Primary.TButton", background=self.accent_color, foreground="#000000", font=("Segoe UI", 10, "bold"), borderwidth=0, padding=8)
        style.map("Primary.TButton", background=[("active", self.accent_hover)], foreground=[("active", "#000000")])

        style.configure("Secondary.TButton", background=self.card_color, foreground=self.text_primary, font=("Segoe UI", 9, "bold"), borderwidth=0, padding=6)
        style.map("Secondary.TButton", background=[("active", "#475569")])

        style.configure("TProgressbar", thickness=10, troughcolor=self.card_color, background=self.accent_color)

    def _build_ui(self):
        # 1. HEADER BAR
        header_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=(16, 12))
        header_frame.pack(fill="x", padx=12, pady=(12, 6))

        title_box = ttk.Frame(header_frame, style="Surface.TFrame")
        title_box.pack(side="left")

        ttk.Label(title_box, text="🔍 Artifact Collector 2.0", style="Header.TLabel").pack(anchor="w")
        ttk.Label(title_box, text="Digital Forensics & Incident Response Triage Engine", style="SubHeader.TLabel").pack(anchor="w")

        # Mode Selection on Right Header
        mode_box = ttk.Frame(header_frame, style="Surface.TFrame")
        mode_box.pack(side="right")

        self.mode_var = tk.StringVar(value="local")
        rb_local = ttk.Radiobutton(mode_box, text="⚡ Live System Triage", variable=self.mode_var, value="local", command=self._on_mode_change)
        rb_local.pack(side="left", padx=10)
        rb_file = ttk.Radiobutton(mode_box, text="🗄️ Offline Disk Image", variable=self.mode_var, value="file", command=self._on_mode_change)
        rb_file.pack(side="left")

        # 2. CONFIGURATION & CASE DETAILS (Collapsible / Group Box)
        config_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=14)
        config_frame.pack(fill="x", padx=12, pady=6)

        # Image path (if file mode)
        self.image_frame = ttk.Frame(config_frame, style="Surface.TFrame")
        ttk.Label(self.image_frame, text="Disk Image File (.E01, .dd, .raw):", style="Surface.TLabel", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8))
        self.image_path_var = tk.StringVar()
        self.entry_image = ttk.Entry(self.image_frame, textvariable=self.image_path_var, width=55)
        self.entry_image.pack(side="left", fill="x", expand=True, padx=4)
        btn_browse_img = ttk.Button(self.image_frame, text="Browse Image...", style="Secondary.TButton", command=self._browse_image)
        btn_browse_img.pack(side="left", padx=4)

        # Case Metadata Grid
        meta_grid = ttk.Frame(config_frame, style="Surface.TFrame")
        meta_grid.pack(fill="x", pady=4)

        # Row 1: Case ID, Examiner, Evidence ID
        ttk.Label(meta_grid, text="Case ID:", style="Surface.TLabel").grid(row=0, column=0, sticky="w", padx=4, pady=2)
        self.case_id_var = tk.StringVar(value=f"CASE-{datetime.now().strftime('%Y%m%d')}")
        ttk.Entry(meta_grid, textvariable=self.case_id_var, width=20).grid(row=0, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(meta_grid, text="Examiner:", style="Surface.TLabel").grid(row=0, column=2, sticky="w", padx=(16, 4), pady=2)
        self.examiner_var = tk.StringVar(value=os.environ.get("USERNAME", "Investigator"))
        ttk.Entry(meta_grid, textvariable=self.examiner_var, width=20).grid(row=0, column=3, sticky="w", padx=4, pady=2)

        ttk.Label(meta_grid, text="Output Directory:", style="Surface.TLabel").grid(row=0, column=4, sticky="w", padx=(16, 4), pady=2)
        self.output_dir_var = tk.StringVar(value="output")
        ttk.Entry(meta_grid, textvariable=self.output_dir_var, width=22).grid(row=0, column=5, sticky="w", padx=4, pady=2)

        # 3. MODULE SELECTION (Checkboxes)
        mod_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=14)
        mod_frame.pack(fill="x", padx=12, pady=6)

        mod_header = ttk.Frame(mod_frame, style="Surface.TFrame")
        mod_header.pack(fill="x", pady=(0, 6))
        ttk.Label(mod_header, text="📦 Forensic Modules Selection", style="Section.TLabel").pack(side="left")

        btn_sel_all = ttk.Button(mod_header, text="Select All", style="Secondary.TButton", command=self._select_all_mods)
        btn_sel_all.pack(side="right", padx=4)
        btn_desel_all = ttk.Button(mod_header, text="Deselect All", style="Secondary.TButton", command=self._deselect_all_mods)
        btn_desel_all.pack(side="right")

        # Modules checkboxes grid
        self.mod_vars = {}
        mods = [
            ("system_info", "💻 System & Hardware Specs"),
            ("processes", "⚡ Processes, Hashes & Tree"),
            ("network", "🌐 Network Sockets, DNS & ARP"),
            ("persistence", "⏰ Persistence & Registry Autoruns"),
            ("event_logs", "📜 Windows Security Event Logs"),
            ("usb_history", "🔌 USB Storage Devices History"),
            ("browser_history", "🧭 Browser History & Downloads"),
            ("scheduled_tasks", "📅 Scheduled Tasks & Cron"),
            ("services", "🛠️ Services & Unquoted Paths"),
            ("installed_apps", "📦 Installed Software Inventory"),
            ("users", "👥 Local Users & Privileges"),
            ("terminal_history", "📜 PowerShell & Terminal History"),
            ("execution_history", "⚡ Execution Evidence (Prefetch/BAM)"),
            ("rdp", "🌐 Remote Sessions & RDP"),
            ("firewall", "🔥 Firewall Rules & Exposure"),
            ("drivers", "⚙️ Kernel Drivers & Modules"),
        ]

        grid_frame = ttk.Frame(mod_frame, style="Surface.TFrame")
        grid_frame.pack(fill="x")

        for idx, (mod_id, label) in enumerate(mods):
            var = tk.BooleanVar(value=True)
            self.mod_vars[mod_id] = var
            r = idx // 3
            c = idx % 3
            cb = ttk.Checkbutton(grid_frame, text=label, variable=var)
            cb.grid(row=r, column=c, sticky="w", padx=12, pady=4)

        # 4. ACTION BUTTONS & PROGRESS
        action_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=12)
        action_frame.pack(fill="x", padx=12, pady=6)

        self.btn_run = ttk.Button(action_frame, text="🚀 Start Forensic Triage", style="Primary.TButton", command=self._start_triage)
        self.btn_run.pack(side="left", padx=4)

        self.btn_open_report = ttk.Button(action_frame, text="🌐 Open HTML Report", style="Secondary.TButton", state="disabled", command=self._open_html_report)
        self.btn_open_report.pack(side="left", padx=4)

        self.btn_open_folder = ttk.Button(action_frame, text="📁 Open Output Folder", style="Secondary.TButton", state="disabled", command=self._open_output_folder)
        self.btn_open_folder.pack(side="left", padx=4)

        self.status_label = ttk.Label(action_frame, text="Ready", style="Surface.TLabel", font=("Segoe UI", 9, "bold"))
        self.status_label.pack(side="right", padx=8)

        # Progress bar
        self.progress_bar = ttk.Progressbar(self.root, orient="horizontal", mode="determinate", style="TProgressbar")
        self.progress_bar.pack(fill="x", padx=14, pady=(2, 6))

        # 5. REAL-TIME LOG CONSOLE
        console_frame = ttk.Frame(self.root, style="Surface.TFrame", padding=10)
        console_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        ttk.Label(console_frame, text="📋 Execution Logs & Telemetry Stream", style="Section.TLabel").pack(anchor="w", pady=(0, 4))

        self.console_text = tk.Text(
            console_frame,
            bg="#090d16",
            fg="#a5f3fc",
            insertbackground="#ffffff",
            font=("Consolas", 9),
            wrap="word",
            relief="flat",
            padx=8,
            pady=8
        )
        scrollbar = ttk.Scrollbar(console_frame, orient="vertical", command=self.console_text.yview)
        self.console_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self.console_text.pack(side="left", fill="both", expand=True)

        self._log("Artifact Collector 2.0 Initialized. Ready for triage.", "info")

    def _on_mode_change(self):
        if self.mode_var.get() == "file":
            self.image_frame.pack(fill="x", pady=6, before=self.image_frame.master.winfo_children()[1])
        else:
            self.image_frame.pack_forget()

    def _browse_image(self):
        f = filedialog.askopenfilename(
            title="Select Forensic Disk Image",
            filetypes=[("Forensic Images", "*.E01 *.dd *.raw *.img *.001 *.vmdk"), ("All Files", "*.*")]
        )
        if f:
            self.image_path_var.set(f)

    def _select_all_mods(self):
        for v in self.mod_vars.values():
            v.set(True)

    def _deselect_all_mods(self):
        for v in self.mod_vars.values():
            v.set(False)

    def _log(self, message, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        tag = "NORMAL"
        if level == "error":
            tag = "ERROR"
        elif level == "success":
            tag = "SUCCESS"

        self.console_text.insert("end", f"[{ts}] {message}\n", tag)
        self.console_text.tag_config("ERROR", foreground="#ef4444")
        self.console_text.tag_config("SUCCESS", foreground="#10b981")
        self.console_text.see("end")

    def _progress_callback(self, step, pct, msg):
        self.root.after(0, lambda: self._update_progress_ui(pct, msg))

    def _update_progress_ui(self, pct, msg):
        self.progress_bar["value"] = pct
        self.status_label.config(text=msg)
        self._log(msg)

    def _start_triage(self):
        if self.is_running:
            return

        mode = self.mode_var.get()
        image_path = self.image_path_var.get().strip()

        if mode == "file" and not image_path:
            messagebox.showerror("Error", "Please select a disk image file before running in File mode.")
            return

        if mode == "file" and not os.path.exists(image_path):
            messagebox.showerror("Error", f"Disk image file does not exist: {image_path}")
            return

        # Build enabled modules list
        enabled_modules = [m for m, v in self.mod_vars.items() if v.get()]
        if mode == "local" and not enabled_modules:
            messagebox.showwarning("Warning", "Please select at least one forensic module to collect.")
            return

        case_info = {
            "case_id": self.case_id_var.get().strip(),
            "examiner": self.examiner_var.get().strip(),
            "evidence_id": "EVID-001",
            "notes": f"Triage mode: {mode.upper()}",
        }

        output_base = self.output_dir_var.get().strip() or "output"

        self.is_running = True
        self.btn_run.config(state="disabled")
        self.btn_open_report.config(state="disabled")
        self.btn_open_folder.config(state="disabled")
        self.progress_bar["value"] = 0
        self._log(f"Starting {mode.upper()} mode triage...", "info")

        def worker():
            try:
                if mode == "local":
                    out_dir = run_local_mode(
                        base_output=output_base,
                        modules=enabled_modules,
                        case_info=case_info,
                        progress_cb=self._progress_callback
                    )
                else:
                    out_dir = run_file_mode(
                        base_output=output_base,
                        image_path=image_path,
                        case_info=case_info,
                        progress_cb=self._progress_callback
                    )

                self.latest_output_dir = out_dir
                self.root.after(0, lambda: self._on_triage_complete(True, out_dir))
            except Exception as e:
                self.root.after(0, lambda: self._on_triage_complete(False, str(e)))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    def _on_triage_complete(self, success, result):
        self.is_running = False
        self.btn_run.config(state="normal")

        if success:
            self._log(f"Triage successfully completed! Saved in: {result}", "success")
            self.status_label.config(text="Collection Finished!")
            self.btn_open_report.config(state="normal")
            self.btn_open_folder.config(state="normal")
            messagebox.showinfo("Success", f"Forensic triage completed successfully!\n\nOutput folder: {result}")
        else:
            self._log(f"Error during triage execution: {result}", "error")
            self.status_label.config(text="Error occurred!")
            messagebox.showerror("Execution Error", f"An error occurred:\n{result}")

    def _open_html_report(self):
        if self.latest_output_dir:
            report_file = os.path.join(self.latest_output_dir, "report.html")
            if os.path.exists(report_file):
                webbrowser.open(f"file://{os.path.abspath(report_file)}")

    def _open_output_folder(self):
        if self.latest_output_dir and os.path.exists(self.latest_output_dir):
            if os.name == "nt":
                os.startfile(self.latest_output_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.latest_output_dir])
            else:
                subprocess.Popen(["xdg-open", self.latest_output_dir])


def launch_gui():
    root = tk.Tk()
    app = ForensicGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
