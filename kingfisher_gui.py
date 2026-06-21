import os
import re
import json
import base64
import binascii
import subprocess
import threading
import queue
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import tkinter.ttk as ttk

try:
    import base58
except ImportError:
    base58 = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.join(BASE_DIR, "kingfisher_gui_output.log")
RULES_STATE_FILE = os.path.join(BASE_DIR, "kingfisher_rules_state.json")

HITS_HEX_FILE = os.path.join(BASE_DIR, "hits_hex_current.txt")
HITS_B64_FILE = os.path.join(BASE_DIR, "hits_base64_current.txt")
HITS_B58_FILE = os.path.join(BASE_DIR, "hits_base58_current.txt")
HITS_BIP39_FILE = os.path.join(BASE_DIR, "hits_bip39_current.txt")
HITS_PEM_FILE = os.path.join(BASE_DIR, "hits_pem_current.txt")
HITS_VALIDATED_FILE = os.path.join(BASE_DIR, "hits_validated_current.txt")

MASTER_HITS_FILE = os.path.join(BASE_DIR, "hits_master.txt")
MASTER_VALIDATED_FILE = os.path.join(BASE_DIR, "hits_validated_master.txt")

DEFAULT_KF_PATH = os.path.join(os.environ.get("USERPROFILE", ""), "bin", "kingfisher.exe")
DEFAULT_GITHUB_ROOT = "https://github.com/RepoHere1/"


class KingfisherGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kingfisher Secrets Scanner GUI")
        self.geometry("1365x950")
        self.configure(bg="#05060a")

        self.proc = None
        self.stop_requested = False
        self.log_queue = queue.Queue()

        self.rules = []
        self.rules_vars = {}
        self.saved_rules = set()
        self.rules_search_var = tk.StringVar()
        self.rules_loaded = False

        self.kf_path_var = tk.StringVar(value=DEFAULT_KF_PATH)
        self.dir_var = tk.StringVar()
        self.keyword_var = tk.StringVar()

        self.scan_dirs_var = tk.BooleanVar(value=True)
        self.scan_git_var = tk.BooleanVar(value=True)
        self.scan_http_var = tk.BooleanVar(value=True)

        self.include_contribs_var = tk.BooleanVar(value=True)  # default: include contributors

        self.dec_hex_var = tk.BooleanVar(value=True)
        self.dec_b64_var = tk.BooleanVar(value=True)
        self.dec_b58_var = tk.BooleanVar(value=True)
        self.dec_bip39_var = tk.BooleanVar(value=True)
        self.dec_pem_var = tk.BooleanVar(value=True)

        # collector text widgets (filled later)
        self.hex_text = None
        self.b64_text = None
        self.b58_text = None
        self.bip39_text = None
        self.pem_text = None
        self.validated_text = None

        self.load_rules_state()
        self.create_widgets()
        self.add_context_menus()
        self.after(100, self.drain_log_queue)
        self.after(300, self.load_kingfisher_rules)

    def create_widgets(self):
        style = ttk.Style()
        try:
            style.theme_use("default")
        except tk.TclError:
            pass

        style.configure("TNotebook", background="#05060a", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[10, 5], background="#111318", foreground="#e0e0e0")
        style.map("TNotebook.Tab", background=[("selected", "#111318")])

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.main_tab = tk.Frame(notebook, bg="#05060a")
        self.rules_tab = tk.Frame(notebook, bg="#05060a")

        notebook.add(self.main_tab, text="Scan")
        notebook.add(self.rules_tab, text="Rules")

        self.build_main_tab(self.main_tab)
        self.build_rules_tab(self.rules_tab)

    def build_main_tab(self, parent):
        top_frame = tk.Frame(parent, bg="#05060a")
        top_frame.pack(fill="x", padx=10, pady=(10, 5))

        tk.Label(top_frame, text="Kingfisher binary:", fg="#e0e0e0", bg="#05060a").pack(side="left")
        self.kf_entry = tk.Entry(
            top_frame,
            textvariable=self.kf_path_var,
            width=70,
            bg="#080910",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
        )
        self.kf_entry.pack(side="left", padx=(5, 5))
        tk.Button(top_frame, text="Browse", command=self.browse_kf, bg="#1f4fff", fg="white").pack(side="left", padx=(0, 8))

        tk.Button(top_frame, text="Open Output Folder", command=self.open_output_folder, bg="#1f538d", fg="white").pack(side="left")

        targets_frame = tk.LabelFrame(parent, text="Targets", fg="#e0e0e0", bg="#0f1015")
        targets_frame.pack(fill="x", padx=10, pady=5)

        dir_frame = tk.Frame(targets_frame, bg="#0f1015")
        dir_frame.pack(fill="x", padx=5, pady=3)
        tk.Checkbutton(
            dir_frame,
            text="Scan local directory:",
            variable=self.scan_dirs_var,
            fg="#e0e0e0",
            bg="#0f1015",
            selectcolor="#0f1015",
        ).pack(side="left")
        self.dir_entry = tk.Entry(
            dir_frame,
            textvariable=self.dir_var,
            width=70,
            bg="#080910",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
        )
        self.dir_entry.pack(side="left", padx=(5, 5))
        tk.Button(dir_frame, text="Browse", command=self.browse_dir, bg="#1f4fff", fg="white").pack(side="left")

        urls_frame = tk.Frame(targets_frame, bg="#0f1015")
        urls_frame.pack(fill="both", padx=5, pady=3)
        tk.Label(urls_frame, text="URLs / git URLs (one per line):", fg="#e0e0e0", bg="#0f1015").pack(anchor="w")
        self.urls_text = scrolledtext.ScrolledText(
            urls_frame,
            height=5,
            bg="#080910",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
            wrap="none",  # no truncation/wrapping
        )
        self.urls_text.pack(fill="x", pady=(2, 2))
        self.urls_text.insert("1.0", DEFAULT_GITHUB_ROOT + "\n")

        filter_frame = tk.Frame(targets_frame, bg="#0f1015")
        filter_frame.pack(fill="x", padx=5, pady=(3, 5))
        tk.Label(
            filter_frame,
            text="Keywords (reserved for future repo discovery; does NOT filter URLs):",
            fg="#e0e0e0",
            bg="#0f1015",
        ).pack(anchor="w")
        self.keyword_entry = tk.Entry(
            filter_frame,
            textvariable=self.keyword_var,
            width=90,
            bg="#080910",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
        )
        self.keyword_entry.pack(side="left", padx=(0, 5), pady=(2, 0))
        tk.Button(
            filter_frame,
            text="Clear Keywords",
            command=lambda: self.keyword_var.set(""),
            bg="#444444",
            fg="white",
        ).pack(side="left", pady=(2, 0))

        options_frame = tk.LabelFrame(parent, text="Scan Options & Decoders", fg="#e0e0e0", bg="#0f1015")
        options_frame.pack(fill="x", padx=10, pady=5)

        left_opts = tk.Frame(options_frame, bg="#0f1015")
        left_opts.pack(side="left", fill="y", padx=10, pady=5)

        right_opts = tk.Frame(options_frame, bg="#0f1015")
        right_opts.pack(side="left", fill="y", padx=10, pady=5)

        tk.Checkbutton(
            left_opts,
            text="Scan git URLs (github.com)",
            variable=self.scan_git_var,
            fg="#e0e0e0",
            bg="#0f1015",
            selectcolor="#0f1015",
        ).pack(anchor="w")
        tk.Checkbutton(
            left_opts,
            text="Scan HTTP/HTTPS URLs",
            variable=self.scan_http_var,
            fg="#e0e0e0",
            bg="#0f1015",
            selectcolor="#0f1015",
        ).pack(anchor="w")

        tk.Checkbutton(
            left_opts,
            text="Include contributor-owned repos (GitHub/GitLab)",
            variable=self.include_contribs_var,
            fg="#e0e0e0",
            bg="#0f1015",
            selectcolor="#0f1015",
        ).pack(anchor="w")

        tk.Label(
            left_opts,
            text="Contributor depth: main repo only vs main + contributor repos.\n"
                 "History depth is currently full repo (Kingfisher default).",
            fg="#a0a0a0",
            bg="#0f1015",
            justify="left",
            wraplength=450,
        ).pack(anchor="w", pady=(6, 0))

        tk.Label(right_opts, text="Decode helpers:", fg="#e0e0e0", bg="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="Hex", variable=self.dec_hex_var, fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="Base64", variable=self.dec_b64_var, fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="Base58", variable=self.dec_b58_var, fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="BIP39-like", variable=self.dec_bip39_var, fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="PEM blocks", variable=self.dec_pem_var, fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")

        controls_frame = tk.Frame(parent, bg="#05060a")
        controls_frame.pack(fill="x", padx=10, pady=5)

        self.run_button = tk.Button(
            controls_frame,
            text="RUN SCAN",
            command=self.start_scan,
            bg="#00ff4c",
            fg="#000000",
            width=18,
        )
        self.run_button.pack(side="left", padx=(0, 5))

        self.stop_button = tk.Button(
            controls_frame,
            text="STOP",
            command=self.stop_scan,
            bg="#cc0000",
            fg="white",
            width=10,
        )
        self.stop_button.pack(side="left", padx=(5, 5))

        console_frame = tk.LabelFrame(parent, text="Kingfisher Output + Decoded Hints", fg="#e0e0e0", bg="#0f1015")
        console_frame.pack(fill="both", expand=True, padx=10, pady=(5, 5))

        self.console = scrolledtext.ScrolledText(
            console_frame,
            font=("Consolas", 10),
            bg="#050505",
            fg="#00ff66",
            insertbackground="#00ff66",
            wrap="none",  # no truncation/wrapping
        )
        self.console.pack(fill="both", expand=True)

        # Collector frame: buttons + notebook
        collector_frame = tk.LabelFrame(parent, text="Collectors (Hex/Base64/Base58/BIP39/PEM/Validated)", fg="#e0e0e0", bg="#0f1015")
        collector_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        buttons_row = tk.Frame(collector_frame, bg="#0f1015")
        buttons_row.pack(fill="x", padx=5, pady=(5, 5))

        tk.Button(buttons_row, text="Hex hits", command=self.collect_hex_hits, bg="#444444", fg="white").pack(side="left", padx=3)
        tk.Button(buttons_row, text="Base64 hits", command=self.collect_b64_hits, bg="#444444", fg="white").pack(side="left", padx=3)
        tk.Button(buttons_row, text="Base58 hits", command=self.collect_b58_hits, bg="#444444", fg="white").pack(side="left", padx=3)
        tk.Button(buttons_row, text="BIP39 hits", command=self.collect_bip39_hits, bg="#444444", fg="white").pack(side="left", padx=3)
        tk.Button(buttons_row, text="PEM hits", command=self.collect_pem_hits, bg="#444444", fg="white").pack(side="left", padx=3)

        tk.Button(
            buttons_row,
            text="VALIDATION PASSED",
            command=self.collect_validated_hits,
            bg="#ffff00",
            fg="#000000",
        ).pack(side="left", padx=10)

        tk.Button(
            buttons_row,
            text="Clear & Archive",
            command=self.archive_and_clear_hits,
            bg="#8d5c1f",
            fg="white",
        ).pack(side="right", padx=3)

        hits_notebook = ttk.Notebook(collector_frame)
        hits_notebook.pack(fill="both", expand=True, padx=5, pady=(0, 5))

        # One tab per category
        self.hex_text = scrolledtext.ScrolledText(hits_notebook, bg="#050505", fg="#f5f5f5", insertbackground="#f5f5f5", wrap="none")
        self.b64_text = scrolledtext.ScrolledText(hits_notebook, bg="#050505", fg="#f5f5f5", insertbackground="#f5f5f5", wrap="none")
        self.b58_text = scrolledtext.ScrolledText(hits_notebook, bg="#050505", fg="#f5f5f5", insertbackground="#f5f5f5", wrap="none")
        self.bip39_text = scrolledtext.ScrolledText(hits_notebook, bg="#050505", fg="#f5f5f5", insertbackground="#f5f5f5", wrap="none")
        self.pem_text = scrolledtext.ScrolledText(hits_notebook, bg="#050505", fg="#f5f5f5", insertbackground="#f5f5f5", wrap="none")
        self.validated_text = scrolledtext.ScrolledText(hits_notebook, bg="#050505", fg="#00ff66", insertbackground="#00ff66", wrap="none")

        hits_notebook.add(self.hex_text, text="Hex")
        hits_notebook.add(self.b64_text, text="Base64")
        hits_notebook.add(self.b58_text, text="Base58")
        hits_notebook.add(self.bip39_text, text="BIP39-like")
        hits_notebook.add(self.pem_text, text="PEM")
        hits_notebook.add(self.validated_text, text="Validated")

    def build_rules_tab(self, parent):
        top = tk.Frame(parent, bg="#05060a")
        top.pack(fill="x", padx=10, pady=(10, 5))

        tk.Label(top, text="Filter rules:", fg="#e0e0e0", bg="#05060a").pack(anchor="w")
        search_row = tk.Frame(top, bg="#05060a")
        search_row.pack(fill="x", pady=(2, 5))

        self.rules_search_entry = tk.Entry(
            search_row,
            textvariable=self.rules_search_var,
            width=70,
            bg="#080910",
            fg="#f5f5f5",
            insertbackground="#f5f5f5",
        )
        self.rules_search_entry.pack(side="left", padx=(0, 5))
        self.rules_search_entry.bind("<KeyRelease>", lambda e: self.render_rules())

        tk.Button(
            search_row,
            text="Reload Rules",
            command=self.load_kingfisher_rules,
            bg="#ff8800",
            fg="#000000",
        ).pack(side="left", padx=(0, 5))
        tk.Button(
            search_row,
            text="Select All",
            command=self.select_all_rules,
            bg="#1f8d3a",
            fg="white",
        ).pack(side="left", padx=(0, 5))
        tk.Button(
            search_row,
            text="Select None",
            command=self.select_none_rules,
            bg="#7a2b2b",
            fg="white",
        ).pack(side="left", padx=(0, 5))
        tk.Button(
            search_row,
            text="Save Default (visual only)",
            command=self.save_rules_state,
            bg="#8d5c1f",
            fg="white",
        ).pack(side="left", padx=(0, 5))

        self.rules_count_label = tk.Label(top, text="Rules loaded: 0", fg="#e0e0e0", bg="#05060a")
        self.rules_count_label.pack(anchor="w", pady=(0, 5))

        outer = tk.LabelFrame(parent, text="Kingfisher Rules (read-only list with checkboxes)", fg="#e0e0e0", bg="#0f1015")
        outer.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.rules_canvas = tk.Canvas(outer, bg="#0f1015", highlightthickness=0)
        self.rules_scrollbar = tk.Scrollbar(outer, orient="vertical", command=self.rules_canvas.yview)
        self.rules_inner = tk.Frame(self.rules_canvas, bg="#0f1015")

        self.rules_inner.bind("<Configure>", lambda e: self.rules_canvas.configure(scrollregion=self.rules_canvas.bbox("all")))
        self.rules_canvas.create_window((0, 0), window=self.rules_inner, anchor="nw")
        self.rules_canvas.configure(yscrollcommand=self.rules_scrollbar.set)

        self.rules_canvas.pack(side="left", fill="both", expand=True)
        self.rules_scrollbar.pack(side="right", fill="y")

    def add_context_menus(self):
        self.text_menu = tk.Menu(self, tearoff=0)
        self.text_menu.add_command(label="Cut", command=lambda: self.focus_get().event_generate("<<Cut>>"))
        self.text_menu.add_command(label="Copy", command=lambda: self.focus_get().event_generate("<<Copy>>"))
        self.text_menu.add_command(label="Paste", command=lambda: self.focus_get().event_generate("<<Paste>>"))
        self.text_menu.add_command(label="Select All", command=lambda: self.focus_get().event_generate("<<SelectAll>>"))

        for widget in [
            self.kf_entry,
            self.dir_entry,
            self.urls_text,
            self.keyword_entry,
            self.console,
            self.rules_search_entry,
        ]:
            widget.bind("<Button-3>", lambda e, w=widget: self.show_menu(e, w))

        # Context menu for collector text areas
        for widget in [] if self.hex_text is None else [
            self.hex_text,
            self.b64_text,
            self.b58_text,
            self.bip39_text,
            self.pem_text,
            self.validated_text,
        ]:
            widget.bind("<Button-3>", lambda e, w=widget: self.show_menu(e, w))

    def show_menu(self, event, widget):
        widget.focus_set()
        self.text_menu.tk_popup(event.x_root, event.y_root)

    def browse_kf(self):
        path = filedialog.askopenfilename(
            title="Select kingfisher.exe",
            filetypes=[("Executable", "*.exe"), ("All", "*.*")],
        )
        if path:
            self.kf_path_var.set(path)

    def browse_dir(self):
        d = filedialog.askdirectory(title="Select directory to scan")
        if d:
            self.dir_var.set(d)

    def open_output_folder(self):
        try:
            os.startfile(BASE_DIR)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")

    def load_rules_state(self):
        if os.path.exists(RULES_STATE_FILE):
            try:
                with open(RULES_STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.saved_rules = set(data.get("selected_rules", []))
                self.rules_search_var.set(data.get("search", ""))
            except Exception:
                self.saved_rules = set()

    def save_rules_state(self):
        try:
            data = {
                "selected_rules": [rid for rid, var in self.rules_vars.items() if var.get()],
                "search": self.rules_search_var.get(),
            }
            with open(RULES_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Could not save rule state: {e}")

    def load_kingfisher_rules(self):
        kf = self.kf_path_var.get().strip()
        if not kf or not os.path.isfile(kf):
            return

        cmd = [kf, "rules", "list"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            output = result.stdout
        except Exception:
            return

        self.rules = []
        lines = output.splitlines()

        for line in lines:
            if "│" not in line:
                continue
            parts = [p.strip() for p in line.split("│")]
            if len(parts) < 4:
                continue
            rule_name, rule_id, confidence, pattern = parts[:4]
            if not rule_id.startswith("kingfisher."):
                continue
            self.rules.append(
                {
                    "name": rule_name,
                    "id": rule_id,
                    "confidence": confidence,
                    "pattern": pattern,
                }
            )

        self.rules_loaded = True
        self.rules_count_label.config(text=f"Rules loaded: {len(self.rules)}")
        self.render_rules()

    def render_rules(self):
        for child in self.rules_inner.winfo_children():
            child.destroy()

        query = self.rules_search_var.get().strip().lower()
        self.rules_vars = {}

        row = 0
        for rule in self.rules:
            blob = f'{rule["name"]} {rule["id"]} {rule["confidence"]} {rule["pattern"]}'.lower()
            if query and query not in blob:
                continue

            var = tk.BooleanVar(value=rule["id"] in self.saved_rules if self.saved_rules else True)
            self.rules_vars[rule["id"]] = var

            text = f'{rule["name"]} — {rule["id"]} [{rule["confidence"]}]'
            cb = tk.Checkbutton(
                self.rules_inner,
                text=text,
                variable=var,
                fg="#e0e0e0",
                bg="#0f1015",
                selectcolor="#0f1015",
                anchor="w",
                justify="left",
                wraplength=1200,
                command=self.save_rules_state,
            )
            cb.grid(row=row, column=0, sticky="w", padx=6, pady=2)
            row += 1

        self.rules_inner.update_idletasks()
        self.rules_canvas.yview_moveto(0)

    def select_all_rules(self):
        for var in self.rules_vars.values():
            var.set(True)
        self.save_rules_state()

    def select_none_rules(self):
        for var in self.rules_vars.values():
            var.set(False)
        self.save_rules_state()

    def write_log(self, line):
        self.log_queue.put(line)
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def drain_log_queue(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.console.insert("end", line + "\n")
                self.console.see("end")
        except queue.Empty:
            pass
        self.after(100, self.drain_log_queue)

    def decode_line_hints(self, line):
        hints = []
        token = line.strip()

        if self.dec_pem_var.get() and "-----BEGIN " in line and "-----END " in line:
            try:
                m = re.search(
                    r"-----BEGIN ([A-Z ]+)-----\s+([A-Za-z0-9+/=\r\n]+?)\s+-----END \1-----",
                    line,
                    re.MULTILINE,
                )
                if m:
                    pem_type = m.group(1)
                    raw = base64.b64decode(re.sub(r"\s+", "", m.group(2)))
                    hints.append(f"[PEM {pem_type}: {len(raw)} bytes]")
            except Exception:
                pass

        if self.dec_hex_var.get():
            hex_candidate = re.sub(r"\s+", "", token)
            if (
                len(hex_candidate) >= 16
                and len(hex_candidate) % 2 == 0
                and re.fullmatch(r"[0-9a-fA-F]+", hex_candidate)
            ):
                try:
                    raw = binascii.unhexlify(hex_candidate)
                    try:
                        hints.append(f"[hex→UTF-8] {raw.decode('utf-8')}")
                    except UnicodeDecodeError:
                        hints.append(f"[hex→bytes] len={len(raw)}")
                except Exception:
                    pass

        if self.dec_b64_var.get():
            if len(token) >= 16 and len(token) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", token):
                try:
                    raw = base64.b64decode(token, validate=True)
                    try:
                        hints.append(f"[b64→UTF-8] {raw.decode('utf-8')}")
                    except UnicodeDecodeError:
                        hints.append(f"[b64→bytes] len={len(raw)}")
                except Exception:
                    pass

        if self.dec_b58_var.get() and base58 is not None:
            if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", token):
                try:
                    raw = base58.b58decode(token)
                    try:
                        hints.append(f"[b58→UTF-8] {raw.decode('utf-8')}")
                    except UnicodeDecodeError:
                        hints.append(f"[b58→bytes] len={len(raw)}")
                except Exception:
                    pass

        if self.dec_bip39_var.get():
            words = [w.lower() for w in token.split() if 3 <= len(w) <= 8]
            if len(words) >= 12:
                hints.append(f"[bip39-like] {len(words)} words")

        return hints

    def start_scan(self):
        if self.proc is not None:
            messagebox.showwarning("Scan running", "A scan is already running.")
            return

        kf = self.kf_path_var.get().strip()
        if not kf or not os.path.isfile(kf):
            messagebox.showerror("Error", f"kingfisher binary not found: {kf}")
            return

        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass

        targets = []

        if self.scan_dirs_var.get():
            d = self.dir_var.get().strip()
            if d:
                targets.append(("dir", d))

        raw_urls = self.urls_text.get("1.0", "end").strip().splitlines()
        for u in raw_urls:
            u = u.strip()
            if not u:
                continue

            # strip simple markdown [text](url) to url
            m = re.match(r"\[.*?\]\((https?://[^\)]+)\)", u)
            if m:
                u = m.group(1).strip()

            if u.startswith("http://") or u.startswith("https://"):
                if self.scan_git_var.get() and "github.com" in u:
                    targets.append(("git", u))
                elif self.scan_http_var.get():
                    targets.append(("http", u))

        if not targets:
            messagebox.showwarning(
                "No targets",
                "No targets selected. Check that:\n\n"
                "- Directory path is set and its checkbox is on, or\n"
                "- You have URLs that are valid and git/http checkboxes are on.",
            )
            return

        self.stop_requested = False
        threading.Thread(target=self.run_scan_thread, args=(kf, targets), daemon=True).start()

    def stop_scan(self):
        self.stop_requested = True
        if self.proc is not None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.write_log("[!] Stop requested by user.")

    def run_scan_thread(self, kf, targets):
        try:
            for mode, value in targets:
                if self.stop_requested:
                    break

                cmd = [kf, "scan", value]

                # include contributors for git URLs when enabled
                if mode == "git" and self.include_contribs_var.get():
                    cmd.append("--include-contributors")

                self.write_log(f"\n$ {' '.join(cmd)}\n")

                self.proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                for line in self.proc.stdout:
                    if self.stop_requested:
                        break
                    clean = line.rstrip("\n")
                    self.write_log(clean)
                    for hint in self.decode_line_hints(clean):
                        self.write_log("  " + hint)

                code = self.proc.wait()
                self.write_log(f"[Process exited with code {code}]")
                self.proc = None

        except Exception as e:
            self.write_log(f"[x] Error starting scan: {e}")
        finally:
            self.proc = None

    # -------- collector helpers --------

    def _read_log_lines(self):
        if not os.path.exists(LOG_FILE):
            return []
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                return f.readlines()
        except Exception:
            return []

    def _write_hits(self, path, lines):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception:
            pass

    def _append_master(self, path, lines):
        if not lines:
            return
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception:
            pass

    def collect_hex_hits(self):
        lines = self._read_log_lines()
        hits = []
        for line in lines:
            # simple heuristic: long hex token
            hex_tokens = re.findall(r"\b[0-9a-fA-F]{16,}\b", line)
            if hex_tokens:
                hits.append(line)
        self._write_hits(HITS_HEX_FILE, hits)
        self.hex_text.delete("1.0", "end")
        self.hex_text.insert("1.0", "".join(hits))
        self.hex_text.see("1.0")

    def collect_b64_hits(self):
        lines = self._read_log_lines()
        hits = []
        for line in lines:
            token_matches = re.findall(r"[A-Za-z0-9+/=]{16,}", line)
            useful = False
            for t in token_matches:
                if len(t) >= 32 and len(t) % 4 == 0:
                    useful = True
                    break
            if useful or "[b64→" in line:
                hits.append(line)
        self._write_hits(HITS_B64_FILE, hits)
        self.b64_text.delete("1.0", "end")
        self.b64_text.insert("1.0", "".join(hits))
        self.b64_text.see("1.0")

    def collect_b58_hits(self):
        lines = self._read_log_lines()
        hits = []
        for line in lines:
            token_matches = re.findall(r"[1-9A-HJ-NP-Za-km-z]{16,}", line)
            if token_matches or "[b58→" in line:
                hits.append(line)
        self._write_hits(HITS_B58_FILE, hits)
        self.b58_text.delete("1.0", "end")
        self.b58_text.insert("1.0", "".join(hits))
        self.b58_text.see("1.0")

    def collect_bip39_hits(self):
        lines = self._read_log_lines()
        hits = [line for line in lines if "[bip39-like]" in line]
        self._write_hits(HITS_BIP39_FILE, hits)
        self.bip39_text.delete("1.0", "end")
        self.bip39_text.insert("1.0", "".join(hits))
        self.bip39_text.see("1.0")

    def collect_pem_hits(self):
        lines = self._read_log_lines()
        hits = []
        for line in lines:
            if "-----BEGIN " in line or "-----END " in line or "[PEM " in line:
                hits.append(line)
        self._write_hits(HITS_PEM_FILE, hits)
        self.pem_text.delete("1.0", "end")
        self.pem_text.insert("1.0", "".join(hits))
        self.pem_text.see("1.0")

    def collect_validated_hits(self):
        lines = self._read_log_lines()
        # This depends on Kingfisher's validation output format; match generic "Validated" patterns.
        hits = [line for line in lines if "VALIDATED" in line.upper() or "validation" in line.lower() and "success" in line.lower()]
        self._write_hits(HITS_VALIDATED_FILE, hits)
        self.validated_text.delete("1.0", "end")
        self.validated_text.insert("1.0", "".join(hits))
        self.validated_text.see("1.0")

    def archive_and_clear_hits(self):
        # gather from current hit files
        for path in [HITS_HEX_FILE, HITS_B64_FILE, HITS_B58_FILE, HITS_BIP39_FILE, HITS_PEM_FILE, HITS_VALIDATED_FILE]:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                except Exception:
                    lines = []
                # all hits go to master
                self._append_master(MASTER_HITS_FILE, lines)
                # validated hits also to validated master
                if path == HITS_VALIDATED_FILE:
                    self._append_master(MASTER_VALIDATED_FILE, lines)
                # truncate current
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("")
                except Exception:
                    pass

        # clear GUI views
        self.hex_text.delete("1.0", "end")
        self.b64_text.delete("1.0", "end")
        self.b58_text.delete("1.0", "end")
        self.bip39_text.delete("1.0", "end")
        self.pem_text.delete("1.0", "end")
        self.validated_text.delete("1.0", "end")


if __name__ == "__main__":
    app = KingfisherGUI()
    app.mainloop()