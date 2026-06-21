import os
import subprocess
import threading
import queue
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import re
import binascii
import base64

try:
    import base58
except ImportError:
    base58 = None

DEFAULT_KF_PATH = os.path.join(os.environ.get("USERPROFILE", ""), "bin", "kingfisher.exe")
DEFAULT_GITHUB_ROOT = "https://github.com/RepoHere1/"
LOG_FILE = os.path.join(os.path.dirname(__file__), "kingfisher_gui_output.log")


class KingfisherGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kingfisher Secrets Scanner GUI")
        self.geometry("1000x720")
        self.configure(bg="#05060a")

        self.proc = None
        self.stop_requested = False
        self.log_queue = queue.Queue()

        self.create_widgets()
        self.after(100, self.drain_log_queue)

    def create_widgets(self):
        # --- Row 0: Kingfisher binary path + Browse + Open Output Folder ---
        top_frame = tk.Frame(self, bg="#05060a")
        top_frame.pack(fill="x", padx=10, pady=(10, 5))

        tk.Label(top_frame, text="Kingfisher binary:", fg="#e0e0e0", bg="#05060a").pack(side="left")
        self.kf_path_var = tk.StringVar(value=DEFAULT_KF_PATH)
        self.kf_entry = tk.Entry(top_frame, textvariable=self.kf_path_var, width=70,
                                 bg="#080910", fg="#f5f5f5", insertbackground="#f5f5f5")
        self.kf_entry.pack(side="left", padx=(5, 5))
        tk.Button(top_frame, text="Browse", command=self.browse_kf,
                  bg="#1f4fff", fg="white").pack(side="left", padx=(0, 8))

        tk.Button(top_frame, text="Open Output Folder",
                  command=self.open_output_folder,
                  bg="#1f538d", fg="white").pack(side="left")

        # --- Row 1: Targets frame ---
        targets_frame = tk.LabelFrame(self, text="Targets", fg="#e0e0e0", bg="#0f1015")
        targets_frame.pack(fill="x", padx=10, pady=5)

        # Local directory target
        dir_frame = tk.Frame(targets_frame, bg="#0f1015")
        dir_frame.pack(fill="x", padx=5, pady=3)
        tk.Label(dir_frame, text="Local directory to scan:", fg="#e0e0e0", bg="#0f1015").pack(side="left")
        self.dir_var = tk.StringVar()
        self.dir_entry = tk.Entry(dir_frame, textvariable=self.dir_var, width=70,
                                  bg="#080910", fg="#f5f5f5", insertbackground="#f5f5f5")
        self.dir_entry.pack(side="left", padx=(5, 5))
        tk.Button(dir_frame, text="Browse", command=self.browse_dir,
                  bg="#1f4fff", fg="white").pack(side="left")

        # URLs / git URLs
        urls_frame = tk.Frame(targets_frame, bg="#0f1015")
        urls_frame.pack(fill="both", padx=5, pady=3)
        tk.Label(urls_frame, text="URLs / git URLs (one per line):", fg="#e0e0e0", bg="#0f1015").pack(anchor="w")
        self.urls_text = scrolledtext.ScrolledText(urls_frame, height=4,
                                                   bg="#080910", fg="#f5f5f5", insertbackground="#f5f5f5")
        self.urls_text.pack(fill="x", pady=(2, 2))
        self.urls_text.insert("1.0", DEFAULT_GITHUB_ROOT + "\n")

        # --- Row 2: Scan options / decoders ---
        options_frame = tk.LabelFrame(self, text="Scan Options & Decoders", fg="#e0e0e0", bg="#0f1015")
        options_frame.pack(fill="x", padx=10, pady=5)

        left_opts = tk.Frame(options_frame, bg="#0f1015")
        left_opts.pack(side="left", fill="y", padx=10, pady=5)

        right_opts = tk.Frame(options_frame, bg="#0f1015")
        right_opts.pack(side="left", fill="y", padx=10, pady=5)

        # Mode toggles
        self.scan_dirs_var = tk.BooleanVar(value=True)
        self.scan_git_var = tk.BooleanVar(value=True)
        self.scan_http_var = tk.BooleanVar(value=True)

        tk.Checkbutton(left_opts, text="Scan local directory path",
                       variable=self.scan_dirs_var, fg="#e0e0e0",
                       bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(left_opts, text="Scan git URLs (https://github.com/...)",
                       variable=self.scan_git_var, fg="#e0e0e0",
                       bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(left_opts, text="Scan HTTP URLs (http/https)",
                       variable=self.scan_http_var, fg="#e0e0e0",
                       bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")

        # Decoder helper toggles
        self.dec_hex_var = tk.BooleanVar(value=True)
        self.dec_b64_var = tk.BooleanVar(value=True)
        self.dec_b58_var = tk.BooleanVar(value=True)
        self.dec_bip39_var = tk.BooleanVar(value=True)
        self.dec_pem_var = tk.BooleanVar(value=True)

        tk.Label(right_opts, text="Decode helpers (for matching lines):",
                 fg="#e0e0e0", bg="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="Hex", variable=self.dec_hex_var,
                       fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="Base64", variable=self.dec_b64_var,
                       fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="Base58", variable=self.dec_b58_var,
                       fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="BIP39-like", variable=self.dec_bip39_var,
                       fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")
        tk.Checkbutton(right_opts, text="PEM blocks", variable=self.dec_pem_var,
                       fg="#e0e0e0", bg="#0f1015", selectcolor="#0f1015").pack(anchor="w")

        # --- Row 3: Controls ---
        controls_frame = tk.Frame(self, bg="#05060a")
        controls_frame.pack(fill="x", padx=10, pady=5)

        self.run_button = tk.Button(controls_frame, text="RUN SCAN",
                                    command=self.start_scan, bg="#1f4fff",
                                    fg="white", width=15)
        self.run_button.pack(side="left", padx=(0, 5))

        self.stop_button = tk.Button(controls_frame, text="STOP",
                                     command=self.stop_scan, bg="#cc0000",
                                     fg="white", width=10)
        self.stop_button.pack(side="left", padx=(5, 5))

        # --- Row 4: Log console ---
        console_frame = tk.LabelFrame(self, text="Kingfisher Output + Decoded Hints",
                                      fg="#e0e0e0", bg="#0f1015")
        console_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.console = scrolledtext.ScrolledText(console_frame, font=("Consolas", 10),
                                                 bg="#050505", fg="#00ff66",
                                                 insertbackground="#00ff66")
        self.console.pack(fill="both", expand=True)

    # ---------- UI Helpers ----------

    def browse_kf(self):
        path = filedialog.askopenfilename(title="Select kingfisher.exe",
                                          filetypes=[("Executable", "*.exe"), ("All", "*.*")])
        if path:
            self.kf_path_var.set(path)

    def browse_dir(self):
        d = filedialog.askdirectory(title="Select directory to scan")
        if d:
            self.dir_var.set(d)

    def open_output_folder(self):
        folder = os.path.dirname(LOG_FILE)
        try:
            os.startfile(folder)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")

    # ---------- Logging / decoding ----------

    def write_log(self, line: str):
        # write to GUI
        self.log_queue.put(line)
        # append to file
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

    def decode_line_hints(self, line: str):
        """
        Try to produce human-readable hints from lines that look like secrets.
        Controlled by the decode checkboxes.
        """
        hints = []

        # PEM
        if self.dec_pem_var.get() and "-----BEGIN " in line and "-----END " in line:
            try:
                pem_match = re.search(
                    r"-----BEGIN ([A-Z ]+)-----\s+([A-Za-z0-9+/=\r\n]+?)\s+-----END \1-----",
                    line,
                    re.MULTILINE,
                )
                if pem_match:
                    pem_type = pem_match.group(1)
                    b64_body = pem_match.group(2)
                    raw = base64.b64decode(re.sub(r"\s+", "", b64_body))
                    hints.append(f"[PEM {pem_type}: {len(raw)} bytes]")
            except Exception:
                pass

        token = line.strip()

        # HEX
        if self.dec_hex_var.get():
            hex_candidate = re.sub(r"\s+", "", token)
            if len(hex_candidate) >= 16 and len(hex_candidate) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", hex_candidate):
                try:
                    raw = binascii.unhexlify(hex_candidate)
                    try:
                        decoded = raw.decode("utf-8")
                        hints.append(f"[hex→UTF-8] {decoded}")
                    except UnicodeDecodeError:
                        hints.append(f"[hex→bytes] len={len(raw)}")
                except Exception:
                    pass

        # BASE64
        if self.dec_b64_var.get():
            b64_candidate = token
            if len(b64_candidate) >= 16 and len(b64_candidate) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", b64_candidate):
                try:
                    raw = base64.b64decode(b64_candidate, validate=True)
                    try:
                        decoded = raw.decode("utf-8")
                        hints.append(f"[b64→UTF-8] {decoded}")
                    except UnicodeDecodeError:
                        hints.append(f"[b64→bytes] len={len(raw)}")
                except Exception:
                    pass

        # BASE58
        if self.dec_b58_var.get() and base58 is not None:
            if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", token):
                try:
                    raw = base58.b58decode(token)
                    try:
                        decoded = raw.decode("utf-8")
                        hints.append(f"[b58→UTF-8] {decoded}")
                    except UnicodeDecodeError:
                        hints.append(f"[b58→bytes] len={len(raw)}")
                except Exception:
                    pass

        # BIP39-like
        if self.dec_bip39_var.get():
            words = [w.lower() for w in token.split() if 3 <= len(w) <= 8]
            if len(words) >= 12:
                hints.append(f"[bip39-like] {len(words)} words: " + " ".join(words[:24]))

        return hints

    # ---------- Scan control ----------

    def start_scan(self):
        if self.proc is not None:
            messagebox.showwarning("Scan running", "A scan is already running.")
            return

        kf = self.kf_path_var.get().strip()
        if not kf or not os.path.isfile(kf):
            messagebox.showerror("Error", f"kingfisher binary not found: {kf}")
            return

        # Clear output log file for fresh run
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass

        self.console.insert("end", "\n=== Starting Kingfisher scan ===\n")
        self.console.see("end")

        targets = []

        # Local directory
        if self.scan_dirs_var.get():
            d = self.dir_var.get().strip()
            if d:
                targets.append(("dir", d))

        # URLs/git
        raw_urls = self.urls_text.get("1.0", "end").strip().splitlines()
        for u in raw_urls:
            u = u.strip()
            if not u:
                continue
            if u.startswith("http://") or u.startswith("https://"):
                if self.scan_git_var.get() and "github.com" in u:
                    targets.append(("git", u))
                elif self.scan_http_var.get():
                    targets.append(("http", u))

        if not targets:
            messagebox.showwarning("No targets", "No targets selected. Set a directory and/or URLs.")
            return

        self.stop_requested = False
        t = threading.Thread(target=self.run_scan_thread, args=(kf, targets), daemon=True)
        t.start()

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

                if mode == "dir":
                    cmd = [kf, "scan", value]
                elif mode == "git":
                    cmd = [kf, "scan", value]
                elif mode == "http":
                    cmd = [kf, "scan", value]
                else:
                    continue

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

                    # If it looks like an interesting line, try decode helpers
                    lower = clean.lower()
                    if any(tok in lower for tok in ("secret", "token", "key", "api", "credential")):
                        hints = self.decode_line_hints(clean)
                        for h in hints:
                            self.write_log("  " + h)

                code = self.proc.wait()
                self.write_log(f"[Process exited with code {code}]")
                self.proc = None

        except Exception as e:
            self.write_log(f"[x] Error starting scan: {e}")
        finally:
            self.proc = None


if __name__ == "__main__":
    app = KingfisherGUI()
    app.mainloop()