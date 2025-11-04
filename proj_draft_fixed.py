#!/usr/bin/env python3
"""
proj_draft.py

Secure Communication Channel — Hybrid Cryptography
Dark themed UI and fixes (thread-safe UI updates, proper ttk styling).

Dependencies:
    pip install pycryptodome

Run:
    python proj_draft.py
"""
import base64
import json
import threading
import time
import traceback
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ------------------ Crypto helpers ------------------


def generate_rsa_keypair(bits=2048):
    """Generate RSA key pair and return (private_pem_bytes, public_pem_bytes)."""
    key = RSA.generate(bits)
    return key.export_key(format="PEM"), key.publickey().export_key(format="PEM")


def rsa_encrypt(public_pem_bytes, data_bytes):
    """Encrypt with RSA-OAEP using recipient public key bytes."""
    rsa_key = RSA.import_key(public_pem_bytes)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data_bytes)


def rsa_decrypt(private_pem_bytes, ciphertext_bytes):
    """Decrypt RSA-OAEP using recipient private key bytes."""
    rsa_key = RSA.import_key(private_pem_bytes)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext_bytes)


def aes_encrypt_gcm(key_bytes, plaintext_bytes):
    """AES-256-GCM encrypt. Returns (nonce, ciphertext, tag)."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return nonce, ciphertext, tag


def aes_decrypt_gcm(key_bytes, nonce, ciphertext, tag):
    """AES-256-GCM decrypt and verify tag; raises ValueError on failure."""
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def sign_message(private_pem_bytes, message_bytes):
    """Sign SHA-256 hash of message with RSA private key (pkcs1_15)."""
    key = RSA.import_key(private_pem_bytes)
    h = SHA256.new(message_bytes)
    signature = pkcs1_15.new(key).sign(h)
    return signature


def verify_signature(public_pem_bytes, message_bytes, signature_bytes):
    """Return True if signature valid, False otherwise."""
    try:
        key = RSA.import_key(public_pem_bytes)
        h = SHA256.new(message_bytes)
        pkcs1_15.new(key).verify(h, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False


# ------------------ GUI application ------------------


class HybridCryptoGUI(tk.Tk):
    """Main GUI application with dark theme and safe UI updates."""

    def __init__(self):
        super().__init__()
        self.title("Secure Communication Channel — Hybrid Cryptography")
        self.geometry("1150x720")
        self.minsize(1000, 620)
        self.protocol("WM_DELETE_WINDOW", self._on_exit)

        # Palette
        self.PAL = {
            "window_bg": "#071018",    # near-black
            "panel_bg": "#0b1220",     # panel card
            "card_bg": "#0f1722",
            "input_bg": "#07121b",
            "text_fg": "#e6eef6",
            "muted": "#94a3b8",
            "accent": "#10b981",       # green
            "warn": "#f59e0b",         # amber
            "error": "#ef4444",        # red
            "log_bg": "#041126",
            "pkg_bg": "#1f2937",
            "plain_bg": "#08220f",     # greenish dark
            "button_bg": "#0f1722",
            "badge_bg": "#0b1220"
        }

        # in-memory state
        self.sender_priv = None     # bytes or None
        self.sender_pub = None      # bytes or None
        self.receiver_priv = None
        self.receiver_pub = None
        self.package = None         # dict with base64 fields

        # log file
        self.logfile = Path("hybrid_crypto_log.txt")
        self._log_file_header()

        # styling
        self._setup_style()

        # build UI
        self._create_widgets()
        self._set_status("Ready")

    # ---------- logging ----------

    def _log_file_header(self):
        try:
            if not self.logfile.exists():
                with open(self.logfile, "w", encoding="utf-8") as f:
                    f.write(
                        f"Hybrid Crypto GUI Log — {datetime.utcnow().isoformat()}Z\n")
        except Exception:
            pass

    def _log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full = f"[{ts}] {level}: {msg}\n"
        # GUI pane
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", full)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception:
            # in early init log_text may not exist; ignore then
            pass
        # file
        try:
            with open(self.logfile, "a", encoding="utf-8") as f:
                f.write(full)
        except Exception:
            pass

    # ---------- styling ----------

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        # window background
        self.configure(bg=self.PAL["window_bg"])

        # frames and labelframe
        style.configure("TFrame", background=self.PAL["window_bg"])
        style.configure("Card.TLabelframe",
                        background=self.PAL["panel_bg"], relief="flat")
        style.configure("Card.TLabelframe.Label", foreground=self.PAL["text_fg"],
                        background=self.PAL["panel_bg"], font=("Segoe UI", 11, "bold"))

        # header/status
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"),
                        foreground=self.PAL["text_fg"], background=self.PAL["window_bg"])
        style.configure("Status.TLabel", font=("Segoe UI", 10), foreground=self.PAL["accent"],
                        background=self.PAL["window_bg"])

        # buttons
        style.configure("TButton", background=self.PAL["button_bg"], foreground=self.PAL["text_fg"],
                        padding=6, relief="flat")
        style.map("TButton",
                  foreground=[("active", self.PAL["text_fg"])],
                  background=[("active", self.PAL["card_bg"])])

        # small muted labels
        style.configure(
            "Muted.TLabel", foreground=self.PAL["muted"], background=self.PAL["panel_bg"])

    # ---------- widget building ----------

    def _create_widgets(self):
        # top header
        top = ttk.Frame(self, padding=(12, 10), style="TFrame")
        top.pack(fill="x")
        ttk.Label(top, text="Secure Communication Channel — Hybrid Cryptography",
                  style="Header.TLabel").pack(side="left")
        self.status_var = tk.StringVar(value="No keys generated")
        self.status_label = ttk.Label(
            top, textvariable=self.status_var, style="Status.TLabel")
        self.status_label.pack(side="right")

        # main panes
        main_pane = ttk.Panedwindow(self, orient="horizontal")
        main_pane.pack(fill="both", expand=True, padx=12, pady=8)

        # left: sender
        sender_frame = ttk.Labelframe(
            main_pane, text="Sender", padding=12, style="Card.TLabelframe")
        self._build_sender_panel(sender_frame)
        main_pane.add(sender_frame, weight=1)

        # center: controls & log
        center_frame = ttk.Frame(main_pane, padding=10, style="TFrame")
        self._build_center_panel(center_frame)
        main_pane.add(center_frame, weight=0)

        # right: receiver
        receiver_frame = ttk.Labelframe(
            main_pane, text="Receiver", padding=12, style="Card.TLabelframe")
        self._build_receiver_panel(receiver_frame)
        main_pane.add(receiver_frame, weight=1)

    # ---------- sender panel ----------

    def _build_sender_panel(self, parent):
        # top row (badge + buttons)
        upper = ttk.Frame(parent, style="TFrame")
        upper.pack(fill="x")

        # badge (tk.Label used for explicit bg/fg)
        self.sender_status = tk.Label(upper, text="Keys: none",
                                      bg=self.PAL["badge_bg"], fg=self.PAL["text_fg"], padx=8, pady=4)
        self.sender_status.pack(side="left", padx=(0, 8))

        ttk.Button(upper, text="Generate Sender Keys",
                   command=self._threaded_gen_sender).pack(side="left", padx=4)
        ttk.Button(upper, text="Save Sender Key",
                   command=self._save_sender_key).pack(side="left", padx=4)
        ttk.Button(upper, text="Load Sender Key",
                   command=self._load_sender_key).pack(side="left", padx=4)

        # plaintext area label & text (tk.Label for bg control)
        tk.Label(parent, text="Plaintext message:",
                 bg=self.PAL["panel_bg"], fg=self.PAL["muted"]).pack(anchor="w", pady=(8, 4))
        self.msg_entry = tk.Text(parent, width=48, height=10, wrap="word", font=("Courier New", 11),
                                 bg=self.PAL["input_bg"], fg=self.PAL["text_fg"], insertbackground=self.PAL["text_fg"],
                                 relief="flat", bd=6)
        self.msg_entry.pack(fill="both", expand=True)

        # row of actions
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=8)
        ttk.Button(row, text="Encrypt & Send →",
                   command=self._encrypt_and_send).pack(side="left", padx=4)
        ttk.Button(row, text="Clear message", command=lambda: self.msg_entry.delete(
            "1.0", "end")).pack(side="left", padx=4)
        ttk.Button(row, text="Export Package (JSON)",
                   command=self._export_package).pack(side="left", padx=4)

        # ciphertext display
        tk.Label(parent, text="Last ciphertext (Base64):",
                 bg=self.PAL["panel_bg"], fg=self.PAL["muted"]).pack(anchor="w", pady=(6, 4))
        self.cipher_display = tk.Text(parent, width=48, height=8, wrap="none", bg=self.PAL["input_bg"], fg=self.PAL["text_fg"], insertbackground=self.PAL["text_fg"], relief="flat", bd=6)
        self.cipher_display.pack(fill="both", expand=True)

    # ---------- center panel ----------

    def _build_center_panel(self, parent):
        # tamper / import buttons
        ttk.Button(parent, text="Simulate Tamper (flip package)", command=self._tamper_package).pack(fill="x", pady=(0, 8))
        ttk.Button(parent, text="Import Package (JSON)", command=self._import_package).pack(fill="x", pady=4)

        ttk.Separator(parent, orient="horizontal").pack(fill="x", pady=8)

        # log header & text
        tk.Label(parent, text="Activity Log:", bg=self.PAL["window_bg"], fg=self.PAL["muted"]).pack(anchor="w")
        self.log_text = tk.Text(parent, width=48, height=26, state="disabled",
                                bg=self.PAL["log_bg"], fg=self.PAL["text_fg"], insertbackground=self.PAL["text_fg"],
                                relief="flat", bd=6)
        self.log_text.pack(fill="both", expand=True)

    # ---------- receiver panel ----------

    def _build_receiver_panel(self, parent):
        upper = ttk.Frame(parent, style="TFrame")
        upper.pack(fill="x")

        self.receiver_status = tk.Label(upper, text="Keys: none",
                                        bg=self.PAL["badge_bg"], fg=self.PAL["text_fg"], padx=8, pady=4)
        self.receiver_status.pack(side="left", padx=(0, 8))

        ttk.Button(upper, text="Generate Receiver Keys", command=self._threaded_gen_receiver).pack(side="left", padx=4)
        ttk.Button(upper, text="Save Receiver Key", command=self._save_receiver_key).pack(side="left", padx=4)
        ttk.Button(upper, text="Load Receiver Key", command=self._load_receiver_key).pack(side="left", padx=4)

        tk.Label(parent, text="Received Package (summary):", bg=self.PAL["panel_bg"], fg=self.PAL["muted"]).pack(anchor="w", pady=(8, 4))
        self.package_display = tk.Text(parent, width=48, height=10, wrap="none", bg=self.PAL["pkg_bg"], fg=self.PAL["text_fg"], insertbackground=self.PAL["text_fg"], relief="flat", bd=6)
        self.package_display.pack(fill="both", expand=True)

        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=8)
        ttk.Button(row, text="Decrypt & Verify", command=self._decrypt_and_verify).pack(side="left", padx=4)
        ttk.Button(row, text="Clear package view", command=lambda: self.package_display.delete("1.0", "end")).pack(side="left", padx=4)
        ttk.Button(row, text="Save Package as File", command=self._export_package).pack(side="left", padx=4)

        tk.Label(parent, text="Decrypted message & status:", bg=self.PAL["panel_bg"], fg=self.PAL["muted"]).pack(anchor="w", pady=(6, 4))
        self.plain_display = tk.Text(parent, width=48, height=10, wrap="word", bg=self.PAL["plain_bg"], fg=self.PAL["text_fg"], insertbackground=self.PAL["text_fg"], relief="flat", bd=6)
        self.plain_display.pack(fill="both", expand=True)

    # ---------- status helpers ----------

    def _set_status(self, s):
        # schedule status update on main thread for safety
        def _do():
            self.status_var.set(s)
            self._log(s)

        self.after(0, _do)

    def _update_key_badge(self):
        # update badges on main thread
        def _do():
            if self.sender_priv or self.sender_pub:
                self.sender_status.configure(text="Keys: ready", fg=self.PAL["accent"])
            else:
                self.sender_status.configure(text="Keys: none", fg=self.PAL["error"])

            if self.receiver_priv or self.receiver_pub:
                self.receiver_status.configure(text="Keys: ready", fg=self.PAL["accent"])
            else:
                self.receiver_status.configure(text="Keys: none", fg=self.PAL["error"])

        self.after(0, _do)

    # ---------- safe messagebox helpers (callable from threads) ----------

    def _safe_showinfo(self, title, msg):
        self.after(0, lambda: messagebox.showinfo(title, msg))

    def _safe_showerror(self, title, msg):
        self.after(0, lambda: messagebox.showerror(title, msg))

    # ---------- threaded keygen (to keep UI responsive) ----------

    def _threaded_gen_sender(self):
        t = threading.Thread(target=self._gen_sender_keys, daemon=True)
        t.start()

    def _threaded_gen_receiver(self):
        t = threading.Thread(target=self._gen_receiver_keys, daemon=True)
        t.start()

    def _gen_sender_keys(self):
        try:
            self._set_status("Generating Sender RSA-2048 keys...")
            priv, pub = generate_rsa_keypair(2048)
            # simulate some work so user sees status change
            time.sleep(0.3)
            self.sender_priv = priv
            self.sender_pub = pub
            self._update_key_badge()
            self._set_status("Sender keys generated (2048 bits)")
            self._log("Sender keypair generated.")
            self._safe_showinfo("Sender Keys", "Sender RSA-2048 keypair generated successfully.")
        except Exception as e:
            self._log(f"Sender key generation failed: {e}", level="ERROR")
            self._safe_showerror("Error", f"Failed to generate Sender keys:\n{e}\n{traceback.format_exc()}")

    def _gen_receiver_keys(self):
        try:
            self._set_status("Generating Receiver RSA-2048 keys...")
            priv, pub = generate_rsa_keypair(2048)
            time.sleep(0.3)
            self.receiver_priv = priv
            self.receiver_pub = pub
            self._update_key_badge()
            self._set_status("Receiver keys generated (2048 bits)")
            self._log("Receiver keypair generated.")
            self._safe_showinfo("Receiver Keys", "Receiver RSA-2048 keypair generated successfully.")
        except Exception as e:
            self._log(f"Receiver key generation failed: {e}", level="ERROR")
            self._safe_showerror("Error", f"Failed to generate Receiver keys:\n{e}\n{traceback.format_exc()}")

    # ---------- save / load keys ----------

    def _save_sender_key(self):
        if not self.sender_priv:
            messagebox.showwarning("No Sender Key", "No sender private key to save. Generate or load a private key first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Sender Private Key (PEM)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self.sender_priv)
            self._log(f"Sender private key saved to {path}")
            messagebox.showinfo("Saved", f"Sender private key saved to:\n{path}")
        except Exception as e:
            self._log(f"Failed to save sender key: {e}", level="ERROR")
            messagebox.showerror("Error", f"Failed to save: {e}")

    def _save_receiver_key(self):
        if not self.receiver_priv:
            messagebox.showwarning("No Receiver Key", "No receiver private key to save. Generate or load a private key first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Receiver Private Key (PEM)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self.receiver_priv)
            self._log(f"Receiver private key saved to {path}")
            messagebox.showinfo("Saved", f"Receiver private key saved to:\n{path}")
        except Exception as e:
            self._log(f"Failed to save receiver key: {e}", level="ERROR")
            messagebox.showerror("Error", f"Failed to save: {e}")

    def _load_sender_key(self):
        path = filedialog.askopenfilename(title="Load Sender Key (PEM)", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                raw = f.read()
            key = RSA.import_key(raw)
            # detect private vs public
            if getattr(key, "has_private", lambda: False)():
                # key object supports has_private()
                is_private = key.has_private()
            else:
                # fallback: try to access private attributes
                try:
                    _ = key.d  # will exist only for private keys
                    is_private = True
                except Exception:
                    is_private = False

            if is_private:
                priv = raw
                pub = key.publickey().export_key(format="PEM")
                self.sender_priv = priv
                self.sender_pub = pub
                self._log(f"Loaded sender private key from {path}")
                messagebox.showinfo("Loaded", f"Sender private key loaded from:\n{path}")
            else:
                # public key only
                pub = key.export_key(format="PEM")
                self.sender_pub = pub
                self.sender_priv = None
                self._log(f"Loaded sender public key from {path} (public-only)")
                messagebox.showinfo("Loaded", f"Sender public key loaded (public-only):\n{path}")

            self._update_key_badge()
        except Exception as e:
            self._log(f"Failed to load sender key: {e}", level="ERROR")
            messagebox.showerror("Error", f"Failed to load key:\n{e}")

    def _load_receiver_key(self):
        path = filedialog.askopenfilename(title="Load Receiver Key (PEM)", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                raw = f.read()
            key = RSA.import_key(raw)
            # detect private vs public
            if getattr(key, "has_private", lambda: False)():
                is_private = key.has_private()
            else:
                try:
                    _ = key.d
                    is_private = True
                except Exception:
                    is_private = False

            if is_private:
                self.receiver_priv = raw
                self.receiver_pub = key.publickey().export_key(format="PEM")
                self._log(f"Loaded receiver private key from {path}")
                messagebox.showinfo("Loaded", f"Receiver private key loaded from:\n{path}")
            else:
                self.receiver_pub = key.export_key(format="PEM")
                self.receiver_priv = None
                self._log(f"Loaded receiver public key from {path} (public-only)")
                messagebox.showinfo("Loaded", f"Receiver public key loaded (public-only):\n{path}")

            self._update_key_badge()
        except Exception as e:
            self._log(f"Failed to load receiver key: {e}", level="ERROR")
            messagebox.showerror("Error", f"Failed to load key:\n{e}")

    # ---------- encryption (sender) ----------

    def _encrypt_and_send(self):
        # check presence of keys
        if not (self.sender_priv or self.sender_pub):
            messagebox.showwarning("Missing Sender Key", "Please generate or load Sender keys first.")
            return
        if not self.receiver_pub:
            messagebox.showwarning("Missing Receiver Public Key", "Please generate or load Receiver public key first.")
            return

        msg = self.msg_entry.get("1.0", "end").strip()
        if not msg:
            messagebox.showwarning("Empty message", "Type a plaintext message to encrypt.")
            return

        try:
            msg_bytes = msg.encode("utf-8")

            # 1) AES session key (256-bit)
            session_key = get_random_bytes(32)

            # 2) Encrypt with AES-GCM
            nonce, ciphertext, tag = aes_encrypt_gcm(session_key, msg_bytes)

            # 3) Encrypt session key with receiver public RSA
            enc_session_key = rsa_encrypt(self.receiver_pub, session_key)

            # 4) Sign plaintext with sender private key (if private available)
            if self.sender_priv:
                signature = sign_message(self.sender_priv, msg_bytes)
            else:
                # no private key available -> signature omitted (set to empty)
                signature = b""

            pkg = {
                "enc_session_key": base64.b64encode(enc_session_key).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "tag": base64.b64encode(tag).decode("utf-8"),
                "signature": base64.b64encode(signature).decode("utf-8"),
                "sender_pub": base64.b64encode(self.sender_pub if self.sender_pub else b"").decode("utf-8"),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

            self.package = pkg

            # update UI displays
            self.cipher_display.delete("1.0", "end")
            self.cipher_display.insert("1.0", pkg["ciphertext"])
            self._display_package_summary(pkg)
            self._set_status("Message encrypted & package created")
            self._log("Message encrypted and package created.")
            messagebox.showinfo("Sent", "Message encrypted and package delivered to Receiver view (simulated).")
        except Exception as e:
            self._log(f"Encryption error: {e}\n{traceback.format_exc()}", level="ERROR")
            messagebox.showerror("Encryption Error", f"Failed to encrypt message:\n{e}")

    # ---------- package display / import / export ----------

    def _display_package_summary(self, pkg):
        self.package_display.delete("1.0", "end")
        lines = [
            f"Encrypted Session Key (first 60 chars): {pkg['enc_session_key'][:60]}...",
            f"Nonce: {pkg['nonce'][:20]}...",
            f"Ciphertext (first 60 chars): {pkg['ciphertext'][:60]}...",
            f"Tag: {pkg['tag'][:20]}...",
            f"Signature (first 60 chars): {pkg['signature'][:60]}...",
            f"Sender Public Key (first 60 chars): {pkg['sender_pub'][:60]}...",
            f"Timestamp: {pkg.get('timestamp', '-') }"
        ]
        self.package_display.insert("1.0", "\n".join(lines))

    def _export_package(self):
        if not self.package:
            messagebox.showwarning("No Package", "No package to export. Encrypt & Send first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", title="Save Package", filetypes=[("JSON files", "*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.package, f, indent=2)
            self._log(f"Package exported to {path}")
            messagebox.showinfo("Exported", f"Package saved to:\n{path}")
        except Exception as e:
            self._log(f"Failed to export package: {e}", level="ERROR")
            messagebox.showerror("Error", f"Failed to export package:\n{e}")

    def _import_package(self):
        path = filedialog.askopenfilename(title="Open Package JSON", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            required = {"enc_session_key", "nonce", "ciphertext", "tag", "signature", "sender_pub"}
            if not required.issubset(pkg.keys()):
                raise ValueError("JSON missing required package fields.")
            self.package = pkg
            self._display_package_summary(pkg)
            self._set_status(f"Package imported from {Path(path).name}")
            self._log(f"Package imported from {path}")
            messagebox.showinfo("Imported", f"Package imported from:\n{path}")
        except Exception as e:
            self._log(f"Failed to import package: {e}", level="ERROR")
            messagebox.showerror("Import Error", f"Failed to import package:\n{e}")

    # ---------- tamper simulation ----------

    def _tamper_package(self):
        if not self.package:
            messagebox.showwarning("No Package", "Nothing to tamper. Create or import a package first.")
            return
        try:
            ct_b64 = self.package["ciphertext"]
            pos = max(2, len(ct_b64)//8)
            flipped = list(ct_b64)
            flipped[pos] = 'A' if flipped[pos] != 'A' else 'B'
            self.package["ciphertext"] = "".join(flipped)
            self._display_package_summary(self.package)
            self._set_status("Package tampered (simulated)")
            self._log("Package tampered for demonstration.")
            messagebox.showinfo("Tampered", "Package modified to demonstrate integrity failure.")
        except Exception as e:
            self._log(f"Tamper simulation failed: {e}", level="ERROR")
            messagebox.showerror("Error", f"Tamper simulation failed:\n{e}")

    # ---------- decrypt & verify (receiver) ----------

    def _decrypt_and_verify(self):
        if not self.receiver_priv:
            messagebox.showwarning("Missing Receiver Private Key", "Please generate or load Receiver private key first.")
            return
        if not self.package:
            messagebox.showwarning("No Package", "No package available. Import or wait for Sender.")
            return

        try:
            enc_session_key = base64.b64decode(self.package["enc_session_key"])
            nonce = base64.b64decode(self.package["nonce"])
            ciphertext = base64.b64decode(self.package["ciphertext"])
            tag = base64.b64decode(self.package["tag"])
            signature = base64.b64decode(self.package["signature"])
            sender_pub_pem = base64.b64decode(self.package["sender_pub"])

            # decrypt session key
            session_key = rsa_decrypt(self.receiver_priv, enc_session_key)

            # decrypt ciphertext (ValueError if tag invalid)
            plaintext_bytes = aes_decrypt_gcm(session_key, nonce, ciphertext, tag)

            # verify signature (if present)
            sig_ok = False
            if sender_pub_pem and len(signature) > 0:
                sig_ok = verify_signature(sender_pub_pem, plaintext_bytes, signature)
            else:
                sig_ok = False

            plain_text = plaintext_bytes.decode("utf-8", errors="replace")
            self.plain_display.delete("1.0", "end")
            self.plain_display.insert("1.0", f"Message:\n{plain_text}\n\n")
            if sig_ok:
                status_text = "✓ Signature valid — Sender authenticated. Integrity OK."
                self.plain_display.insert("end", status_text)
                self._set_status("Decryption & verification successful")
                self._log("Decryption and signature verification SUCCESS.")
                messagebox.showinfo("Verified", "Message decrypted and signature verified successfully.")
            else:
                status_text = "✗ Signature INVALID or missing — Sender could not be authenticated."
                self.plain_display.insert("end", status_text)
                self._set_status("Signature verification failed")
                self._log("Signature verification FAILED.", level="ERROR")
                messagebox.showerror("Signature Error", "Signature verification failed or signature missing! Do not trust this message.")

        except ValueError as e:
            # AES-GCM tag fail (integrity)
            self.plain_display.delete("1.0", "end")
            self.plain_display.insert("1.0", "✗ INTEGRITY CHECK FAILED — Message tampered or corrupted.")
            self._set_status("Integrity check FAILED")
            self._log(f"Integrity check failed: {e}", level="ERROR")
            messagebox.showerror("Integrity Error", f"Integrity verification failed:\n{e}")
        except Exception as e:
            self._log(f"Decrypt/Verify error: {e}\n{traceback.format_exc()}", level="ERROR")
            messagebox.showerror("Error", f"Failed to decrypt/verify:\n{e}")

    # ---------- exit ----------

    def _on_exit(self):
        if messagebox.askokcancel("Quit", "Exit the application?"):
            self.destroy()


# ---------- main ----------

def main():
    app = HybridCryptoGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
