#!/usr/bin/env python3
import os, sys, math, json, time, secrets, tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception:
    tk.Tk().withdraw()
    messagebox.showerror("Missing dependency", "Install:\n  pip install cryptography")
    sys.exit(1)

try:
    from argon2.low_level import hash_secret_raw, Type
    HAVE_ARGON2 = True
except Exception:
    HAVE_ARGON2 = False

if sys.platform.startswith("win"):
    try:
        import ctypes
        try: ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception: ctypes.windll.user32.SetProcessDPIAware()
    except Exception: pass

UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGIT = "0123456789"
SYMBOL = r"!@#$%^&*()-_=+[]{};:,.?/\\|`~'\"<>"
UNICODE_EXTRA = (
    "§±µ¶ªº¿¡€£¥₿₩₪₫₴₺₦₭ℤℝℵ∆∇∑∏√∞≈≠≤≥⊕⊗⊙⊥⋈⋂⋃∩∪↦↺↻⇄⇆⇌⇔∀∃⊂⊃⊆⊇"
    "αβγδεζηθικλμνξοπρστυφχψωΓΔΘΛΞΠΣΦΨΩ"
)

MAGIC = b"CCBIN\x00"
VERSION = 1
KDF_ARGON2ID = 1
KDF_PBKDF2 = 2

def entropy_bits(length, alphabet_size): return length * math.log2(alphabet_size)

def gen_password(length, use_unicode):
    if length < 8: raise ValueError("Minimum length is 8")
    pools = [UPPER, LOWER, DIGIT, SYMBOL]
    if use_unicode: pools.append(UNICODE_EXTRA)
    union = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    for _ in range(length - len(chars)):
        chars.append(secrets.choice(union))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars), entropy_bits(length, len(set(union)))

def kdf_derive(key_len, password, salt, kind, params):
    pwd = password.encode("utf-8")
    if kind == KDF_ARGON2ID:
        return hash_secret_raw(
            secret=pwd, salt=salt,
            time_cost=int(params.get("time_cost", 2)),
            memory_cost=int(params.get("mem_kib", 262144)),
            parallelism=int(params.get("parallelism", 2)),
            hash_len=key_len, type=Type.ID,
        )
    iters = int(params.get("iterations", 600_000))
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=iters).derive(pwd)

def _stealth_pad_bytes():
    pad_len = 65536 + secrets.randbelow(196608)
    pad = bytearray(b"\xEF\xBB\xBF")
    for _ in range(pad_len):
        pad.append(0x0A if secrets.randbits(1) else 0x20)
    return bytes(pad)

def _build_header(kdf_kind, salt, nonce, params_dict):
    h = bytearray()
    h += MAGIC
    h += VERSION.to_bytes(1, "big")
    h += (kdf_kind & 0xFF).to_bytes(1, "big")
    h += len(salt).to_bytes(1, "big")
    h += len(nonce).to_bytes(1, "big")
    pbytes = json.dumps(params_dict, separators=(",", ":")).encode("utf-8")
    h += len(pbytes).to_bytes(2, "big")
    return bytes(h), pbytes

def write_cc_text(path, text, password, kdf_kind=None):
    write_cc_bytes(path, text.encode("utf-8"), password, kdf_kind)

def write_cc_bytes(path, blob, password, kdf_kind=None):
    if kdf_kind is None: kdf_kind = KDF_ARGON2ID if HAVE_ARGON2 else KDF_PBKDF2
    salt = secrets.token_bytes(32 if kdf_kind == KDF_ARGON2ID else 16)
    nonce = secrets.token_bytes(12)
    params = {"mem_kib": 262144, "time_cost": 2, "parallelism": 2} if kdf_kind == KDF_ARGON2ID else {"iterations": 600_000}
    key = kdf_derive(32, password, salt, kdf_kind, params)
    ct = AESGCM(key).encrypt(nonce, blob, b"ccbin-v1")
    header, pbytes = _build_header(kdf_kind, salt, nonce, params)
    pad = _stealth_pad_bytes()
    tmp = f"{path}.tmp-{os.getpid()}-{int(time.time())}"
    with open(tmp, "wb") as f:
        f.write(pad)
        f.write(header)
        f.write(salt)
        f.write(nonce)
        f.write(pbytes)
        f.write(ct)
    os.replace(tmp, path)

def read_cc_text(path, password):
    return read_cc_bytes(path, password).decode("utf-8")

def read_cc_bytes(path, password):
    with open(path, "rb") as f: data = f.read()
    idx = data.find(MAGIC)
    if idx < 0: raise ValueError("Not a .cc file")
    off = idx + len(MAGIC)
    if off + 5 > len(data): raise ValueError("Corrupt file")
    ver = data[off]; off += 1
    if ver != VERSION: raise ValueError("Unsupported version")
    kdf_kind = data[off]; off += 1
    sl = data[off]; off += 1
    nl = data[off]; off += 1
    pl = int.from_bytes(data[off:off+2], "big"); off += 2
    need = off + sl + nl + pl
    if len(data) < need: raise ValueError("Truncated file")
    salt = data[off:off+sl]; off += sl
    nonce = data[off:off+nl]; off += nl
    params = json.loads(data[off:off+pl].decode("utf-8")); off += pl
    ct = data[off:]
    key = kdf_derive(32, password, salt, kdf_kind, params)
    return AESGCM(key).decrypt(nonce, ct, b"ccbin-v1")

# ---------- UI ----------
class CopyDialog(tk.Toplevel):
    def __init__(self, master, title, text):
        super().__init__(master)
        self.title(title); self.configure(bg="#101216"); self.resizable(False, False)
        self.transient(master); self.grab_set()
        frm = ttk.Frame(self, padding=12); frm.grid(sticky="nsew")
        ttk.Label(frm, text="Keep this safe:").grid(row=0, column=0, sticky="w")
        self.e = ttk.Entry(frm, width=64)
        self.e.grid(row=1, column=0, sticky="ew", pady=(6,2))
        self.e.insert(0, text); self.e.select_range(0, tk.END)
        btns = ttk.Frame(frm); btns.grid(row=2, column=0, sticky="e", pady=(8,0))
        ttk.Button(btns, text="Copy", command=self.copy).grid(row=0, column=0, padx=(0,6))
        ttk.Button(btns, text="Close", command=self.destroy).grid(row=0, column=1)
        frm.columnconfigure(0, weight=1)
        self.bind("<Return>", lambda _e: self.copy())
    def copy(self):
        self.clipboard_clear(); self.clipboard_append(self.e.get()); self.update()

class PasswordDialog(tk.Toplevel):
    def __init__(self, master, title="Enter password"):
        super().__init__(master)
        self.title(title); self.configure(bg="#101216"); self.resizable(False, False)
        self.transient(master); self.grab_set()
        frm = ttk.Frame(self, padding=12); frm.grid(sticky="nsew")
        ttk.Label(frm, text="Password").grid(row=0, column=0, sticky="w")
        self.var = tk.StringVar(master=self)
        self.ent = ttk.Entry(frm, textvariable=self.var, show="•", width=32)
        self.ent.grid(row=1, column=0, sticky="ew", pady=(6,0))
        self.show = tk.BooleanVar(master=self, value=False)
        ttk.Checkbutton(frm, text="Show", variable=self.show, command=self.toggle).grid(row=2, column=0, sticky="w", pady=(6,0))
        btns = ttk.Frame(frm); btns.grid(row=3, column=0, sticky="e", pady=(10,0))
        ttk.Button(btns, text="OK", command=self.ok).grid(row=0, column=0, padx=(0,6))
        ttk.Button(btns, text="Cancel", command=self.cancel).grid(row=0, column=1)
        frm.columnconfigure(0, weight=1); self.ent.focus()
        self.result = None
        self.bind("<Return>", lambda _e: self.ok()); self.bind("<Escape>", lambda _e: self.cancel())
    def toggle(self): self.ent.config(show="" if self.show.get() else "•")
    def ok(self): self.result = self.var.get(); self.destroy()
    def cancel(self): self.result = None; self.destroy()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CCCRYPT")
        self.configure(bg="#0d0f13")
        self.geometry("980x640"); self.minsize(860, 580)
        self.attributes("-topmost", True)
        self._style_dark()

        root = ttk.Frame(self, padding=10); root.grid(sticky="nsew")
        self.columnconfigure(0, weight=1); self.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1); root.rowconfigure(0, weight=1)

        nb = ttk.Notebook(root); nb.grid(sticky="nsew")
        self.gen_tab   = ttk.Frame(nb)
        self.create_tab= ttk.Frame(nb)
        self.open_tab  = ttk.Frame(nb)
        self.files_tab = ttk.Frame(nb)
        self.dec_tab   = ttk.Frame(nb)
        nb.add(self.gen_tab,    text="Password")
        nb.add(self.create_tab, text="Create Document")
        nb.add(self.open_tab,   text="Open/Edit")
        nb.add(self.files_tab,  text="Encrypt Files")
        nb.add(self.dec_tab,    text="Decrypt Files")

        self._build_gen_tab()
        self._build_create_tab()
        self._build_open_tab()
        self._build_files_tab()
        self._build_dec_tab()

        self.status = ttk.Label(root, text="Ready", anchor="w")
        self.status.grid(sticky="ew", pady=(8,0))

    def _style_dark(self):
        s = ttk.Style()
        try: s.theme_use("clam")
        except Exception: pass
        base="#0d0f13"; panel="#12151b"; panel2="#171b22"; fg="#e8e8ea"
        s.configure(".", background=base, foreground=fg, fieldbackground=panel)
        s.configure("TFrame", background=base)
        s.configure("TLabel", background=base, foreground=fg)
        s.configure("TButton", background=panel2, padding=8)
        s.map("TButton", background=[("active", "#202633")])
        s.configure("TNotebook", background=base, borderwidth=0)
        s.configure("TNotebook.Tab", background=panel, padding=(12,6))
        s.map("TNotebook.Tab", background=[("selected", panel2)])
        s.configure("TEntry", fieldbackground=panel, foreground=fg)
        s.configure("TCheckbutton", background=base, foreground=fg)
        s.configure("Horizontal.TProgressbar", troughcolor=panel, background="#2a2f38")

    def _add_scroll(self, widget):
        parent = widget.master
        y = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
        x = ttk.Scrollbar(parent, orient="horizontal", command=widget.xview)
        widget.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        info = widget.grid_info()
        row = int(info["row"])
        y.grid(row=row, column=1, sticky="ns")
        x.grid(row=row+1, column=0, sticky="ew", padx=8)
        parent.grid_columnconfigure(0, weight=1)

    # password tab
    def _build_gen_tab(self):
        f = self.gen_tab
        f.grid_columnconfigure(0, weight=1); f.grid_rowconfigure(2, weight=1)
        bar = ttk.Frame(f); bar.grid(row=0, column=0, sticky="ew", pady=(8,6), padx=8)
        ttk.Label(bar, text="Length").grid(row=0, column=0, padx=(0,6))
        self.len_var = tk.IntVar(master=self, value=32)
        ttk.Spinbox(bar, from_=8, to=512, textvariable=self.len_var, width=6).grid(row=0, column=1)
        self.uni_var = tk.BooleanVar(master=self, value=False)
        ttk.Checkbutton(bar, text="Unicode", variable=self.uni_var).grid(row=0, column=2, padx=10)
        ttk.Button(bar, text="Generate", command=self.on_gen).grid(row=0, column=3, padx=6)
        ttk.Button(bar, text="Copy", command=self.on_copy_pwd).grid(row=0, column=4, padx=6)
        ttk.Button(bar, text="Use in Create", command=self.push_to_create).grid(row=0, column=5, padx=6)
        ttk.Label(f, text="Password").grid(row=1, column=0, sticky="w", padx=8)
        self.pwd_entry = tk.Text(f, height=3, wrap="none", bg="#171b22", fg="#e8e8ea",
                                 insertbackground="#e8e8ea", relief="flat")
        self.pwd_entry.grid(row=2, column=0, sticky="nsew", padx=8)
        self._add_scroll(self.pwd_entry)
        self.entropy_lbl = ttk.Label(f, text="Entropy: –")
        self.entropy_lbl.grid(row=3, column=0, sticky="w", padx=8, pady=(6,8))

    # document tab
    def _build_create_tab(self):
        f = self.create_tab
        for i in range(3): f.grid_rowconfigure(i, weight=0)
        f.grid_rowconfigure(3, weight=1); f.grid_columnconfigure(0, weight=1)
        top = ttk.Frame(f); top.grid(row=0, column=0, sticky="ew", padx=8, pady=(8,6))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Output").grid(row=0, column=0, sticky="w")
        self.out_var = tk.StringVar(master=self)
        ttk.Entry(top, textvariable=self.out_var).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="Browse", command=self.browse_save).grid(row=0, column=2)
        pwf = ttk.Frame(f); pwf.grid(row=1, column=0, sticky="ew", padx=8, pady=6)
        self.auto_var = tk.BooleanVar(master=self, value=True)
        ttk.Checkbutton(pwf, text="Auto password", variable=self.auto_var, command=self.toggle_pw_fields).grid(row=0, column=0)
        self.ap_len = tk.IntVar(master=self, value=32)
        self.ap_uni = tk.BooleanVar(master=self, value=False)
        ttk.Spinbox(pwf, from_=8, to=512, textvariable=self.ap_len, width=6).grid(row=0, column=1, padx=(10,6))
        ttk.Checkbutton(pwf, text="Unicode", variable=self.ap_uni).grid(row=0, column=2, padx=(0,10))
        ttk.Label(pwf, text="Manual:").grid(row=0, column=3)
        self.pw_var = tk.StringVar(master=self)
        self.pw_entry = ttk.Entry(pwf, textvariable=self.pw_var, show="•", width=28)
        self.pw_entry.grid(row=0, column=4, padx=6)
        self.show_var = tk.BooleanVar(master=self, value=False)
        ttk.Checkbutton(pwf, text="Show", variable=self.show_var, command=self.toggle_show).grid(row=0, column=5)
        ttk.Button(pwf, text="Pull from Password tab", command=self.pull_pwd_from_tab).grid(row=0, column=6, padx=8)
        ttk.Label(f, text="Content").grid(row=2, column=0, sticky="w", padx=8)
        self.content_txt = tk.Text(f, wrap="word", bg="#171b22", fg="#e8e8ea",
                                   insertbackground="#e8e8ea", relief="flat")
        self.content_txt.grid(row=3, column=0, sticky="nsew", padx=8)
        self._add_scroll(self.content_txt)
        btn = ttk.Frame(f); btn.grid(row=4, column=0, sticky="e", padx=8, pady=8)
        ttk.Button(btn, text="Save .cc", command=self.save_cc).grid(row=0, column=0)
        self.toggle_pw_fields()

    # document tab 2
    def _build_open_tab(self):
        f = self.open_tab
        f.grid_columnconfigure(0, weight=1); f.grid_rowconfigure(2, weight=1)
        bar = ttk.Frame(f); bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8,6))
        ttk.Button(bar, text="Open .cc", command=self.open_cc).grid(row=0, column=0, padx=(0,6))
        ttk.Button(bar, text="Save", command=self.save_opened).grid(row=0, column=1, padx=6)
        ttk.Button(bar, text="Save As", command=self.save_opened_as).grid(row=0, column=2, padx=6)
        ttk.Label(f, text="Content").grid(row=1, column=0, sticky="w", padx=8)
        self.open_txt = tk.Text(f, wrap="word", bg="#171b22", fg="#e8e8ea",
                                insertbackground="#e8e8ea", relief="flat")
        self.open_txt.grid(row=2, column=0, sticky="nsew", padx=8)
        self._add_scroll(self.open_txt)
        self.current_open_path = None; self.current_open_password = None

    # file encrypt tab
    def _build_files_tab(self):
        f = self.files_tab
        f.grid_columnconfigure(1, weight=1); f.grid_rowconfigure(6, weight=1)

        ttk.Label(f, text="Source:").grid(row=0, column=0, sticky="w", padx=8, pady=(10,4))
        src_row = ttk.Frame(f); src_row.grid(row=0, column=1, sticky="ew", padx=8, pady=(10,4))
        src_row.columnconfigure(1, weight=1)
        self.src_mode = tk.StringVar(master=self, value="file")
        ttk.Radiobutton(src_row, text="Single file", value="file", variable=self.src_mode).grid(row=0, column=0, padx=(0,8))
        ttk.Radiobutton(src_row, text="Directory (recursive)", value="dir", variable=self.src_mode).grid(row=0, column=1, sticky="w")

        ttk.Label(f, text="Path").grid(row=1, column=0, sticky="w", padx=8)
        pick = ttk.Frame(f); pick.grid(row=1, column=1, sticky="ew", padx=8)
        pick.columnconfigure(0, weight=1)
        self.src_path = tk.StringVar(master=self)
        ttk.Entry(pick, textvariable=self.src_path).grid(row=0, column=0, sticky="ew")
        ttk.Button(pick, text="Browse", command=self.browse_src).grid(row=0, column=1, padx=(6,0))

        ttk.Label(f, text="Output folder").grid(row=2, column=0, sticky="w", padx=8, pady=(6,0))
        outp = ttk.Frame(f); outp.grid(row=2, column=1, sticky="ew", padx=8, pady=(6,0))
        outp.columnconfigure(0, weight=1)
        self.dst_root = tk.StringVar(master=self)
        ttk.Entry(outp, textvariable=self.dst_root).grid(row=0, column=0, sticky="ew")
        ttk.Button(outp, text="Browse", command=self.browse_dst).grid(row=0, column=1, padx=(6,0))

        pwf = ttk.Frame(f); pwf.grid(row=3, column=0, columnspan=2, sticky="ew", padx=8, pady=8)
        self.auto_files = tk.BooleanVar(master=self, value=True)
        ttk.Checkbutton(pwf, text="Auto password", variable=self.auto_files, command=self.toggle_files_pw).grid(row=0, column=0, padx=(0,10))
        self.files_len = tk.IntVar(master=self, value=32)
        self.files_unicode = tk.BooleanVar(master=self, value=False)
        ttk.Spinbox(pwf, from_=8, to=512, textvariable=self.files_len, width=6).grid(row=0, column=1)
        ttk.Checkbutton(pwf, text="Unicode", variable=self.files_unicode).grid(row=0, column=2, padx=(8,12))
        ttk.Label(pwf, text="Manual:").grid(row=0, column=3)
        self.files_pw = tk.StringVar(master=self)
        self.files_pw_entry = ttk.Entry(pwf, textvariable=self.files_pw, show="•", width=28)
        self.files_pw_entry.grid(row=0, column=4, padx=(6,6))
        self.files_show = tk.BooleanVar(master=self, value=False)
        ttk.Checkbutton(pwf, text="Show", variable=self.files_show, command=self.toggle_files_show).grid(row=0, column=5)

        prog = ttk.Frame(f); prog.grid(row=4, column=0, columnspan=2, sticky="ew", padx=8, pady=6)
        prog.columnconfigure(0, weight=1)
        self.progbar = ttk.Progressbar(prog, mode="determinate", maximum=100)
        self.progbar.grid(row=0, column=0, sticky="ew")
        self.prog_label = ttk.Label(prog, text="No job")
        self.prog_label.grid(row=0, column=1, padx=(8,0))

        ttk.Label(f, text="Log").grid(row=5, column=0, sticky="w", padx=8)
        self.log = tk.Text(f, height=8, wrap="none", bg="#171b22", fg="#e8e8ea", insertbackground="#e8e8ea", relief="flat")
        self.log.grid(row=6, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0,8))
        self._add_scroll(self.log)

        btns = ttk.Frame(f); btns.grid(row=7, column=0, columnspan=2, sticky="e", padx=8, pady=8)
        ttk.Button(btns, text="Start Encryption", command=self.start_files_encrypt).grid(row=0, column=0)

        self.toggle_files_pw()

    # file decrypt tab
    def _build_dec_tab(self):
        f = self.dec_tab
        f.grid_columnconfigure(1, weight=1); f.grid_rowconfigure(6, weight=1)

        ttk.Label(f, text="Source:").grid(row=0, column=0, sticky="w", padx=8, pady=(10,4))
        src_row = ttk.Frame(f); src_row.grid(row=0, column=1, sticky="ew", padx=8, pady=(10,4))
        src_row.columnconfigure(1, weight=1)
        self.dsrc_mode = tk.StringVar(master=self, value="file")
        ttk.Radiobutton(src_row, text="Single .cc file", value="file", variable=self.dsrc_mode).grid(row=0, column=0, padx=(0,8))
        ttk.Radiobutton(src_row, text=".cc Directory (recursive)", value="dir", variable=self.dsrc_mode).grid(row=0, column=1, sticky="w")

        ttk.Label(f, text="Path").grid(row=1, column=0, sticky="w", padx=8)
        pick = ttk.Frame(f); pick.grid(row=1, column=1, sticky="ew", padx=8)
        pick.columnconfigure(0, weight=1)
        self.dsrc_path = tk.StringVar(master=self)
        ttk.Entry(pick, textvariable=self.dsrc_path).grid(row=0, column=0, sticky="ew")
        ttk.Button(pick, text="Browse", command=self.dbrowse_src).grid(row=0, column=1, padx=(6,0))

        ttk.Label(f, text="Output folder").grid(row=2, column=0, sticky="w", padx=8, pady=(6,0))
        outp = ttk.Frame(f); outp.grid(row=2, column=1, sticky="ew", padx=8, pady=(6,0))
        outp.columnconfigure(0, weight=1)
        self.ddst_root = tk.StringVar(master=self)
        ttk.Entry(outp, textvariable=self.ddst_root).grid(row=0, column=0, sticky="ew")
        ttk.Button(outp, text="Browse", command=self.dbrowse_dst).grid(row=0, column=1, padx=(6,0))

        pwf = ttk.Frame(f); pwf.grid(row=3, column=0, columnspan=2, sticky="ew", padx=8, pady=8)
        ttk.Label(pwf, text="Password").grid(row=0, column=0, padx=(0,10))
        self.dpw = tk.StringVar(master=self)
        self.dpw_entry = ttk.Entry(pwf, textvariable=self.dpw, show="•", width=28)
        self.dpw_entry.grid(row=0, column=1)
        self.dshow = tk.BooleanVar(master=self, value=False)
        ttk.Checkbutton(pwf, text="Show", variable=self.dshow, command=lambda: self.dpw_entry.config(show="" if self.dshow.get() else "•")).grid(row=0, column=2, padx=(10,0))

        prog = ttk.Frame(f); prog.grid(row=4, column=0, columnspan=2, sticky="ew", padx=8, pady=6)
        prog.columnconfigure(0, weight=1)
        self.dbar = ttk.Progressbar(prog, mode="determinate", maximum=100)
        self.dbar.grid(row=0, column=0, sticky="ew")
        self.dlabel = ttk.Label(prog, text="No job")
        self.dlabel.grid(row=0, column=1, padx=(8,0))

        ttk.Label(f, text="Log").grid(row=5, column=0, sticky="w", padx=8)
        self.dlog = tk.Text(f, height=8, wrap="none", bg="#171b22", fg="#e8e8ea", insertbackground="#e8e8ea", relief="flat")
        self.dlog.grid(row=6, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0,8))
        self._add_scroll(self.dlog)

        btns = ttk.Frame(f); btns.grid(row=7, column=0, columnspan=2, sticky="e", padx=8, pady=8)
        ttk.Button(btns, text="Start Decryption", command=self.start_files_decrypt).grid(row=0, column=0)

    # helpers
    def _unique_path(self, base_path):
        if not os.path.exists(base_path): return base_path
        root, ext = os.path.splitext(base_path)
        i = 1
        while True:
            cand = f"{root}_{i}{ext}"
            if not os.path.exists(cand): return cand
            i += 1

    def _collect_files(self, src):
        if os.path.isfile(src):
            return [src]
        hits = []
        for dp, _dirs, files in os.walk(src):
            for fn in files:
                hits.append(os.path.join(dp, fn))
        return hits

    def _log(self, widget, line):
        widget.insert("end", line + "\n"); widget.see("end")

    # tab actions
    def on_gen(self):
        try:
            pwd, H = gen_password(self.len_var.get(), self.uni_var.get())
        except Exception as e:
            messagebox.showerror("Error", str(e)); return
        self.pwd_entry.delete("1.0","end"); self.pwd_entry.insert("1.0", pwd)
        self.entropy_lbl.config(text=f"Entropy ≈ {H:.2f} bits")
        self.clipboard_clear(); self.clipboard_append(pwd)
        self.status.config(text="Generated + copied")

    def on_copy_pwd(self):
        pwd = self.pwd_entry.get("1.0","end-1c")
        if pwd:
            self.clipboard_clear(); self.clipboard_append(pwd)
            self.status.config(text="Copied")

    def push_to_create(self):
        p = self.pwd_entry.get("1.0","end-1c")
        if not p: return
        self.auto_var.set(False); self.toggle_pw_fields(); self.pw_var.set(p)
        self.status.config(text="Password loaded into Create")

    # create tab actions
    def toggle_show(self): self.pw_entry.config(show="" if self.show_var.get() else "•")
    def toggle_pw_fields(self):
        st = "disabled" if self.auto_var.get() else "normal"
        self.pw_entry.config(state=st)
    def pull_pwd_from_tab(self):
        p = self.pwd_entry.get("1.0","end-1c")
        if not p: messagebox.showinfo("Info","Generate a password first."); return
        self.auto_var.set(False); self.toggle_pw_fields(); self.pw_var.set(p)
    def browse_save(self):
        path = filedialog.asksaveasfilename(defaultextension=".cc", filetypes=[("CC files","*.cc")])
        if path: self.out_var.set(path)
    def save_cc(self):
        path = self.out_var.get().strip()
        if not path: messagebox.showerror("Error","Choose an output file."); return
        if not path.lower().endswith(".cc"): path += ".cc"
        if self.auto_var.get():
            try: pwd, _ = gen_password(self.ap_len.get(), self.ap_uni.get())
            except Exception as e: messagebox.showerror("Error", str(e)); return
            final_pwd = pwd
            CopyDialog(self, "Auto password", pwd).wait_window()
        else:
            final_pwd = self.pw_var.get()
            if len(final_pwd) < 8: messagebox.showerror("Error","Password too short."); return
        try:
            write_cc_text(path, self.content_txt.get("1.0","end-1c"), final_pwd)
        except Exception as e:
            messagebox.showerror("Error", str(e)); return
        messagebox.showinfo("Saved", f"Saved: {path}")
        self.status.config(text=f"Saved {os.path.basename(path)}")

    def open_cc(self):
        path = filedialog.askopenfilename(filetypes=[("CC files","*.cc"),("All files","*.*")])
        if not path: return
        dlg = PasswordDialog(self); dlg.wait_window()
        pw = dlg.result
        if pw is None: return
        try:
            plain = read_cc_text(path, pw)
        except Exception as e:
            messagebox.showerror("Decryption failed", str(e)); return
        self.current_open_path = path; self.current_open_password = pw
        self.open_txt.delete("1.0","end"); self.open_txt.insert("1.0", plain)
        self.title(f"CC Security — {os.path.basename(path)}")
        self.status.config(text=f"Opened {os.path.basename(path)}")

    def save_opened(self):
        if not self.current_open_path or not self.current_open_password:
            messagebox.showinfo("Info","Open a .cc file first."); return
        try:
            write_cc_text(self.current_open_path, self.open_txt.get("1.0","end-1c"), self.current_open_password)
        except Exception as e:
            messagebox.showerror("Error", str(e)); return
        self.status.config(text="Updated file"); messagebox.showinfo("Saved","Updated.")

    def save_opened_as(self):
        if not self.current_open_password:
            messagebox.showinfo("Info","Open a .cc file first."); return
        path = filedialog.asksaveasfilename(defaultextension=".cc", filetypes=[("CC files","*.cc")])
        if not path: return
        try:
            write_cc_text(path, self.open_txt.get("1.0","end-1c"), self.current_open_password)
        except Exception as e:
            messagebox.showerror("Error", str(e)); return
        self.current_open_path = path; self.status.config(text=f"Saved as {os.path.basename(path)}")

    def toggle_files_pw(self):
        st = "disabled" if self.auto_files.get() else "normal"
        self.files_pw_entry.config(state=st)
    def toggle_files_show(self):
        self.files_pw_entry.config(show="" if self.files_show.get() else "•")
    def browse_src(self):
        if self.src_mode.get() == "file":
            p = filedialog.askopenfilename()
        else:
            p = filedialog.askdirectory()
        if p: self.src_path.set(p)
    def browse_dst(self):
        p = filedialog.askdirectory()
        if p: self.dst_root.set(p)
    def start_files_encrypt(self):
        src = self.src_path.get().strip()
        dst_root = self.dst_root.get().strip()
        if not src or not os.path.exists(src):
            messagebox.showerror("Error", "Select a valid source."); return
        if not dst_root:
            messagebox.showerror("Error", "Select an output folder."); return
        try: os.makedirs(dst_root, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Output not writable:\n{e}"); return
        if self.auto_files.get():
            try: pwd, _ = gen_password(self.files_len.get(), self.files_unicode.get())
            except Exception as e: messagebox.showerror("Error", str(e)); return
            CopyDialog(self, "Encryption password (files)", pwd).wait_window()
            password = pwd
        else:
            password = self.files_pw.get()
            if len(password) < 8:
                messagebox.showerror("Error", "Password too short."); return
        files = self._collect_files(src)
        if not files: messagebox.showinfo("Info", "No files found."); return
        total = len(files); done = 0
        self.progbar["value"] = 0; self.progbar["maximum"] = total
        self.prog_label.config(text=f"0/{total}")
        self.log.delete("1.0", "end")
        src_base = os.path.dirname(src) if os.path.isfile(src) else src
        for fpath in files:
            try: rel = os.path.relpath(fpath, start=src_base)
            except Exception: rel = os.path.basename(fpath)
            out_rel = rel + ".cc"
            out_path = os.path.join(dst_root, out_rel)
            out_dir = os.path.dirname(out_path)
            try: os.makedirs(out_dir, exist_ok=True)
            except Exception as e:
                self._log(self.log, f"[skip] {rel} -> cannot create dir: {e}"); continue
            out_path = self._unique_path(out_path)
            try:
                with open(fpath, "rb") as r: data = r.read()
                write_cc_bytes(out_path, data, password)
                self._log(self.log, f"[ok] {rel} -> {os.path.relpath(out_path, dst_root)}")
            except Exception as e:
                self._log(self.log, f"[fail] {rel} -> {e}")
            done += 1
            self.progbar["value"] = done; self.prog_label.config(text=f"{done}/{total}")
            self.update_idletasks()
        self.status.config(text=f"Finished: {done}/{total}")

    def dbrowse_src(self):
        if self.dsrc_mode.get() == "file":
            p = filedialog.askopenfilename(filetypes=[("CC files","*.cc"), ("All files","*.*")])
        else:
            p = filedialog.askdirectory()
        if p: self.dsrc_path.set(p)
    def dbrowse_dst(self):
        p = filedialog.askdirectory()
        if p: self.ddst_root.set(p)
    def _collect_cc(self, src):
        if os.path.isfile(src):
            return [src]
        hits = []
        for dp, _dirs, files in os.walk(src):
            for fn in files:
                if fn.lower().endswith(".cc"):
                    hits.append(os.path.join(dp, fn))
        return hits
    def start_files_decrypt(self):
        src = self.dsrc_path.get().strip()
        dst_root = self.ddst_root.get().strip()
        password = self.dpw.get()
        if not src or not os.path.exists(src):
            messagebox.showerror("Error", "Select a valid .cc source."); return
        if not dst_root:
            messagebox.showerror("Error", "Select an output folder."); return
        if len(password) < 1:
            messagebox.showerror("Error", "Enter the password."); return
        try: os.makedirs(dst_root, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Output not writable:\n{e}"); return
        files = self._collect_cc(src)
        if not files:
            messagebox.showinfo("Info", "No .cc files found."); return
        total = len(files); done = 0
        self.dbar["value"] = 0; self.dbar["maximum"] = total
        self.dlabel.config(text=f"0/{total}")
        self.dlog.delete("1.0","end")
        src_base = os.path.dirname(src) if os.path.isfile(src) else src
        for fpath in files:
            try: rel = os.path.relpath(fpath, start=src_base)
            except Exception: rel = os.path.basename(fpath)
            if rel.lower().endswith(".cc"):
                out_rel = rel[:-3]
            else:
                out_rel = rel + ".dec"
            out_path = os.path.join(dst_root, out_rel)
            out_dir = os.path.dirname(out_path)
            try: os.makedirs(out_dir, exist_ok=True)
            except Exception as e:
                self._log(self.dlog, f"[skip] {rel} -> cannot create dir: {e}"); continue
            out_path = self._unique_path(out_path)
            try:
                data = read_cc_bytes(fpath, password)
                with open(out_path, "wb") as w: w.write(data)
                self._log(self.dlog, f"[ok] {rel} -> {os.path.relpath(out_path, dst_root)}")
            except Exception as e:
                self._log(self.dlog, f"[fail] {rel} -> {e}")
            done += 1
            self.dbar["value"] = done; self.dlabel.config(text=f"{done}/{total}")
            self.update_idletasks()
        self.status.config(text=f"Decryption finished: {done}/{total}")

if __name__ == "__main__":
    App().mainloop()
