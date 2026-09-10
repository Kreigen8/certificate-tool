import re
import hashlib
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ctypes
from ctypes import wintypes

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


from csp_report import write_csp_report
from certificate_utils import (
    DRIVE_FIXED,
    DRIVE_REMOVABLE,
    INVALID_CHARS_RE,
    STARTUP_WARNING,
    STATUS_EXPIRED,
    STATUS_NOCERT,
    STATUS_VALID,
    _SKIP_DIR_NAMES,
    build_date_suffix,
    cert_is_expired,
    fmt_date,
    format_name_variant,
    get_certificate_report_fields,
    get_cn_or_subject,
    normalize_person_name,
    now_utc,
    parse_date,
)

from file_operations import (
    _find_dir_by_name,
    build_container_path_candidates,
    build_container_zip_name,
    compact_name_for_archive,
    find_container_folder_on_removable,
    is_flash_unique_name,
    iter_drive_roots_for_container_search,
    load_cert_file,
    make_safe_name,
    safe_output_path,
    safe_rename_target,
    zip_folder_with_root,
)

from windows_crypto import (
    AT_KEYEXCHANGE,
    AT_SIGNATURE,
    CERT_CONTEXT,
    CERT_FIND_PUBLIC_KEY,
    CERT_STORE_OPEN_EXISTING_FLAG,
    CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE,
    CRYPT_ALGORITHM_IDENTIFIER,
    CRYPT_DELETEKEYSET,
    CRYPT_EXPORT,
    CRYPT_FIRST,
    CRYPT_MACHINE_KEYSET,
    CRYPT_NEXT,
    CRYPT_VERIFYCONTEXT,
    CryptAcquireContextW,
    CryptDestroyKey,
    CryptEnumProvidersW,
    CryptGetKeyParam,
    CryptGetProvParam,
    CryptGetUserKey,
    CryptReleaseContext,
    CryptSetKeyParam,
    ENCODING,
    HCERTSTORE,
    HCRYPTKEY,
    HCRYPTPROV,
    KP_CERTIFICATE,
    KP_PERMISSIONS,
    PCCERT_CONTEXT,
    PKCS_7_ASN_ENCODING,
    PP_ENUMCONTAINERS,
    PP_UNIQUE_CONTAINER,
    X509_ASN_ENCODING,
    _open_system_store,
    advapi32,
    crypt32,
    delete_container,
    delete_from_store_by_thumbprints,
    enum_csp_containers_for_provider,
    enum_csp_providers,
    find_cert_in_my_by_public_key,
    get_key_exportable,
    get_unique_container_name,
    is_user_admin,
    iter_store_der,
    set_key_exportable,
    try_get_cert_der_from_container,
)

class ToolTip:
    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip = None
        self.active = True
        widget.bind("<Enter>", self._enter, add=True)
        widget.bind("<Leave>", self._leave, add=True)
        widget.bind("<Motion>", self._motion, add=True)

    def set_active(self, active: bool):
        self.active = active
        if not active:
            self._hide()

    def _enter(self, _e=None):
        if self.active:
            self._show()

    def _leave(self, _e=None):
        self._hide()

    def _motion(self, _e=None):
        if self.tip and self.active:
            self._position()

    def _show(self):
        if self.tip or not self.text:
            return
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.attributes("-topmost", True)
        lbl = ttk.Label(self.tip, text=self.text, padding=(8, 5))
        lbl.pack()
        self._position()

    def _position(self):
        try:
            x = self.widget.winfo_pointerx() + 12
            y = self.widget.winfo_pointery() + 12
            self.tip.geometry(f"+{x}+{y}")
        except Exception:
            pass

    def _hide(self):
        if self.tip:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None


from enhanced_ui import EnhancedAppMixin


class App(EnhancedAppMixin, tk.Tk):
    def __init__(self):
        super().__init__()
        self.init_workflows()
        self.admin = is_user_admin()

        self.title("Certificate Tool — 2026.09.10.1")
        self.geometry("1500x820")
        self.minsize(1100, 650)

        self.status_var = tk.StringVar(value="Готово.")

        # data caches for filtering
        self.files_rows = []
        self.store_rows = []
        self.csp_rows = []

        # sort states
        self.sort_state_files = {}
        self.sort_state_store = {}
        self.sort_state_csp = {}

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_files = ttk.Frame(nb)
        self.tab_store = ttk.Frame(nb)
        self.tab_csp = ttk.Frame(nb)

        nb.add(self.tab_files, text="Файлы сертификатов")
        nb.add(self.tab_store, text="Реестр (хранилища Windows)")
        nb.add(self.tab_csp, text="Контейнеры ЭЦП (CSP)")

        self._build_files_tab()
        self._build_store_tab()
        self._build_csp_tab()

        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(10, 6)).pack(fill="x", side="bottom")

        self.build_job_bar()

        self._startup_warning_id = self.after(150, lambda: messagebox.showwarning("Внимание", STARTUP_WARNING))

    # -------------------------
    # Sorting helper
    # -------------------------
    def _sort_tree(self, tree: ttk.Treeview, col: str, sort_state: dict, col_types: dict):
        reverse = sort_state.get(col, False)
        items = list(tree.get_children(""))

        def key_func(item_id):
            v = tree.set(item_id, col)
            typ = col_types.get(col, "str")
            if typ == "int":
                try:
                    return (0, int(v))
                except (ValueError, TypeError):
                    return (1, 0)
            if typ == "date":
                d = parse_date(v)
                return d or datetime.min
            return (v or "").lower()

        items.sort(key=key_func, reverse=reverse)
        for idx, iid in enumerate(items):
            tree.move(iid, "", idx)
        sort_state[col] = not reverse
        if tree is self.tree_csp:
            self._csp_sort = (col, reverse)

    # =========================
    # TAB: Files
    # =========================
    def _build_files_tab(self):
        top = ttk.Frame(self.tab_files, padding=10)
        top.pack(fill="x")

        self.path_var = tk.StringVar(value=str(Path(".").resolve()))
        self.recurse_var = tk.BooleanVar(value=True)

        ttk.Label(top, text="Папка:").pack(side="left")
        ttk.Entry(top, textvariable=self.path_var, width=70).pack(side="left", padx=6)
        ttk.Button(top, text="Выбрать...", command=self._pick_folder).pack(side="left", padx=6)
        ttk.Checkbutton(top, text="С подпапками", variable=self.recurse_var).pack(side="left", padx=10)

        # Search
        search = ttk.Frame(self.tab_files, padding=(10, 0, 10, 10))
        search.pack(fill="x")
        ttk.Label(search, text="Поиск по CN:").pack(side="left")
        self.search_files_var = tk.StringVar(value="")
        ttk.Entry(search, textvariable=self.search_files_var, width=40).pack(side="left", padx=8)
        ttk.Button(search, text="Сброс", command=lambda: self.search_files_var.set("")).pack(side="left")
        self.search_files_var.trace_add("write", lambda *_: self._render_files_filtered())

        # Rename options
        opt = ttk.LabelFrame(self.tab_files, text="Переименование", padding=(10, 8))
        opt.pack(fill="x", padx=10, pady=(0, 10))

        self.name_mode_var = tk.StringVar(value="fio")
        self.date_mode_var = tk.StringVar(value="end")

        row1 = ttk.Frame(opt)
        row1.pack(fill="x", pady=(0, 6))
        ttk.Label(row1, text="Имя:").pack(side="left")
        ttk.Radiobutton(row1, text="Фамилия Имя Отчество", value="fio", variable=self.name_mode_var).pack(side="left", padx=10)
        ttk.Radiobutton(row1, text="Фамилия И.О.", value="fio_short", variable=self.name_mode_var).pack(side="left", padx=10)

        row2 = ttk.Frame(opt)
        row2.pack(fill="x")
        ttk.Label(row2, text="Дата:").pack(side="left")
        ttk.Radiobutton(row2, text="Без даты", value="none", variable=self.date_mode_var).pack(side="left", padx=10)
        ttk.Radiobutton(row2, text="Окончание срока действия", value="end", variable=self.date_mode_var).pack(side="left", padx=10)
        ttk.Radiobutton(row2, text="Начало и конец срока действия", value="start_end", variable=self.date_mode_var).pack(side="left", padx=10)

        # Buttons
        btns = ttk.Frame(self.tab_files, padding=(10, 0, 10, 10))
        btns.pack(fill="x")
        ttk.Button(btns, text="Показать файлы", command=self.files_show).pack(side="left")
        ttk.Button(btns, text="Переименовать по шаблону", command=self.files_rename).pack(side="left", padx=10)
        ttk.Button(btns, text="Удалить просроченные файлы", command=self.files_delete_expired).pack(side="left")

        # Tree
        cols = ("name", "start", "end", "status", "path")
        tree_frame = ttk.Frame(self.tab_files)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tree_files = ttk.Treeview(tree_frame, columns=cols, show="headings")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_files.yview)
        self.tree_files.configure(yscrollcommand=vsb.set)

        self.tree_files.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree_files.tag_configure("expired", foreground="red")

        headers = {"name": "Имя (CN)", "start": "Начало", "end": "Окончание", "status": "Статус", "path": "Файл"}
        self.files_col_types = {"name": "str", "start": "date", "end": "date", "status": "str", "path": "str"}

        for c in cols:
            self.tree_files.heading(c, text=headers[c], command=lambda col=c: self._sort_tree(self.tree_files, col, self.sort_state_files, self.files_col_types))
            w = 220 if c != "path" else 760
            self.tree_files.column(c, width=w, anchor="w")

    def _pick_folder(self):
        p = filedialog.askdirectory(initialdir=self.path_var.get() or str(Path(".").resolve()))
        if p:
            self.path_var.set(p)

    def _clear_tree(self, tree: ttk.Treeview):
        for i in tree.get_children():
            tree.delete(i)


    def _render_files_filtered(self):
        q = (self.search_files_var.get() or "").strip().lower()
        self._clear_tree(self.tree_files)

        total = len([r for r in self.files_rows if not r.get("is_error")])
        total_expired = len([r for r in self.files_rows if r.get("is_expired") and not r.get("is_error")])

        shown = 0
        expired_shown = 0

        for r in self.files_rows:
            if q and q not in (r.get("name") or "").lower():
                continue
            tags = ("expired",) if r.get("is_expired") else ()
            self.tree_files.insert("", "end", values=(r["name"], r["start"], r["end"], r["status"], r["path"]), tags=tags)
            shown += 1
            if r.get("is_expired"):
                expired_shown += 1

        if self.files_rows and q:
            self.status_var.set(f"Файлы: показано {shown} из {total}, просроченных показано {expired_shown} из {total_expired}.")

    def files_rename(self):
        if self._busy:
            return
        if not self.files_rows:
            messagebox.showinfo("Файлы", "Сначала загрузите список файлов.", parent=self)
            return

        name_mode = self.name_mode_var.get()
        date_mode = self.date_mode_var.get()

        renamed = 0
        errors = 0

        for r in self.files_rows:
            if r.get("is_error"):
                continue
            p = Path(r["path"])
            if not p.exists() or not p.is_file():
                continue

            base_name = make_safe_name(format_name_variant(str(r["name"]), name_mode))
            date_suffix = build_date_suffix(date_mode, str(r["start"]), str(r["end"]))
            new_stem = f"{base_name} - {date_suffix}" if date_suffix else base_name

            target = safe_rename_target(p, new_stem)
            if target == p:
                continue

            try:
                p.rename(target)
                renamed += 1
            except Exception:
                errors += 1

        self.files_show()
        self.status_var.set(f"Файлы: переименовано {renamed}, ошибок {errors}.")

    def files_delete_expired(self):
        if self._busy:
            return
        if not self.files_rows:
            messagebox.showinfo("Файлы", "Сначала загрузите список файлов.", parent=self)
            return

        expired_files = [r for r in self.files_rows if r.get("is_expired") and not r.get("is_error")]
        if not expired_files:
            messagebox.showinfo("Готово", "Просроченных файлов не найдено.")
            return

        if not messagebox.askyesno("Подтверждение", f"Удалить просроченные файлы сертификатов: {len(expired_files)} шт.?"):
            return

        deleted = 0
        errors = 0
        for r in expired_files:
            try:
                p = Path(r["path"])
                if p.exists():
                    p.unlink()
                    deleted += 1
            except Exception:
                errors += 1

        self.files_show()
        self.status_var.set(f"Файлы: удалено {deleted}, ошибок {errors}.")

    # =========================
    # TAB: Windows store (registry)
    # =========================
    def _build_store_tab(self):
        top = ttk.Frame(self.tab_store, padding=10)
        top.pack(fill="x")

        self.store_current_user_var = tk.BooleanVar(value=True)
        self.store_local_machine_var = tk.BooleanVar(value=False)
        self.store_my_var = tk.BooleanVar(value=True)
        self.store_ca_var = tk.BooleanVar(value=False)
        self.store_root_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(top, text="CurrentUser", variable=self.store_current_user_var).pack(side="left")

        self.cb_lm = ttk.Checkbutton(top, text="LocalMachine", variable=self.store_local_machine_var)
        self.cb_lm.pack(side="left", padx=10)
        self.tt_lm = ToolTip(self.cb_lm, "Перезапустите утилиту от имени администратора")
        if not self.admin:
            self.cb_lm.state(["disabled"])
            self.store_local_machine_var.set(False)
            self.tt_lm.set_active(True)
        else:
            self.tt_lm.set_active(False)

        ttk.Checkbutton(top, text="MY", variable=self.store_my_var).pack(side="left", padx=10)
        ttk.Checkbutton(top, text="CA", variable=self.store_ca_var).pack(side="left", padx=10)
        ttk.Checkbutton(top, text="ROOT", variable=self.store_root_var).pack(side="left", padx=10)

        ttk.Button(top, text="Показать сертификаты", command=self.store_show).pack(side="left", padx=20)
        ttk.Button(top, text="Удалить просроченные", command=self.store_delete_expired).pack(side="left")

        # Search
        search = ttk.Frame(self.tab_store, padding=(10, 0, 10, 10))
        search.pack(fill="x")
        ttk.Label(search, text="Поиск по CN:").pack(side="left")
        self.search_store_var = tk.StringVar(value="")
        ttk.Entry(search, textvariable=self.search_store_var, width=40).pack(side="left", padx=8)
        ttk.Button(search, text="Сброс", command=lambda: self.search_store_var.set("")).pack(side="left")
        self.search_store_var.trace_add("write", lambda *_: self._render_store_filtered())

        cols = ("where", "name", "start", "end", "status")
        tree_frame = ttk.Frame(self.tab_store)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tree_store = ttk.Treeview(tree_frame, columns=cols, show="headings")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_store.yview)
        self.tree_store.configure(yscrollcommand=vsb.set)

        self.tree_store.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree_store.tag_configure("expired", foreground="red")

        headers = {"where": "Где", "name": "Имя (CN)", "start": "Начало", "end": "Окончание", "status": "Статус"}
        self.store_col_types = {"where": "str", "name": "str", "start": "date", "end": "date", "status": "str"}

        for c in cols:
            self.tree_store.heading(c, text=headers[c], command=lambda col=c: self._sort_tree(self.tree_store, col, self.sort_state_store, self.store_col_types))
            w = 300 if c == "where" else 260
            if c == "name":
                w = 700
            self.tree_store.column(c, width=w, anchor="w")

    def _get_selected_store_scopes_and_stores(self):
        stores = []
        if self.store_my_var.get():
            stores.append("MY")
        if self.store_ca_var.get():
            stores.append("CA")
        if self.store_root_var.get():
            stores.append("ROOT")

        scopes = []
        if self.store_current_user_var.get():
            scopes.append(("CurrentUser", CERT_SYSTEM_STORE_CURRENT_USER))
        if self.admin and self.store_local_machine_var.get():
            scopes.append(("LocalMachine", CERT_SYSTEM_STORE_LOCAL_MACHINE))
        return scopes, stores


    def _render_store_filtered(self):
        q = (self.search_store_var.get() or "").strip().lower()
        self._clear_tree(self.tree_store)

        total = len([r for r in self.store_rows if not r.get("is_error")])
        total_expired = len([r for r in self.store_rows if r.get("is_expired") and not r.get("is_error")])

        shown = 0
        expired_shown = 0

        for r in self.store_rows:
            if q and q not in (r.get("name") or "").lower():
                continue
            tags = ("expired",) if r.get("is_expired") else ()
            self.tree_store.insert("", "end", values=(r["where"], r["name"], r["start"], r["end"], r["status"]), tags=tags)
            shown += 1
            if r.get("is_expired"):
                expired_shown += 1

        if self.store_rows and q:
            self.status_var.set(f"Реестр: показано {shown} из {total}, просроченных показано {expired_shown} из {total_expired}.")

    def store_delete_expired(self):
        if self._busy:
            return
        scopes, stores = self._get_selected_store_scopes_and_stores()
        if not scopes:
            messagebox.showinfo("Опции", "Выбери хотя бы CurrentUser (или запусти от администратора для LocalMachine).")
            return
        if not stores:
            messagebox.showinfo("Опции", "Выбери хотя бы один стор: MY/CA/ROOT.")
            return

        if not messagebox.askyesno("Подтверждение", "Удалить все просроченные сертификаты из выбранных хранилищ Windows?"):
            return

        dt = now_utc()
        total_deleted = 0
        total_errors = 0
        total_expired_found = 0

        for scope_label, scope_flag in scopes:
            for store_name in stores:
                thumbs = set()
                try:
                    for der in iter_store_der(store_name, scope_flag):
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        na = cert.not_valid_after
                        if na.tzinfo is None:
                            na = na.replace(tzinfo=timezone.utc)
                        if na < dt:
                            thumbs.add(hashlib.sha1(der).hexdigest().upper())
                    total_expired_found += len(thumbs)
                    if thumbs:
                        d, e = delete_from_store_by_thumbprints(store_name, scope_flag, thumbs)
                        total_deleted += d
                        total_errors += e
                except Exception:
                    total_errors += 1

        self.store_show()
        self.status_var.set(f"Реестр: найдено просроченных {total_expired_found}, удалено {total_deleted}, ошибок {total_errors}.")

    # =========================
    # TAB: CSP Containers (SMART)
    # =========================
    def _build_csp_tab(self):
        top = ttk.Frame(self.tab_csp, padding=10)
        top.pack(fill="x")

        self.csp_scope_user_var = tk.BooleanVar(value=True)
        self.csp_scope_machine_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(top, text="CurrentUser", variable=self.csp_scope_user_var).pack(side="left")

        self.cb_csp_lm = ttk.Checkbutton(top, text="LocalMachine", variable=self.csp_scope_machine_var)
        self.cb_csp_lm.pack(side="left", padx=10)

        self.tt_csp_lm = ToolTip(self.cb_csp_lm, "Перезапустите утилиту от имени администратора")
        if not self.admin:
            self.cb_csp_lm.state(["disabled"])
            self.csp_scope_machine_var.set(False)
            self.tt_csp_lm.set_active(True)
        else:
            self.tt_csp_lm.set_active(False)

        ttk.Button(top, text="Показать контейнеры", command=self.csp_show).pack(side="left", padx=20)
        ttk.Button(top, text="Удалить просроченные", command=self.csp_delete_expired).pack(side="left")
        ttk.Button(top, text="Удалить выбранные", command=self.csp_delete_selected).pack(side="left", padx=10)

        self.csp_show_nocert_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Показывать без сертификата", variable=self.csp_show_nocert_var).pack(side="left", padx=10)


        # Search (by CN and container)
        search = ttk.Frame(self.tab_csp, padding=(10, 0, 10, 10))
        search.pack(fill="x")
        ttk.Label(search, text="Поиск (ФИО, учреждение, должность, контейнер):").pack(side="left")
        self.search_csp_var = tk.StringVar(value="")
        ttk.Entry(search, textvariable=self.search_csp_var, width=36).pack(side="left", padx=8)
        ttk.Button(search, text="Сброс", command=lambda: self.search_csp_var.set("")).pack(side="left")
        self.csp_report_button = ttk.Button(search, text="Отчет", command=self.csp_report)
        self.csp_report_button.pack(side="left", padx=20)
        ToolTip(self.csp_report_button, "Сохранить XLSX по показанным контейнерам с сертификатами. Срок — дата окончания.")
        self.csp_show_nocert_var.trace_add("write", lambda *_: self._render_csp_filtered())
        self.search_csp_var.trace_add("write", lambda *_: self._render_csp_filtered())

        cols = ("scope", "provider", "container", "unique", "cn", "organization", "position", "serial", "thumb", "export", "cert_in", "start", "end", "days_left", "status", "error")
        tree_frame = ttk.Frame(self.tab_csp)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tree_csp = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="extended")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_csp.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree_csp.xview)
        self.tree_csp.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree_csp.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.tree_csp.tag_configure("expired", foreground="red")
        self.tree_csp.tag_configure("nocert", foreground="gray")
        self.tree_csp.tag_configure("error", foreground="#9C2700")
        self.tree_csp.tag_configure("soon", background="#FFF1CC")
        self.tree_csp.tag_configure("future", foreground="#5555AA")
        self.tree_csp.bind("<Double-1>", self._csp_details)



        # Context menu
        self.csp_menu = tk.Menu(self, tearoff=0)
        self.csp_menu.add_command(label="Копировать серийный номер", command=lambda: self._csp_copy_field("serial"))
        self.csp_menu.add_command(label="Копировать отпечаток", command=lambda: self._csp_copy_field("thumb"))
        self.csp_menu.add_separator()
        self.csp_menu.add_command(label="Сжать контейнер в ZIP", command=self._csp_zip_selected_container)
        self.csp_menu.add_separator()
        self.csp_menu.add_command(label="Сделать контейнер экспортируемым", command=self._csp_make_exportable)

        self.tree_csp.bind("<Button-3>", self._csp_on_right_click, add=True)

        headers = {
            "scope": "Область",
            "organization": "Учреждение",
            "position": "Должность",
            "days_left": "Осталось дней",
            "error": "Ошибка / предупреждение",
            "provider": "Провайдер",
            "container": "Контейнер",
            "unique": "Уникальное имя",
            "cn": "Владелец (CN)",
            "serial": "Серийный номер",
            "thumb": "Отпечаток",
            "export": "Экспорт закрытого ключа",
            "cert_in": "Серт. в контейнере",
            "start": "Начало",
            "end": "Окончание",
            "status": "Статус",
        }

        self.csp_col_types = {"scope": "str", "provider": "str", "container": "str", "unique": "str", "cn": "str", "serial": "str", "thumb": "str", "export": "str", "cert_in": "str", "start": "date", "end": "date", "status": "str"}

        self.csp_col_types.update(organization="str", position="str", days_left="int", error="str")

        for c in cols:
            self.tree_csp.heading(c, text=headers[c], command=lambda col=c: self._sort_tree(self.tree_csp, col, self.sort_state_csp, self.csp_col_types))
            w = 100
            if c == "provider":
                w = 100
            if c == "container":
                w = 320
            if c == "unique":
                w = 300
            if c in ("cn", "organization", "position", "error"):
                w = 300
            if c == "serial":
                w = 150
            if c == "thumb":
                w = 150
            if c in ("export", "cert_in"):
                w = 50
            if c in ("start", "end"):
                w = 80
            self.tree_csp.column(c, width=w, anchor="w", stretch=False)

    def _get_csp_scopes(self):
        scopes = []
        if self.csp_scope_user_var.get():
            scopes.append(("CurrentUser", False, CERT_SYSTEM_STORE_CURRENT_USER))
        if self.admin and self.csp_scope_machine_var.get():
            scopes.append(("LocalMachine", True, CERT_SYSTEM_STORE_LOCAL_MACHINE))
        return scopes




    def _csp_rows_by_iids(self, iids):
        m = {}
        for r in self.csp_rows:
            iid = r.get("_iid")
            if iid:
                m[iid] = r
        out = []
        for iid in iids:
            if iid in m:
                out.append(m[iid])
        return out





    # =========================
    # CSP: context menu actions
    # =========================
    def _csp_on_right_click(self, event):
        iid = self.tree_csp.identify_row(event.y)
        if not iid:
            return
        # select row under cursor (without clearing multi-selection if already selected)
        if iid not in self.tree_csp.selection():
            self.tree_csp.selection_set(iid)

        selected_rows = self._csp_rows_by_iids(self.tree_csp.selection())
        zip_state = "normal" if self._csp_can_zip_rows(selected_rows) else "disabled"
        self.csp_menu.entryconfig("Сжать контейнер в ZIP", state=zip_state)

        self.csp_menu.tk_popup(event.x_root, event.y_root)

    def _csp_get_first_selected_row(self):
        sel = self.tree_csp.selection()
        if not sel:
            return None
        rows = self._csp_rows_by_iids(sel)
        if not rows:
            return None
        return rows[0]

    def _csp_is_flash_row(self, row) -> bool:
        return bool(row) and is_flash_unique_name(row.get("unique", ""))

    def _csp_can_zip_row(self, row) -> bool:
        if not self._csp_is_flash_row(row):
            return False
        if not row.get("has_cert"):
            return False
        if not (row.get("cn") or "").strip():
            return False
        if not (row.get("end") or "").strip():
            return False
        return True

    def _csp_can_zip_rows(self, rows) -> bool:
        rows = rows or []
        if not rows:
            return False
        return all(self._csp_can_zip_row(row) for row in rows)


    def _csp_copy_field(self, field: str):
        row = self._csp_get_first_selected_row()
        if not row:
            return
        val = (row.get(field) or "").strip()
        if not val:
            messagebox.showinfo("Копирование", "Значение пустое.")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(val)
            self.update_idletasks()
            self.status_var.set(f"Скопировано в буфер: {field}.")
        except Exception:
            messagebox.showerror("Ошибка", "Не удалось скопировать в буфер обмена.")

    def _csp_make_exportable(self):
        if self._busy:
            return
        row = self._csp_get_first_selected_row()
        if not row:
            return

        if row.get("export") == "+":
            messagebox.showinfo("Экспорт", "Контейнер уже выглядит как экспортируемый.")
            return

        if not messagebox.askyesno(
            "Подтверждение",
            "Попробовать сделать закрытый ключ экспортируемым?\n"
            "Не все CSP/токены позволяют менять это свойство программно."
        ):
            return

        prov = row.get("provider")
        cont = row.get("container")
        machine = bool(row.get("machine"))
        key_spec = row.get("key_spec") or AT_KEYEXCHANGE

        ok = set_key_exportable(prov, row.get("prov_type"), cont, machine, key_spec)
        if ok:
            self.status_var.set("Экспорт: флаг установлен (если CSP поддерживает). Обновляю список...")
            self.csp_show()
        else:
            messagebox.showwarning(
                "Экспорт",
                "Не получилось. Вероятно, CSP/токен не поддерживает изменение экспортируемости.\n"
                "В некоторых случаях это настраивается только при генерации ключа."
            )



if __name__ == "__main__":
    app = App()
    app.mainloop()
