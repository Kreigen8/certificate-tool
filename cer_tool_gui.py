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


# =========================
# ADMIN CHECK
# =========================
def is_user_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# =========================
# Tooltip (simple)
# =========================
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


# =========================
# Common helpers
# =========================
INVALID_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1F]')

STATUS_EXPIRED = "Срок действия истек"
STATUS_VALID = "Действующий"
STATUS_NOCERT = "Без сертификата"

STARTUP_WARNING = (
    "Утилита предназначена для просмотра и обработки сертификатов в файловой системе, "
    "в хранилищах Windows и контейнерах ЭЦП (CSP).\n\n"
    "Возможности программы:\n"
    "• просмотр сертификатов в каталогах\n"
    "• переименование файлов сертификатов по шаблону\n"
    "• удаление просроченных файлов сертификатов\n"
    "• просмотр сертификатов в хранилищах Windows\n"
    "• удаление просроченных сертификатов из хранилищ Windows\n"
    "• просмотр контейнеров ЭЦП (CryptoPro/ViPNet/токены) с привязанными сертификатами\n"
    "• удаление просроченных и выбранных контейнеров\n\n"
    "Ответственность за последствия использования программы полностью лежит на пользователе.\n"
    "Перед удалением рекомендуется создавать резервные копии и внимательно проверять список действий."
)


def now_utc():
    return datetime.now(timezone.utc)


def fmt_date(dt):
    return dt.strftime("%Y-%m-%d")


def parse_date(s: str):
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None


def make_safe_name(name: str, max_len: int = 200) -> str:
    safe = INVALID_CHARS_RE.sub("-", name or "")
    safe = safe.strip().strip(".")
    safe = re.sub(r"\s+", " ", safe).strip()
    if len(safe) > max_len:
        safe = safe[:max_len].rstrip()
    return safe or "EMPTY"


def get_cn_or_subject(cert: x509.Certificate) -> str:
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn and cn[0].value:
            return str(cn[0].value)
    except Exception:
        pass
    return cert.subject.rfc4514_string() or ""


def cert_is_expired(cert: x509.Certificate) -> bool:
    dt = now_utc()
    na = cert.not_valid_after
    if na.tzinfo is None:
        na = na.replace(tzinfo=timezone.utc)
    return na < dt


def normalize_person_name(raw: str) -> str:
    s = re.sub(r"\s+", " ", (raw or "").strip())
    s = re.sub(r"[;,]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def format_name_variant(raw_name: str, variant: str) -> str:
    """
    variant:
      - "fio": Фамилия Имя Отчество
      - "fio_short": Фамилия И.О.
    """
    name = normalize_person_name(raw_name)
    parts = [p for p in name.split(" ") if p]

    if len(parts) < 2:
        return name

    surname = parts[0]
    firstname = parts[1] if len(parts) >= 2 else ""
    patronymic = parts[2] if len(parts) >= 3 else ""

    if variant == "fio":
        if patronymic:
            return f"{surname} {firstname} {patronymic}"
        return f"{surname} {firstname}"

    if variant == "fio_short":
        ini1 = (firstname[0] + ".") if firstname else ""
        ini2 = (patronymic[0] + ".") if patronymic else ""
        initials = (ini1 + ini2).strip()
        if initials:
            return f"{surname} {initials}"
        return surname

    return name


def build_date_suffix(date_mode: str, start_s: str, end_s: str) -> str:
    """
    date_mode:
      - "none": Без даты
      - "end": Окончание срока действия
      - "start_end": Начало и конец
    """
    if date_mode == "none":
        return ""
    if date_mode == "end":
        return end_s
    if date_mode == "start_end":
        if start_s and end_s:
            return f"{start_s}_{end_s}"
        return end_s or start_s
    return ""


def safe_rename_target(path: Path, new_stem: str) -> Path:
    new_stem = make_safe_name(new_stem)
    candidate = path.with_name(new_stem + path.suffix)
    if candidate == path:
        return path
    if not candidate.exists():
        return candidate

    i = 1
    while True:
        cand = path.with_name(f"{new_stem} ({i}){path.suffix}")
        if not cand.exists():
            return cand
        i += 1


def compact_name_for_archive(raw_name: str) -> str:
    name = normalize_person_name(raw_name)
    parts = [p for p in name.split(" ") if p]
    if not parts:
        return "CONTAINER"

    surname = parts[0]
    firstname = parts[1] if len(parts) >= 2 else ""
    patronymic = parts[2] if len(parts) >= 3 else ""

    initials = ""
    if firstname:
        initials += firstname[0]
    if patronymic:
        initials += patronymic[0]

    return make_safe_name(f"{surname}{initials}")


def safe_output_path(parent: Path, stem: str, suffix: str) -> Path:
    safe_stem = make_safe_name(stem)
    candidate = parent / f"{safe_stem}{suffix}"
    if not candidate.exists():
        return candidate

    i = 1
    while True:
        cand = parent / f"{safe_stem} ({i}){suffix}"
        if not cand.exists():
            return cand
        i += 1


def build_container_zip_name(raw_name: str, end_s: str) -> str:
    base = compact_name_for_archive(raw_name)
    if end_s:
        return f"{base}-{end_s}"
    return base


DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
_SKIP_DIR_NAMES = {"$recycle.bin", "system volume information"}


def iter_drive_roots_for_container_search():
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:
        bitmask = 0

    removable = []
    fixed = []

    for i in range(26):
        if not (bitmask & (1 << i)):
            continue
        letter = chr(ord("A") + i)
        root = f"{letter}:\\"
        try:
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        except Exception:
            continue

        p = Path(root)
        if drive_type == DRIVE_REMOVABLE:
            removable.append(p)
        elif drive_type == DRIVE_FIXED:
            fixed.append(p)

    # Некоторые USB-флешки Windows показывает как fixed disk.
    # Поэтому сначала проверяем removable, потом fixed.
    return removable + fixed


def is_flash_unique_name(unique_name: str) -> bool:
    u = (unique_name or "").replace("/", "\\").strip().upper()
    return u.startswith("FAT") or u.startswith("FLASH")


def build_container_path_candidates(unique_name: str, container_name: str):
    candidates = []

    def add_candidate(parts):
        clean = [p.strip() for p in parts if p and p.strip()]
        if not clean:
            return
        candidates.append(tuple(clean))

    for raw in (unique_name, container_name):
        if not raw:
            continue
        parts = [p for p in str(raw).replace("/", "\\").split("\\") if p]
        if not parts:
            continue

        add_candidate(parts)
        add_candidate([parts[-1]])

        if len(parts) >= 2:
            add_candidate([parts[-2]])
            add_candidate(parts[-2:])

        if parts[0].upper().startswith("FAT") or parts[0].upper().startswith("FLASH"):
            add_candidate(parts[1:])
            if len(parts) > 2:
                add_candidate(parts[1:-1])
                add_candidate(parts[2:-1])
            if len(parts) >= 2:
                add_candidate([parts[-2]])

    unique = []
    seen = set()
    for parts in candidates:
        key = "\\".join(parts).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(parts)
    return unique


def _find_dir_by_name(root: Path, target_names: set, max_depth: int = 5):
    def walk(cur: Path, depth: int):
        try:
            entries = list(os.scandir(cur))
        except Exception:
            return None

        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except Exception:
                continue

            entry_name_l = entry.name.lower()
            if entry_name_l in _SKIP_DIR_NAMES:
                continue

            p = Path(entry.path)
            if entry_name_l in target_names:
                return p

            if depth < max_depth:
                found = walk(p, depth + 1)
                if found:
                    return found
        return None

    return walk(root, 1)


def find_container_folder_on_removable(unique_name: str, container_name: str):
    candidates = build_container_path_candidates(unique_name, container_name)
    if not candidates:
        return None

    target_leafs = {parts[-1].lower() for parts in candidates if parts}

    for root in iter_drive_roots_for_container_search():
        for parts in candidates:
            try:
                candidate = root.joinpath(*parts)
            except Exception:
                continue
            try:
                if candidate.is_dir():
                    return candidate
            except Exception:
                pass

        found = _find_dir_by_name(root, target_leafs, max_depth=3)
        if found:
            return found

    return None


def zip_folder_with_root(src_dir: Path, zip_path: Path) -> int:
    files_count = 0
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in src_dir.rglob("*"):
            if not p.is_file():
                continue
            arcname = str(p.relative_to(src_dir.parent))
            zf.write(p, arcname=arcname)
            files_count += 1
    return files_count


# =========================
# Cert file load
# =========================
def load_cert_file(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except ValueError:
        return x509.load_pem_x509_certificate(data, default_backend())


# =========================
# Windows Crypt32 for CERT STORES (used by "Реестр" tab and CSP matching)
# =========================
crypt32 = ctypes.WinDLL("crypt32.dll")

CERT_STORE_PROV_SYSTEM_W = ctypes.c_void_p(10)
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000

PCCERT_CONTEXT = ctypes.c_void_p
HCERTSTORE = ctypes.c_void_p

class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", HCERTSTORE),
    ]

crypt32.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
crypt32.CertOpenStore.restype = HCERTSTORE
crypt32.CertCloseStore.argtypes = [HCERTSTORE, wintypes.DWORD]
crypt32.CertCloseStore.restype = wintypes.BOOL
crypt32.CertEnumCertificatesInStore.argtypes = [HCERTSTORE, PCCERT_CONTEXT]
crypt32.CertEnumCertificatesInStore.restype = PCCERT_CONTEXT
crypt32.CertDeleteCertificateFromStore.argtypes = [PCCERT_CONTEXT]
crypt32.CertDeleteCertificateFromStore.restype = wintypes.BOOL

# For matching container -> cert by public key
crypt32.CryptExportPublicKeyInfo.argtypes = [
    wintypes.HANDLE,  # hCryptProvOrNCryptKey
    wintypes.DWORD,   # dwKeySpec
    wintypes.DWORD,   # dwCertEncodingType
    ctypes.c_void_p,  # pInfo (PCERT_PUBLIC_KEY_INFO) or None
    ctypes.POINTER(wintypes.DWORD)  # pcbInfo
]
crypt32.CryptExportPublicKeyInfo.restype = wintypes.BOOL

crypt32.CertFindCertificateInStore.argtypes = [
    HCERTSTORE,
    wintypes.DWORD,  # dwCertEncodingType
    wintypes.DWORD,  # dwFindFlags
    wintypes.DWORD,  # dwFindType
    ctypes.c_void_p, # pvFindPara
    PCCERT_CONTEXT   # pPrevCertContext
]
crypt32.CertFindCertificateInStore.restype = PCCERT_CONTEXT


# Public key find
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
ENCODING = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING

CERT_FIND_PUBLIC_KEY = 0x00000006  # per WinCrypt.h
# NOTE: pvFindPara points to CERT_PUBLIC_KEY_INFO structure

class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [
        ("pszObjId", wintypes.LPSTR),
        ("Parameters", ctypes.c_byte * 1),  # placeholder, not used directly
    ]



def _open_system_store(store_name: str, scope_flag: int) -> HCERTSTORE:
    pvPara = ctypes.c_wchar_p(store_name)
    h = crypt32.CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        None,
        scope_flag | CERT_STORE_OPEN_EXISTING_FLAG,
        ctypes.cast(pvPara, ctypes.c_void_p),
    )
    if not h:
        raise OSError("CertOpenStore failed")
    return h


def iter_store_der(store_name: str, scope_flag: int):
    h = _open_system_store(store_name, scope_flag)
    try:
        ctx = PCCERT_CONTEXT(None)
        while True:
            ctx = crypt32.CertEnumCertificatesInStore(h, ctx)
            if not ctx:
                break
            cc = ctypes.cast(ctx, ctypes.POINTER(CERT_CONTEXT)).contents
            der = ctypes.string_at(cc.pbCertEncoded, cc.cbCertEncoded)
            yield der
    finally:
        crypt32.CertCloseStore(h, 0)


def delete_from_store_by_thumbprints(store_name: str, scope_flag: int, thumbs_set: set):
    h = _open_system_store(store_name, scope_flag)
    deleted = 0
    errors = 0
    try:
        ctx = PCCERT_CONTEXT(None)
        while True:
            ctx = crypt32.CertEnumCertificatesInStore(h, ctx)
            if not ctx:
                break
            cc = ctypes.cast(ctx, ctypes.POINTER(CERT_CONTEXT)).contents
            der = ctypes.string_at(cc.pbCertEncoded, cc.cbCertEncoded)
            th = hashlib.sha1(der).hexdigest().upper()
            if th in thumbs_set:
                ok = crypt32.CertDeleteCertificateFromStore(ctx)
                if ok:
                    deleted += 1
                else:
                    errors += 1
                ctx = PCCERT_CONTEXT(None)
        return deleted, errors
    finally:
        crypt32.CertCloseStore(h, 0)


def find_cert_in_my_by_public_key(scope_flag: int, hprov: wintypes.HANDLE, key_spec: int):
    """
    Export CERT_PUBLIC_KEY_INFO from provider and find cert in MY by CERT_FIND_PUBLIC_KEY.
    Returns DER cert bytes or None.
    """
    pcb = wintypes.DWORD(0)

    ok = crypt32.CryptExportPublicKeyInfo(hprov, key_spec, ENCODING, None, ctypes.byref(pcb))
    if not ok or pcb.value == 0:
        return None

    buf = (ctypes.c_ubyte * pcb.value)()
    ok = crypt32.CryptExportPublicKeyInfo(
        hprov, key_spec, ENCODING, ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(pcb)
    )
    if not ok:
        return None

    hstore = _open_system_store("MY", scope_flag)
    try:
        # ВАЖНО: pvFindPara должен указывать на CERT_PUBLIC_KEY_INFO, который уже лежит в buf
        ctx = crypt32.CertFindCertificateInStore(
            hstore,
            ENCODING,
            0,
            CERT_FIND_PUBLIC_KEY,
            ctypes.cast(buf, ctypes.c_void_p),
            PCCERT_CONTEXT(None),
        )
        if not ctx:
            return None

        cc = ctypes.cast(ctx, ctypes.POINTER(CERT_CONTEXT)).contents
        der = ctypes.string_at(cc.pbCertEncoded, cc.cbCertEncoded)
        return der
    finally:
        crypt32.CertCloseStore(hstore, 0)



# =========================
# CSP (advapi32) container logic
# =========================
advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)

CryptEnumProvidersW = advapi32.CryptEnumProvidersW
CryptEnumProvidersW.argtypes = [
    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
]
CryptEnumProvidersW.restype = wintypes.BOOL

HCRYPTPROV = wintypes.HANDLE
HCRYPTKEY = wintypes.HANDLE

CryptAcquireContextW = advapi32.CryptAcquireContextW
CryptAcquireContextW.argtypes = [
    ctypes.POINTER(HCRYPTPROV),
    wintypes.LPCWSTR,  # pszContainer
    wintypes.LPCWSTR,  # pszProvider
    wintypes.DWORD,    # dwProvType
    wintypes.DWORD     # dwFlags
]
CryptAcquireContextW.restype = wintypes.BOOL

CryptReleaseContext = advapi32.CryptReleaseContext
CryptReleaseContext.argtypes = [HCRYPTPROV, wintypes.DWORD]
CryptReleaseContext.restype = wintypes.BOOL

CryptGetProvParam = advapi32.CryptGetProvParam
CryptGetProvParam.argtypes = [
    HCRYPTPROV, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD
]
CryptGetProvParam.restype = wintypes.BOOL

CryptGetUserKey = advapi32.CryptGetUserKey
CryptGetUserKey.argtypes = [HCRYPTPROV, wintypes.DWORD, ctypes.POINTER(HCRYPTKEY)]
CryptGetUserKey.restype = wintypes.BOOL

CryptGetKeyParam = advapi32.CryptGetKeyParam
CryptGetKeyParam.argtypes = [HCRYPTKEY, wintypes.DWORD, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
CryptGetKeyParam.restype = wintypes.BOOL

CryptSetKeyParam = advapi32.CryptSetKeyParam
CryptSetKeyParam.argtypes = [HCRYPTKEY, wintypes.DWORD, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD]
CryptSetKeyParam.restype = wintypes.BOOL

CryptDestroyKey = advapi32.CryptDestroyKey
CryptDestroyKey.argtypes = [HCRYPTKEY]
CryptDestroyKey.restype = wintypes.BOOL

PP_ENUMCONTAINERS = 2
CRYPT_FIRST = 1
CRYPT_NEXT = 2

CRYPT_VERIFYCONTEXT = 0xF0000000
CRYPT_MACHINE_KEYSET = 0x00000020
CRYPT_DELETEKEYSET = 0x00000010

AT_KEYEXCHANGE = 1
AT_SIGNATURE = 2

KP_CERTIFICATE = 26  # certificate (DER) from key, if provider supports

# Extra CSP params
PP_UNIQUE_CONTAINER = 36  # unique container name (like FAT12\...)
KP_PERMISSIONS = 6        # key permissions
CRYPT_EXPORT = 0x00000004 # permission flag: export allowed



def enum_csp_providers():
    providers = []
    idx = 0

    allow = ("crypto-pro", "криптопро", "vipnet", "випнет", "rutoken", "рутокен", "aktiv", "актив")

    while True:
        prov_type = wintypes.DWORD(0)
        name_len = wintypes.DWORD(0)

        ok = CryptEnumProvidersW(idx, None, 0, ctypes.byref(prov_type), None, ctypes.byref(name_len))
        if not ok:
            err = ctypes.get_last_error()
            if err == 259:
                break
            break

        buf = ctypes.create_unicode_buffer(name_len.value)
        ok = CryptEnumProvidersW(idx, None, 0, ctypes.byref(prov_type), buf, ctypes.byref(name_len))
        if not ok:
            break

        name = buf.value
        n = (name or "").lower()
        if any(a in n for a in allow):
            providers.append((name, prov_type.value))

        idx += 1

    return providers



def enum_csp_containers_for_provider(provider_name: str, prov_type: int, machine: bool):
    flags = CRYPT_VERIFYCONTEXT | (CRYPT_MACHINE_KEYSET if machine else 0)
    h = HCRYPTPROV()
    ok = CryptAcquireContextW(ctypes.byref(h), None, provider_name, prov_type, flags)
    if not ok:
        return []

    out = []
    try:
        # first size
        data_len = wintypes.DWORD(0)
        ok = CryptGetProvParam(h, PP_ENUMCONTAINERS, None, ctypes.byref(data_len), CRYPT_FIRST)
        if not ok or data_len.value == 0:
            return []

        # loop
        prev_first = True
        while True:
            buf = (ctypes.c_ubyte * data_len.value)()
            ok = CryptGetProvParam(h, PP_ENUMCONTAINERS, buf, ctypes.byref(data_len), CRYPT_FIRST if prev_first else CRYPT_NEXT)
            prev_first = False
            if not ok:
                err = ctypes.get_last_error()
                if err == 259:
                    break
                break

            raw = bytes(buf[:data_len.value])
            # Most CSP return ANSI here
            try:
                name = raw.split(b"\x00", 1)[0].decode("mbcs", errors="replace")
            except Exception:
                name = raw.hex()

            name = (name or "").strip()
            if name:
                out.append(name)

            # prepare next
            data_len = wintypes.DWORD(4096)
    finally:
        CryptReleaseContext(h, 0)

    # unique
    seen = set()
    res = []
    for c in out:
        if c not in seen:
            seen.add(c)
            res.append(c)
    return res


def delete_container(provider_name: str, prov_type: int, container_name: str, machine: bool) -> bool:
    flags = CRYPT_DELETEKEYSET | (CRYPT_MACHINE_KEYSET if machine else 0)
    h = HCRYPTPROV()
    ok = CryptAcquireContextW(ctypes.byref(h), container_name, provider_name, prov_type, flags)
    # On success handle may be returned or not used. For DELETEKEYSET, success means deletion.
    if ok:
        try:
            CryptReleaseContext(h, 0)
        except Exception:
            pass
    return bool(ok)

def get_unique_container_name(provider_name: str, prov_type: int, container_name: str, machine: bool) -> str:
    flags = (CRYPT_MACHINE_KEYSET if machine else 0)
    hprov = HCRYPTPROV()
    ok = CryptAcquireContextW(ctypes.byref(hprov), container_name, provider_name, prov_type, flags)
    if not ok:
        return ""
    try:
        cb = wintypes.DWORD(0)
        ok1 = CryptGetProvParam(hprov, PP_UNIQUE_CONTAINER, None, ctypes.byref(cb), 0)
        if not ok1 or cb.value == 0:
            return ""
        buf = (ctypes.c_ubyte * cb.value)()
        ok2 = CryptGetProvParam(hprov, PP_UNIQUE_CONTAINER, buf, ctypes.byref(cb), 0)
        if not ok2:
            return ""
        raw = bytes(buf[:cb.value])
        try:
            return raw.split(b"\x00", 1)[0].decode("mbcs", errors="replace").strip()
        except Exception:
            return ""
    finally:
        CryptReleaseContext(hprov, 0)


def get_key_exportable(provider_name: str, prov_type: int, container_name: str, machine: bool, key_spec: int):
    """Return (exportable: bool|None, perms_int|None). None if can't read."""
    flags = (CRYPT_MACHINE_KEYSET if machine else 0)
    hprov = HCRYPTPROV()
    ok = CryptAcquireContextW(ctypes.byref(hprov), container_name, provider_name, prov_type, flags)
    if not ok:
        return (None, None, False)
    try:
        hkey = HCRYPTKEY()
        okk = CryptGetUserKey(hprov, key_spec, ctypes.byref(hkey))
        if not okk:
            return (None, None, False)
        try:
            cb = wintypes.DWORD(ctypes.sizeof(wintypes.DWORD))
            buf = (ctypes.c_ubyte * cb.value)()
            okp = CryptGetKeyParam(hkey, KP_PERMISSIONS, buf, ctypes.byref(cb), 0)
            if not okp or cb.value < 4:
                return (None, None, False)
            perms = int.from_bytes(bytes(buf[:4]), "little", signed=False)
            return (bool(perms & CRYPT_EXPORT), perms)
        finally:
            CryptDestroyKey(hkey)
    finally:
        CryptReleaseContext(hprov, 0)


def set_key_exportable(provider_name: str, prov_type: int, container_name: str, machine: bool, key_spec: int) -> bool:
    """Try to set export permission on the key. Not all CSPs allow this."""
    flags = (CRYPT_MACHINE_KEYSET if machine else 0)
    hprov = HCRYPTPROV()
    ok = CryptAcquireContextW(ctypes.byref(hprov), container_name, provider_name, prov_type, flags)
    if not ok:
        return False
    try:
        hkey = HCRYPTKEY()
        okk = CryptGetUserKey(hprov, key_spec, ctypes.byref(hkey))
        if not okk:
            return False
        try:
            cb = wintypes.DWORD(4)
            buf = (ctypes.c_ubyte * 4)()
            okp = CryptGetKeyParam(hkey, KP_PERMISSIONS, buf, ctypes.byref(cb), 0)
            if not okp:
                return False
            perms = int.from_bytes(bytes(buf[:4]), "little", signed=False)
            perms2 = perms | CRYPT_EXPORT
            b2 = perms2.to_bytes(4, "little", signed=False)
            buf2 = (ctypes.c_ubyte * 4).from_buffer_copy(b2)
            return bool(CryptSetKeyParam(hkey, KP_PERMISSIONS, buf2, 0))
        finally:
            CryptDestroyKey(hkey)
    finally:
        CryptReleaseContext(hprov, 0)




def try_get_cert_der_from_container(provider_name: str, prov_type: int, container_name: str, machine: bool):
    """
    Open container and try:
      1) KP_CERTIFICATE from key (AT_KEYEXCHANGE then AT_SIGNATURE)
      2) fallback: find cert in MY store by public key
    Returns: (der_bytes, key_spec_used, cert_in_container_bool) or (None, None, False)
    """
    flags = (CRYPT_MACHINE_KEYSET if machine else 0)
    hprov = HCRYPTPROV()
    ok = CryptAcquireContextW(ctypes.byref(hprov), container_name, provider_name, prov_type, flags)
    if not ok:
        return (None, None, False)

    try:
        # Try both key specs
        for key_spec in (AT_KEYEXCHANGE, AT_SIGNATURE):
            hkey = HCRYPTKEY()
            okk = CryptGetUserKey(hprov, key_spec, ctypes.byref(hkey))
            if not okk:
                continue

            try:
                # 1) KP_CERTIFICATE
                cb = wintypes.DWORD(0)
                ok1 = CryptGetKeyParam(hkey, KP_CERTIFICATE, None, ctypes.byref(cb), 0)
                if ok1 and cb.value > 0:
                    buf = (ctypes.c_ubyte * cb.value)()
                    ok2 = CryptGetKeyParam(hkey, KP_CERTIFICATE, buf, ctypes.byref(cb), 0)
                    if ok2:
                        der = bytes(buf[:cb.value])
                        # sanity: must parse
                        try:
                            _ = x509.load_der_x509_certificate(der, default_backend())
                            return (der, key_spec, True)
                        except Exception:
                            pass

                
                # 2) fallback: find in MY by public key (with CN sanity check)
                scope_flag = CERT_SYSTEM_STORE_LOCAL_MACHINE if machine else CERT_SYSTEM_STORE_CURRENT_USER
                der2 = find_cert_in_my_by_public_key(scope_flag, hprov, key_spec)
                if der2:
                    try:
                        cert2 = x509.load_der_x509_certificate(der2, default_backend())
                        cn2 = get_cn_or_subject(cert2).lower()
                        cont_l = container_name.lower()

                        # проверяем, что контейнер и CN действительно связаны
                        if cn2 in cont_l or cont_l in cn2:
                            return (der2, key_spec, False)
                    except Exception:
                        pass


            finally:
                try:
                    CryptDestroyKey(hkey)
                except Exception:
                    pass

        return (None, None, False)
    finally:
        CryptReleaseContext(hprov, 0)


# =========================
# GUI App
# =========================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.admin = is_user_admin()

        self.title("Certificate Tool")
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

        self.after(150, lambda: messagebox.showwarning("Внимание", STARTUP_WARNING))

    # -------------------------
    # Sorting helper
    # -------------------------
    def _sort_tree(self, tree: ttk.Treeview, col: str, sort_state: dict, col_types: dict):
        reverse = sort_state.get(col, False)
        items = list(tree.get_children(""))

        def key_func(item_id):
            v = tree.set(item_id, col)
            typ = col_types.get(col, "str")
            if typ == "date":
                d = parse_date(v)
                return d or datetime.min
            return (v or "").lower()

        items.sort(key=key_func, reverse=reverse)
        for idx, iid in enumerate(items):
            tree.move(iid, "", idx)
        sort_state[col] = not reverse

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

    def files_show(self):
        root = Path(self.path_var.get()).expanduser()
        if not root.exists():
            messagebox.showerror("Ошибка", "Папка не найдена.")
            return

        pattern = "**/*.cer" if self.recurse_var.get() else "*.cer"
        rows = []
        total = 0
        expired = 0

        for f in root.glob(pattern):
            if not f.is_file():
                continue
            total += 1
            try:
                cert = load_cert_file(f)
                name = get_cn_or_subject(cert)
                start = fmt_date(cert.not_valid_before)
                end = fmt_date(cert.not_valid_after)
                is_exp = cert_is_expired(cert)
                status = STATUS_EXPIRED if is_exp else STATUS_VALID
                if is_exp:
                    expired += 1
                rows.append({
                    "name": name, "start": start, "end": end, "status": status, "path": str(f),
                    "is_expired": is_exp, "is_error": False
                })
            except Exception as e:
                rows.append({
                    "name": "Ошибка чтения", "start": "", "end": "", "status": "",
                    "path": f"{f} | {e}", "is_expired": False, "is_error": True
                })

        self.files_rows = rows
        self._render_files_filtered()
        self.status_var.set(f"Файлы: сертификатов найдено {total}, просроченных {expired}.")

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
        if not self.files_rows:
            self.files_show()
            if not self.files_rows:
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
        if not self.files_rows:
            self.files_show()
            if not self.files_rows:
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

    def store_show(self):
        scopes, stores = self._get_selected_store_scopes_and_stores()
        if not scopes:
            messagebox.showinfo("Опции", "Выбери хотя бы CurrentUser (или запусти от администратора для LocalMachine).")
            return
        if not stores:
            messagebox.showinfo("Опции", "Выбери хотя бы один стор: MY/CA/ROOT.")
            return

        rows = []
        total = 0
        expired = 0
        dt = now_utc()

        for scope_label, scope_flag in scopes:
            for store_name in stores:
                where = f"{scope_label}\\{store_name}"
                try:
                    for der in iter_store_der(store_name, scope_flag):
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        name = get_cn_or_subject(cert)
                        start = fmt_date(cert.not_valid_before)
                        end = fmt_date(cert.not_valid_after)
                        na = cert.not_valid_after
                        if na.tzinfo is None:
                            na = na.replace(tzinfo=timezone.utc)
                        is_exp = na < dt
                        status = STATUS_EXPIRED if is_exp else STATUS_VALID
                        if is_exp:
                            expired += 1
                        total += 1
                        rows.append({
                            "where": where, "name": name, "start": start, "end": end, "status": status,
                            "is_expired": is_exp, "is_error": False
                        })
                except Exception as e:
                    rows.append({
                        "where": where, "name": "Ошибка чтения", "start": "", "end": "", "status": str(e),
                        "is_expired": False, "is_error": True
                    })

        self.store_rows = rows
        self._render_store_filtered()
        self.status_var.set(f"Реестр: сертификатов найдено {total}, просроченных {expired}.")

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
        ttk.Label(search, text="Поиск (CN/контейнер):").pack(side="left")
        self.search_csp_var = tk.StringVar(value="")
        ttk.Entry(search, textvariable=self.search_csp_var, width=44).pack(side="left", padx=8)
        ttk.Button(search, text="Сброс", command=lambda: self.search_csp_var.set("")).pack(side="left")
        self.search_csp_var.trace_add("write", lambda *_: self._render_csp_filtered())

        cols = ("scope", "provider", "container", "unique", "cn", "serial", "thumb", "export", "cert_in", "start", "end", "status")
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
            "scope": "Scope",
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

        for c in cols:
            self.tree_csp.heading(c, text=headers[c], command=lambda col=c: self._sort_tree(self.tree_csp, col, self.sort_state_csp, self.csp_col_types))
            w = 100
            if c == "provider":
                w = 100
            if c == "container":
                w = 320
            if c == "unique":
                w = 300
            if c == "cn":
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

    def csp_show(self):
        scopes = self._get_csp_scopes()
        if not scopes:
            messagebox.showinfo("Опции", "Выбери хотя бы CurrentUser (или запусти от администратора для LocalMachine).")
            return

        providers = enum_csp_providers()
        dt = now_utc()

        best_by_key = {}

        def provider_rank(name: str) -> int:
            n = (name or "").lower()
            r = 0
            if "strong" in n:
                r += 30
            if "2012" in n:
                r += 20
            if "2001" in n:
                r += 5
            return r

        for scope_label, machine, scope_flag in scopes:
            for prov_name, prov_type in providers:
                containers = enum_csp_containers_for_provider(prov_name, prov_type, machine)

                for cont in containers:
                    der, key_spec, cert_in_container = try_get_cert_der_from_container(
                        prov_name, prov_type, cont, machine
                    )

                    # Если сертификата нет, показываем контейнер только если включен чекбокс
                    if not der:
                        if not self.csp_show_nocert_var.get():
                            continue

                        key = (scope_label, cont, "nocert")

                        row = {
                            "scope": scope_label,
                            "machine": machine,
                            "scope_flag": scope_flag,
                            "provider": prov_name,
                            "prov_type": prov_type,
                            "container": cont,
                            "key_spec": None,
                            "unique": get_unique_container_name(prov_name, prov_type, cont, machine),
                            "cn": "(нет сертификата)",
                            "serial": "",
                            "thumb": "",
                            "export": "",
                            "cert_in": "-",
                            "start": "",
                            "end": "",
                            "status": STATUS_NOCERT,
                            "is_expired": False,
                            "has_cert": False,
                        }

                        # Дедуп + выбор "лучшего" провайдера оставляем как у тебя
                        if key in best_by_key:
                            old = best_by_key[key]
                            if provider_rank(prov_name) > provider_rank(old["provider"]):
                                best_by_key[key] = row
                        else:
                            best_by_key[key] = row

                        continue


                    try:
                        cert = x509.load_der_x509_certificate(der, default_backend())
                    except Exception:
                        continue

                    cn = get_cn_or_subject(cert)
                    start = fmt_date(cert.not_valid_before)
                    end = fmt_date(cert.not_valid_after)

                    na = cert.not_valid_after
                    if na.tzinfo is None:
                        na = na.replace(tzinfo=timezone.utc)
                    is_exp = na < dt

                    status = STATUS_EXPIRED if is_exp else STATUS_VALID

                    cert_thumb = hashlib.sha1(der).hexdigest().upper()

                    # serial number
                    try:
                        sn = cert.serial_number
                        serial_hex = f"{sn:X}"
                        if len(serial_hex) % 2 == 1:
                            serial_hex = "0" + serial_hex
                    except Exception:
                        serial_hex = ""

                    # exportable permission
                    exportable, _perms = (None, None)
                    if key_spec:
                        exportable, _perms = get_key_exportable(prov_name, prov_type, cont, machine, key_spec)
                    export_mark = "+" if exportable else ("-" if exportable is False else "")

                    key = (scope_label, cont, cert_thumb)

                    row = {
                        "scope": scope_label,
                        "machine": machine,
                        "scope_flag": scope_flag,
                        "provider": prov_name,
                        "prov_type": prov_type,
                        "container": cont,
                        "key_spec": key_spec,
                        "unique": get_unique_container_name(prov_name, prov_type, cont, machine),
                        "cn": cn,
                        "serial": serial_hex,
                        "thumb": cert_thumb,
                        "export": export_mark,
                        "cert_in": "+" if cert_in_container else "-",
                        "start": start,
                        "end": end,
                        "status": status,
                        "is_expired": is_exp,
                        "has_cert": True,
                    }

                    if key in best_by_key:
                        old = best_by_key[key]
                        if provider_rank(prov_name) > provider_rank(old["provider"]):
                            best_by_key[key] = row
                    else:
                        best_by_key[key] = row

        rows = list(best_by_key.values())

        total_shown = len(rows)
        expired = sum(1 for r in rows if r.get("is_expired"))

        self.csp_rows = rows
        self._render_csp_filtered()
        self.status_var.set(f"Контейнеры CSP: показано {total_shown}, просроченных {expired}.")


    def _render_csp_filtered(self):
        q = (self.search_csp_var.get() or "").strip().lower()
        self._clear_tree(self.tree_csp)

        shown = 0
        expired_shown = 0

        for r in self.csp_rows:
            hay = f"{r.get('cn','')} {r.get('container','')} {r.get('unique','')} {r.get('serial','')} {r.get('thumb','')}".lower()
            if q and q not in hay:
                continue

            if r.get("is_expired"):
                tags = ("expired",)
            elif not r.get("has_cert", True):
                tags = ("nocert",)
            else:
                tags = ()

            iid = self.tree_csp.insert(
                "", "end",
                values=(r["scope"], r["provider"], r["container"], r.get("unique",""), r["cn"], r.get("serial",""), r.get("thumb",""), r.get("export",""), r.get("cert_in",""), r["start"], r["end"], r["status"]),
                tags=tags
            )
            # keep index -> iid mapping by attaching iid into dict (for deletion by selection)
            r["_iid"] = iid

            shown += 1
            if r.get("is_expired"):
                expired_shown += 1

        if self.csp_rows and q:
            total = len(self.csp_rows)
            total_expired = len([x for x in self.csp_rows if x.get("is_expired")])
            self.status_var.set(f"Контейнеры CSP: показано {shown} из {total}, просроченных показано {expired_shown} из {total_expired}.")

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

    def csp_delete_expired(self):
        if not self.csp_rows:
            self.csp_show()
            if not self.csp_rows:
                return

        expired_rows = [r for r in self.csp_rows if r.get("is_expired")]
        if not expired_rows:
            messagebox.showinfo("Готово", "Просроченных контейнеров не найдено (по сертификатам).")
            return

        if not messagebox.askyesno("Подтверждение", f"Удалить просроченные контейнеры: {len(expired_rows)} шт.?"):
            return

        okc = 0
        errc = 0
        for r in expired_rows:
            ok = delete_container(r["provider"], r["prov_type"], r["container"], r["machine"])
            if ok:
                okc += 1
            else:
                errc += 1

        self.csp_show()
        self.status_var.set(f"Контейнеры CSP: удалено {okc}, ошибок {errc} (просроченные).")

    def csp_delete_selected(self):
        selected = self.tree_csp.selection()
        if not selected:
            messagebox.showinfo("Выбор", "Выдели контейнеры в таблице и нажми 'Удалить выбранные'.")
            return

        rows = self._csp_rows_by_iids(selected)
        if not rows:
            messagebox.showinfo("Выбор", "Не удалось определить выбранные строки (обнови список).")
            return

        # Safety: show short summary
        cnt = len(rows)
        exp_cnt = len([r for r in rows if r.get("is_expired")])

        if not messagebox.askyesno(
            "Подтверждение",
            f"Удалить выбранные контейнеры: {cnt} шт.?\n"
            f"Из них просроченных (по сертификату): {exp_cnt}.\n\n"
            f"Удаление контейнера удаляет закрытый ключ."
        ):
            return

        okc = 0
        errc = 0
        for r in rows:
            ok = delete_container(r["provider"], r["prov_type"], r["container"], r["machine"])
            if ok:
                okc += 1
            else:
                errc += 1

        self.csp_show()
        self.status_var.set(f"Контейнеры CSP: удалено {okc}, ошибок {errc} (выбранные).")


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

    def _csp_zip_selected_container(self):
        rows = self._csp_rows_by_iids(self.tree_csp.selection())
        if not rows:
            return

        invalid_rows = [row for row in rows if not self._csp_can_zip_row(row)]
        if invalid_rows:
            messagebox.showinfo(
                "ZIP",
                "Архивация доступна только для контейнеров на флешке, у которых есть сертификат, ФИО и дата окончания."
            )
            return

        created = []
        errors = []
        total_files = 0

        for row in rows:
            src_dir = find_container_folder_on_removable(row.get("unique", ""), row.get("container", ""))
            if not src_dir:
                errors.append(
                    f"{row.get('container', '')}: не удалось найти папку контейнера на подключенной флешке"
                )
                continue

            zip_name = build_container_zip_name(row.get("cn", ""), row.get("end", ""))
            zip_path = safe_output_path(src_dir.parent, zip_name, ".zip")

            try:
                files_count = zip_folder_with_root(src_dir, zip_path)
                total_files += files_count
                created.append((row.get("container", ""), src_dir, zip_path, files_count))
            except Exception as e:
                errors.append(f"{row.get('container', '')}: {e}")

        if created and not errors:
            if len(created) == 1:
                cont, src_dir, zip_path, files_count = created[0]
                self.status_var.set(f"Контейнер упакован в ZIP: {zip_path}")
                messagebox.showinfo(
                    "ZIP",
                    f"Архив создан.\n\nПапка: {src_dir}\nФайлов: {files_count}\nZIP: {zip_path}"
                )
                return

            self.status_var.set(f"Контейнеры упакованы в ZIP: {len(created)} шт.")
            names = "\n".join(f"- {item[0]} -> {item[2]}" for item in created[:20])
            extra = ""
            if len(created) > 20:
                extra = f"\n... и еще {len(created) - 20}"
            messagebox.showinfo(
                "ZIP",
                f"Архивы созданы: {len(created)}\nФайлов внутри: {total_files}\n\n{names}{extra}"
            )
            return

        if not created and errors:
            err_text = "\n".join(f"- {e}" for e in errors[:20])
            extra = ""
            if len(errors) > 20:
                extra = f"\n... и еще {len(errors) - 20}"
            messagebox.showwarning("ZIP", f"Не удалось создать архивы.\n\n{err_text}{extra}")
            return

        self.status_var.set(f"Контейнеры упакованы в ZIP: {len(created)} из {len(rows)}")
        ok_text = "\n".join(f"- {item[0]} -> {item[2]}" for item in created[:15])
        err_text = "\n".join(f"- {e}" for e in errors[:15])
        extra_ok = ""
        extra_err = ""
        if len(created) > 15:
            extra_ok = f"\n... и еще {len(created) - 15}"
        if len(errors) > 15:
            extra_err = f"\n... и еще {len(errors) - 15}"
        messagebox.showinfo(
            "ZIP",
            f"Создано архивов: {len(created)} из {len(rows)}\nФайлов внутри: {total_files}"
            f"\n\nУспешно:\n{ok_text}{extra_ok}"
            f"\n\nОшибки:\n{err_text}{extra_err}"
        )

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