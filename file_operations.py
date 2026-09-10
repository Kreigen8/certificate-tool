import re
import hashlib
import os
import zipfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import ctypes
from ctypes import wintypes

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


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

def make_safe_name(name: str, max_len: int = 200) -> str:
    safe = INVALID_CHARS_RE.sub("-", name or "")
    safe = safe.strip().strip(".")
    safe = re.sub(r"\s+", " ", safe).strip()
    if len(safe) > max_len:
        safe = safe[:max_len].rstrip()
    return safe or "EMPTY"


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
    src_dir, zip_path = Path(src_dir), Path(zip_path)
    if zip_path.resolve().is_relative_to(src_dir.resolve()):
        raise ValueError('Архив необходимо сохранять вне папки контейнера.')
    files_count = 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=zip_path.parent, suffix='.tmp', delete=False) as f:
            temporary = Path(f.name)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in src_dir.rglob("*"):
                if not p.is_file():
                    continue
                arcname = str(p.relative_to(src_dir.parent))
                zf.write(p, arcname=arcname)
                files_count += 1
        if not files_count:
            raise ValueError('Папка контейнера пуста; архив не создан.')
        with zipfile.ZipFile(temporary) as zf:
            if zf.testzip() is not None:
                raise OSError('Архив не прошел проверку целостности.')
        os.replace(temporary, zip_path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return files_count


def load_cert_file(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except ValueError:
        return x509.load_pem_x509_certificate(data, default_backend())
