import re
import hashlib
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import ctypes
from ctypes import wintypes

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


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


def get_cn_or_subject(cert: x509.Certificate) -> str:
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn and cn[0].value:
            return str(cn[0].value)
    except Exception:
        pass
    return cert.subject.rfc4514_string() or ""


def get_certificate_report_fields(cert: x509.Certificate) -> dict:
    def value(oid):
        attributes = cert.subject.get_attributes_for_oid(oid)
        return str(attributes[0].value).strip() if attributes else ""

    surname = value(NameOID.SURNAME)
    given_name = value(NameOID.GIVEN_NAME)
    full_name = " ".join(part for part in (surname, given_name) if part)
    if not (surname and given_name):
        full_name = value(NameOID.COMMON_NAME) or full_name
    return {
        "organization": value(NameOID.ORGANIZATION_NAME),
        "position": value(NameOID.TITLE),
        "full_name": full_name,
    }


def cert_is_expired(cert: x509.Certificate) -> bool:
    return certificate_dates(cert)['is_expired']


STATUS_FUTURE = "Еще не действует"


def certificate_dates(cert, at=None):
    at = at or now_utc()
    start = cert.not_valid_before_utc
    end = cert.not_valid_after_utc
    expired = end < at
    status = STATUS_EXPIRED if expired else (STATUS_FUTURE if start > at else STATUS_VALID)
    import math
    return dict(start=fmt_date(start), end=fmt_date(end), status=status,
                is_expired=expired, is_future=start > at,
                days_left=math.ceil((end - at).total_seconds() / 86400))


def matches_csp_filter(row, query='', deadline='Все сроки', show_nocert=False):
    if not row.get('has_cert') and not show_nocert:
        return False
    hay = ' '.join(str(row.get(key, '') or '') for key in
                   ('cn', 'full_name', 'organization', 'position', 'container', 'unique', 'serial', 'thumb', 'error')).casefold()
    if query.strip().casefold() not in hay:
        return False
    if deadline == 'Просроченные':
        return bool(row.get('is_expired'))
    if deadline == STATUS_FUTURE:
        return bool(row.get('is_future'))
    if deadline != 'Все сроки':
        days = row.get('days_left')
        return (isinstance(days, int) and not row.get('is_expired') and not row.get('is_future')
                and 0 <= days <= int(deadline.split()[0]))
    return True


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


DRIVE_REMOVABLE = 2


DRIVE_FIXED = 3


_SKIP_DIR_NAMES = {"$recycle.bin", "system volume information"}
