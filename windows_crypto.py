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

def crypto_error(operation, code=None):
    code = (ctypes.get_last_error() if code is None else code) & 0xffffffff
    return OSError(f'{operation}: 0x{code:08X} — {ctypes.FormatError(ctypes.c_long(code).value).strip()}')


def is_user_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)

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
crypt32.CertFreeCertificateContext.argtypes = [PCCERT_CONTEXT]
crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
crypt32.CertDuplicateCertificateContext.argtypes = [PCCERT_CONTEXT]
crypt32.CertDuplicateCertificateContext.restype = PCCERT_CONTEXT

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

CERT_FIND_PUBLIC_KEY = 6 << 16
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
        raise crypto_error('Открытие хранилища ' + store_name)
    return h


def iter_store_der(store_name, scope_flag):
    h = _open_system_store(store_name, scope_flag)
    ctx = None
    try:
        while True:
            ctx = crypt32.CertEnumCertificatesInStore(h, ctx)
            if not ctx:
                break
            cc = ctypes.cast(ctx, ctypes.POINTER(CERT_CONTEXT)).contents
            yield ctypes.string_at(cc.pbCertEncoded, cc.cbCertEncoded)
    finally:
        if ctx:
            crypt32.CertFreeCertificateContext(ctx)
        crypt32.CertCloseStore(h, 0)



def delete_from_store_by_thumbprints(store_name, scope_flag, thumbs_set):
    h = _open_system_store(store_name, scope_flag)
    targets = []
    ctx = None
    deleted = errors = 0
    try:
        while True:
            ctx = crypt32.CertEnumCertificatesInStore(h, ctx)
            if not ctx:
                break
            cc = ctypes.cast(ctx, ctypes.POINTER(CERT_CONTEXT)).contents
            der = ctypes.string_at(cc.pbCertEncoded, cc.cbCertEncoded)
            if hashlib.sha1(der).hexdigest().upper() in thumbs_set:
                duplicate = crypt32.CertDuplicateCertificateContext(ctx)
                if duplicate:
                    targets.append(duplicate)
                else:
                    errors += 1
        # Delete each matched context once; a failure must not restart enumeration.
        while targets:
            target = targets.pop()
            if crypt32.CertDeleteCertificateFromStore(target):
                deleted += 1
            else:
                errors += 1
        return deleted, errors
    finally:
        if ctx:
            crypt32.CertFreeCertificateContext(ctx)
        for target in targets:
            crypt32.CertFreeCertificateContext(target)
        crypt32.CertCloseStore(h, 0)



def find_cert_in_my_by_public_key(scope_flag: int, hprov: wintypes.HANDLE, key_spec: int, store=None):
    """
    Export CERT_PUBLIC_KEY_INFO from provider and find cert in MY by CERT_FIND_PUBLIC_KEY.
    Returns DER cert bytes or None.
    """
    pcb = wintypes.DWORD(0)

    ok = crypt32.CryptExportPublicKeyInfo(hprov, key_spec, ENCODING, None, ctypes.byref(pcb))
    if not ok or pcb.value == 0:
        raise crypto_error('Чтение открытого ключа')

    buf = (ctypes.c_ubyte * pcb.value)()
    ok = crypt32.CryptExportPublicKeyInfo(
        hprov, key_spec, ENCODING, ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(pcb)
    )
    if not ok:
        raise crypto_error('Экспорт открытого ключа')

    hstore = store or _open_system_store("MY", scope_flag)
    ctx = None
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
            code = ctypes.get_last_error() & 0xffffffff
            if code != 0x80092004:  # CRYPT_E_NOT_FOUND
                raise crypto_error('Поиск сертификата в MY', code)
            return None

        cc = ctypes.cast(ctx, ctypes.POINTER(CERT_CONTEXT)).contents
        der = ctypes.string_at(cc.pbCertEncoded, cc.cbCertEncoded)
        return der
    finally:
        if ctx:
            crypt32.CertFreeCertificateContext(ctx)
        if store is None:
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
            raise crypto_error('Перечисление провайдеров', err)

        buf = ctypes.create_unicode_buffer(name_len.value)
        ok = CryptEnumProvidersW(idx, None, 0, ctypes.byref(prov_type), buf, ctypes.byref(name_len))
        if not ok:
            raise crypto_error('Чтение имени провайдера')

        name = buf.value
        n = (name or "").lower()
        if any(a in n for a in allow):
            providers.append((name, prov_type.value))

        idx += 1

    return providers



def enum_csp_containers_for_provider(provider_name, prov_type, machine):
    flags = CRYPT_VERIFYCONTEXT | (CRYPT_MACHINE_KEYSET if machine else 0)
    h = HCRYPTPROV()
    if not CryptAcquireContextW(ctypes.byref(h), None, provider_name, prov_type, flags):
        raise crypto_error('Открытие провайдера')
    names = []
    first = True
    capacity = 4096
    try:
        while True:
            size = wintypes.DWORD(capacity)
            buf = (ctypes.c_ubyte * capacity)()
            if not CryptGetProvParam(h, PP_ENUMCONTAINERS, buf, ctypes.byref(size), CRYPT_FIRST if first else CRYPT_NEXT):
                code = ctypes.get_last_error() & 0xffffffff
                if code == 259:
                    break
                if code == 234 and size.value > capacity:
                    capacity = size.value
                    continue
                raise crypto_error('Перечисление контейнеров', code)
            first = False
            name = bytes(buf[:size.value]).split(b'\0', 1)[0].decode('mbcs', errors='replace').strip()
            if name:
                names.append(name)
    finally:
        CryptReleaseContext(h, 0)
    return list(dict.fromkeys(names))



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
        return (None, None)
    try:
        hkey = HCRYPTKEY()
        okk = CryptGetUserKey(hprov, key_spec, ctypes.byref(hkey))
        if not okk:
            return (None, None)
        try:
            cb = wintypes.DWORD(ctypes.sizeof(wintypes.DWORD))
            buf = (ctypes.c_ubyte * cb.value)()
            okp = CryptGetKeyParam(hkey, KP_PERMISSIONS, buf, ctypes.byref(cb), 0)
            if not okp or cb.value < 4:
                return (None, None)
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




def read_container_details(provider_name, prov_type, container_name, machine, get_store):
    """Read metadata using one provider handle; never export a private key."""
    result = dict(unique='', der=None, key_spec=None, export='', cert_in='-', errors=[])
    h = HCRYPTPROV()
    if not CryptAcquireContextW(ctypes.byref(h), container_name, provider_name, prov_type,
                               CRYPT_MACHINE_KEYSET if machine else 0):
        raise crypto_error('Открытие контейнера')
    try:
        try:
            size = wintypes.DWORD(0)
            if not CryptGetProvParam(h, PP_UNIQUE_CONTAINER, None, ctypes.byref(size), 0):
                raise crypto_error('Чтение уникального имени')
            buf = (ctypes.c_ubyte * size.value)()
            if not CryptGetProvParam(h, PP_UNIQUE_CONTAINER, buf, ctypes.byref(size), 0):
                raise crypto_error('Чтение уникального имени')
            result['unique'] = bytes(buf[:size.value]).split(b'\0', 1)[0].decode('mbcs', errors='replace')
        except OSError as exc:
            result['errors'].append(str(exc))
        for spec in (AT_KEYEXCHANGE, AT_SIGNATURE):
            key = HCRYPTKEY()
            if not CryptGetUserKey(h, spec, ctypes.byref(key)):
                code = ctypes.get_last_error() & 0xffffffff
                if code != 0x8009000D:  # NTE_NO_KEY: this key slot is empty.
                    result['errors'].append(str(crypto_error('Чтение ключа', code)))
                continue
            try:
                size = wintypes.DWORD(0)
                der = None
                if CryptGetKeyParam(key, KP_CERTIFICATE, None, ctypes.byref(size), 0) and size.value:
                    buf = (ctypes.c_ubyte * size.value)()
                    if CryptGetKeyParam(key, KP_CERTIFICATE, buf, ctypes.byref(size), 0):
                        der = bytes(buf[:size.value])
                        result['cert_in'] = '+'
                    else:
                        result['errors'].append(str(crypto_error('Чтение сертификата')))
                else:
                    code = ctypes.get_last_error() & 0xffffffff
                    if code not in (0, 2, 50, 87, 0x8009000A, 0x80090011):
                        result['errors'].append(str(crypto_error('Чтение сертификата', code)))
                if not der:
                    try:
                        scope = CERT_SYSTEM_STORE_LOCAL_MACHINE if machine else CERT_SYSTEM_STORE_CURRENT_USER
                        der = find_cert_in_my_by_public_key(scope, h, spec, get_store(scope))
                    except OSError as exc:
                        result['errors'].append(str(exc))
                if not der:
                    continue
                result.update(der=der, key_spec=spec)
                size = wintypes.DWORD(4)
                permissions = (ctypes.c_ubyte * 4)()
                if CryptGetKeyParam(key, KP_PERMISSIONS, permissions, ctypes.byref(size), 0):
                    result['export'] = '+' if int.from_bytes(bytes(permissions), 'little') & CRYPT_EXPORT else '-'
                else:
                    result['errors'].append(str(crypto_error('Чтение прав экспорта')))
                break
            finally:
                CryptDestroyKey(key)
    finally:
        CryptReleaseContext(h, 0)
    return result


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
                        if cert2 is not None:
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
