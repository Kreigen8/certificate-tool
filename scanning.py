"""Read-only scans. No Tk calls; safe to run in one background worker."""
import hashlib
from contextlib import closing
from time import monotonic

from cryptography import x509
from certificate_utils import certificate_dates, get_cn_or_subject, get_certificate_report_fields, STATUS_NOCERT
from file_operations import load_cert_file
from diagnostics import logger
import windows_crypto as crypto


def scan_csp(scopes, cancel, progress):
    started = monotonic()
    stores, cache, best = {}, {}, {}
    count = 0

    def get_store(scope):
        if scope not in stores:
            stores[scope] = crypto._open_system_store('MY', scope)
        return stores[scope]

    def rank(row):
        name = row['provider'].lower()
        return (not bool(row.get('error')), 30 * ('strong' in name) + 20 * ('2012' in name) + 5 * ('2001' in name))

    try:
        providers = crypto.enum_csp_providers()
        for label, machine, scope in scopes:
            for provider, prov_type in providers:
                if cancel.is_set():
                    break
                base = dict(scope=label, machine=machine, scope_flag=scope, provider=provider,
                            prov_type=prov_type, container='', unique='', cn='', serial='', thumb='',
                            export='', cert_in='-', start='', end='', status=STATUS_NOCERT,
                            has_cert=False, is_expired=False, is_future=False, days_left=None, error='')
                progress(f'{provider}: поиск контейнеров…')
                try:
                    containers = crypto.enum_csp_containers_for_provider(provider, prov_type, machine)
                except Exception as exc:
                    logger.exception('Provider scan failed: %s / %s', label, provider)
                    best[(label, provider, 'provider-error')] = dict(base, cn='Ошибка провайдера',
                        status='Ошибка чтения', error=str(exc), provider_error=True)
                    continue
                for container in containers:
                    if cancel.is_set():
                        break
                    count += 1
                    progress(f'Обработано: {count}; провайдер: {provider}')
                    row = dict(base, container=container)
                    try:
                        details = crypto.read_container_details(provider, prov_type, container, machine, get_store)
                        row.update({key: details[key] for key in ('unique', 'key_spec', 'export', 'cert_in')})
                        row['error'] = '; '.join(dict.fromkeys(details['errors']))
                        der = details['der']
                        if der:
                            thumb = hashlib.sha1(der).hexdigest().upper()
                            if thumb not in cache:
                                cert = x509.load_der_x509_certificate(der)
                                serial = f'{cert.serial_number:X}'
                                cache[thumb] = dict(certificate_dates(cert), **get_certificate_report_fields(cert),
                                                   cn=get_cn_or_subject(cert), serial=serial.zfill(len(serial) + len(serial) % 2))
                            row.update(cache[thumb], thumb=thumb, has_cert=True)
                        else:
                            row['cn'] = '(нет сертификата)' if not row['error'] else 'Ошибка чтения'
                            if row['error']:
                                row['status'] = 'Ошибка чтения'
                    except Exception as exc:
                        row.update(error=str(exc), status='Ошибка чтения', cn='Ошибка чтения')
                        logger.exception('Container read failed: %s / %s / %s', label, provider, container)
                    if row['error']:
                        logger.warning('%s / %s: %s', provider, container, row['error'])
                    # Keep providers separate unless a stable container identity AND certificate agree.
                    identity = row['unique'] or (provider, prov_type, container)
                    key = (label, identity, row['thumb'])
                    if key not in best or rank(row) > rank(best[key]):
                        best[key] = row
    finally:
        for store in stores.values():
            crypto.crypt32.CertCloseStore(store, 0)
    rows = list(best.values())
    logger.info('CSP scan: attempts=%s certificates_parsed=%s rows=%s elapsed=%.2fs cancelled=%s',
                count, len(cache), len(rows), monotonic()-started, cancel.is_set())
    return rows


def scan_files(root, recursive, cancel, progress):
    rows = []
    for path in root.glob('**/*.cer' if recursive else '*.cer'):
        if cancel.is_set():
            break
        if not path.is_file():
            continue
        progress(f'Файлы: обработано {len(rows)}')
        try:
            cert = load_cert_file(path)
            rows.append(dict(certificate_dates(cert), name=get_cn_or_subject(cert), path=str(path), is_error=False))
        except Exception as exc:
            logger.exception('Certificate file read failed: %s', path)
            rows.append(dict(name='Ошибка чтения', path=str(path), start='', end='', status=str(exc),
                             is_expired=False, is_error=True))
    return rows


def scan_stores(scopes, stores, cancel, progress):
    rows = []
    for label, flag in scopes:
        for store in stores:
            if cancel.is_set():
                return rows
            where = f'{label}\\{store}'
            progress(f'Хранилище {where}')
            try:
                with closing(crypto.iter_store_der(store, flag)) as certificates:
                    for der in certificates:
                        if cancel.is_set():
                            return rows
                        try:
                            cert = x509.load_der_x509_certificate(der)
                            rows.append(dict(certificate_dates(cert), where=where, name=get_cn_or_subject(cert),
                                             is_error=False, thumb=hashlib.sha1(der).hexdigest().upper()))
                        except Exception as exc:
                            logger.exception('Certificate parse failed: %s', where)
                            rows.append(dict(where=where, name='Ошибка сертификата', start='', end='',
                                             status=str(exc), is_expired=False, is_error=True))
            except Exception as exc:
                logger.exception('Store read failed: %s', where)
                rows.append(dict(where=where, name='Ошибка чтения', start='', end='',
                                 status=str(exc), is_expired=False, is_error=True))
    return rows
