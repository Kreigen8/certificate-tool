import ctypes
import threading
import time
import unittest
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch, Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import certificate_utils as data
import windows_crypto as crypto
import scanning
import enhanced_ui
import cer_tool_gui as gui
import file_operations


def sample_der():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Иванов Иван'),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Школа №1'),
                      x509.NameAttribute(NameOID.TITLE, 'Директор')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(123).not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc)).sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))


class NativeTests(unittest.TestCase):
    def test_export_failure_has_consistent_two_value_contract(self):
        with patch.object(crypto, 'CryptAcquireContextW', return_value=0):
            self.assertEqual(crypto.get_key_exportable('p', 1, 'c', False, 1), (None, None))

    def test_public_key_search_flag_and_context_lifetime(self):
        self.assertEqual(crypto.CERT_FIND_PUBLIC_KEY, 0x60000)
        der = sample_der()
        buf = (ctypes.c_ubyte * len(der)).from_buffer_copy(der)
        cert = crypto.CERT_CONTEXT()
        cert.pbCertEncoded = buf
        cert.cbCertEncoded = len(der)
        ptr = ctypes.cast(ctypes.pointer(cert), ctypes.c_void_p)
        def export(*args):
            args[-1]._obj.value = 64
            return 1
        with patch.object(crypto.crypt32, 'CryptExportPublicKeyInfo', side_effect=export), \
             patch.object(crypto.crypt32, 'CertFindCertificateInStore', return_value=ptr) as find, \
             patch.object(crypto.crypt32, 'CertFreeCertificateContext') as free, \
             patch.object(crypto.crypt32, 'CertCloseStore') as close:
            result = crypto.find_cert_in_my_by_public_key(1, 2, 1, store=99)
            self.assertEqual(result, der)
            self.assertEqual(find.call_args.args[3], 0x60000)
            free.assert_called_once_with(ptr)
            close.assert_not_called()

    def test_one_container_handle_and_fallback_without_name_comparison(self):
        der = sample_der()
        def prov(h, param, buf, size, flags):
            value = b'FAT12\\unique\0'
            size._obj.value = len(value)
            if buf is not None:
                ctypes.memmove(buf, value, len(value))
            return 1
        def key(h, param, buf, size, flags):
            if param == crypto.KP_CERTIFICATE:
                ctypes.set_last_error(ctypes.c_long(0x80090011).value)
                return 0
            ctypes.memmove(buf, b'\x04\0\0\0', 4)
            return 1
        with patch.object(crypto, 'CryptAcquireContextW', return_value=1) as acquire, \
             patch.object(crypto, 'CryptReleaseContext') as release, \
             patch.object(crypto, 'CryptGetProvParam', side_effect=prov), \
             patch.object(crypto, 'CryptGetUserKey', return_value=1), \
             patch.object(crypto, 'CryptGetKeyParam', side_effect=key), \
             patch.object(crypto, 'CryptDestroyKey') as destroy, \
             patch.object(crypto, 'find_cert_in_my_by_public_key', return_value=der):
            result = crypto.read_container_details('p', 1, '{GUID-UNRELATED-TO-CN}', False, lambda scope:99)
            self.assertEqual(result['der'], der)
            self.assertEqual(result['export'], '+')
            self.assertEqual(result['errors'], [])
            acquire.assert_called_once()
            release.assert_called_once()
            destroy.assert_called_once()

    def test_provider_failure_is_not_an_empty_list(self):
        with patch.object(crypto, 'CryptAcquireContextW', return_value=0):
            with self.assertRaises(OSError):
                crypto.enum_csp_containers_for_provider('p', 1, False)

    def test_failed_deletion_does_not_restart_enumeration(self):
        der = sample_der()
        buf = (ctypes.c_ubyte * len(der)).from_buffer_copy(der)
        cert = crypto.CERT_CONTEXT()
        cert.pbCertEncoded = buf
        cert.cbCertEncoded = len(der)
        ptr = ctypes.cast(ctypes.pointer(cert), ctypes.c_void_p)
        import hashlib
        with patch.object(crypto, '_open_system_store', return_value=99), \
             patch.object(crypto.crypt32, 'CertEnumCertificatesInStore', side_effect=[ptr, None]) as enum, \
             patch.object(crypto.crypt32, 'CertDuplicateCertificateContext', return_value=ptr), \
             patch.object(crypto.crypt32, 'CertDeleteCertificateFromStore', return_value=0) as delete, \
             patch.object(crypto.crypt32, 'CertCloseStore'), \
             patch.object(crypto.crypt32, 'CertFreeCertificateContext'):
            self.assertEqual(crypto.delete_from_store_by_thumbprints('MY', 1, {hashlib.sha1(der).hexdigest().upper()}), (0, 1))
            self.assertEqual(enum.call_count, 2)
            delete.assert_called_once()


class ArchiveTests(unittest.TestCase):
    def test_atomic_archive_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'container'
            source.mkdir()
            (source / 'synthetic.key').write_bytes(b'test-data-only')
            target = root / 'backup.zip'
            self.assertEqual(file_operations.zip_folder_with_root(source, target), 1)
            with zipfile.ZipFile(target) as archive:
                self.assertEqual(archive.read('container/synthetic.key'), b'test-data-only')
            before = target.read_bytes()
            with patch.object(file_operations.os, 'replace', side_effect=PermissionError('file open')):
                with self.assertRaises(PermissionError):
                    file_operations.zip_folder_with_root(source, target)
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['backup.zip', 'container'])


class ScanTests(unittest.TestCase):
    def test_cache_error_rows_and_store_lifetime(self):
        der = sample_der()
        def read(provider, kind, container, machine, get_store):
            if container == 'broken':
                raise PermissionError('Access denied')
            get_store(crypto.CERT_SYSTEM_STORE_CURRENT_USER)
            return dict(der=der, unique=container, key_spec=1, export='+', cert_in='+', errors=[])
        with patch.object(crypto, 'enum_csp_providers', return_value=[('p', 1)]), \
             patch.object(crypto, 'enum_csp_containers_for_provider', return_value=['one', 'two', 'broken']), \
             patch.object(crypto, 'read_container_details', side_effect=read), \
             patch.object(crypto, '_open_system_store', return_value=99) as opened, \
             patch.object(crypto.crypt32, 'CertCloseStore') as closed, \
             patch.object(scanning.x509, 'load_der_x509_certificate', wraps=x509.load_der_x509_certificate) as parse:
            rows = scanning.scan_csp([('CurrentUser', False, crypto.CERT_SYSTEM_STORE_CURRENT_USER)], threading.Event(), lambda text:None)
            self.assertEqual(len(rows), 3)
            self.assertEqual(sum(row['has_cert'] for row in rows), 2)
            self.assertEqual(rows[0]['organization'], 'Школа №1')
            self.assertIn('Access denied', rows[2]['error'])
            parse.assert_called_once()
            opened.assert_called_once()
            closed.assert_called_once_with(99, 0)

    def test_cancel_stops_before_next_container(self):
        cancel = threading.Event()
        def read(*args):
            cancel.set()
            return dict(der=None, unique='one', key_spec=None, export='', cert_in='-', errors=[])
        with patch.object(crypto, 'enum_csp_providers', return_value=[('p', 1)]), \
             patch.object(crypto, 'enum_csp_containers_for_provider', return_value=['one', 'two']), \
             patch.object(crypto, 'read_container_details', side_effect=read) as reader:
            rows = scanning.scan_csp([('CurrentUser', False, 1)], cancel, lambda text:None)
            self.assertEqual(len(rows), 1)
            reader.assert_called_once()

    def test_dates_and_filter_boundaries(self):
        at = datetime(2026, 9, 10, tzinfo=timezone.utc)
        cert = SimpleNamespace(not_valid_before_utc=at-timedelta(days=1), not_valid_after_utc=at+timedelta(days=7))
        row = dict(data.certificate_dates(cert, at), has_cert=True, organization='Школа', position='Директор')
        self.assertEqual(row['days_left'], 7)
        self.assertTrue(data.matches_csp_filter(row, 'ДИРЕКТОР', '7 дней'))
        self.assertFalse(data.matches_csp_filter(row, '', 'Просроченные'))
        cert.not_valid_before_utc = at+timedelta(days=1)
        future = dict(data.certificate_dates(cert, at), has_cert=True)
        self.assertEqual(future['status'], 'Еще не действует')
        self.assertFalse(data.matches_csp_filter(future, '', '7 дней'))
        cert.not_valid_before_utc = at-timedelta(days=30)
        cert.not_valid_after_utc = at-timedelta(seconds=1)
        expired = dict(data.certificate_dates(cert, at), has_cert=True)
        self.assertTrue(data.matches_csp_filter(expired, '', 'Просроченные'))
        self.assertFalse(data.matches_csp_filter(expired, '', '7 дней'))
        self.assertFalse(data.matches_csp_filter(dict(has_cert=False, error='Access denied')))
        self.assertTrue(data.matches_csp_filter(dict(has_cert=False, error='Access denied'), show_nocert=True))
        self.assertFalse(data.matches_csp_filter(dict(has_cert=False)))


class UiTests(unittest.TestCase):
    def setUp(self):
        self.warning = patch.object(gui.messagebox, 'showwarning').start()
        self.app = gui.App()
        self.app.withdraw()

    def tearDown(self):
        self.app._close_app()
        patch.stopall()

    def pump(self, condition, timeout=3):
        end = time.monotonic() + timeout
        while not condition() and time.monotonic() < end:
            self.app.update()
            time.sleep(.01)
        self.assertTrue(condition())

    def test_background_cancel_keeps_ui_alive_and_finishes_on_main_thread(self):
        main = threading.get_ident()
        worker_ids, done_ids = [], []
        def work(cancel, progress):
            worker_ids.append(threading.get_ident())
            progress('Working')
            cancel.wait(2)
            return ['partial']
        self.assertTrue(self.app._run_job('Test', work, lambda rows:done_ids.append(threading.get_ident())))
        self.assertFalse(self.app._run_job('Duplicate', work, lambda rows:None))
        self.pump(lambda: bool(worker_ids))
        tick = []
        self.app.after(10, lambda:tick.append(True))
        self.pump(lambda: bool(tick))
        self.app._cancel_job()
        self.pump(lambda: not self.app._busy)
        self.assertNotEqual(worker_ids[0], main)
        self.assertEqual(done_ids, [main])
        self.assertIn('частичный результат', self.app.status_var.get())
        self.assertEqual(self.app.job_progress.winfo_manager(), '')
        self.assertEqual(float(self.app.job_progress['value']), 0)

    def test_progress_visible_only_while_running_and_resets_after_error(self):
        progressbar = self.app.job_progress
        self.assertEqual(progressbar.winfo_manager(), '')
        for fail in (False, True):
            with self.subTest(fail=fail), patch.object(enhanced_ui.messagebox, 'showerror') as error:
                release = threading.Event()
                def work(cancel, progress):
                    release.wait(2)
                    if fail:
                        raise RuntimeError('Synthetic test failure')
                    return []
                self.assertTrue(self.app._run_job('Progress test', work, lambda rows:None))
                self.assertEqual(progressbar.winfo_manager(), 'pack')
                self.pump(lambda: float(progressbar['value']) > 1)
                release.set()
                self.pump(lambda: not self.app._busy)
                self.assertEqual(progressbar.winfo_manager(), '')
                self.assertEqual(float(progressbar['value']), 0)
                self.assertTrue(self.app.cancel_button.instate(['disabled']))
                self.assertEqual(error.call_count, int(fail))

    def test_report_and_delete_scope_and_numeric_sort(self):
        self.app.csp_rows = [dict(container=str(i), cn=name, provider='p', scope='CurrentUser',
                                 has_cert=True, is_expired=True, days_left=days, organization='Школа')
                             for i, (name, days) in enumerate([('Первый', -2), ('Второй', -10), ('Скрытый', -1)])]
        self.app._render_csp_filtered()
        self.app.tree_csp.detach('csp_2')
        self.app.tree_csp.selection_set('csp_1')
        self.assertEqual([r['cn'] for r in self.app._deletion_candidates(True)], ['Второй'])
        self.assertEqual([r['cn'] for r in self.app._deletion_candidates(False)], ['Второй'])
        self.assertEqual([r['cn'] for r in self.app._report_rows()], ['Первый', 'Второй'])
        self.app._sort_tree(self.app.tree_csp, 'days_left', self.app.sort_state_csp, self.app.csp_col_types)
        self.assertEqual(self.app.tree_csp.get_children()[0], 'csp_1')
        self.app.search_csp_var.set('школа')
        self.assertEqual(self.app.tree_csp.get_children()[0], 'csp_1')
        self.app.search_csp_var.set('Второй')
        self.assertEqual([r['cn'] for r in self.app._report_rows()], ['Второй'])

    def test_nocert_checkbox_hides_read_errors_without_rescanning(self):
        self.app.csp_rows = [
            dict(cn='Сертификат прочитан', has_cert=True),
            dict(cn='Сертификат с предупреждением', has_cert=True, error='Не прочитаны права экспорта'),
            dict(cn='Без сертификата', has_cert=False),
            dict(cn='Ошибка чтения', has_cert=False, error='Access denied'),
            dict(cn='Ошибка провайдера', has_cert=False, error='Provider unavailable', provider_error=True),
        ]
        with patch.object(enhanced_ui, 'scan_csp') as scan:
            self.app._render_csp_filtered()
            self.assertEqual(self.app.tree_csp.get_children(), ('csp_0', 'csp_1'))
            self.app.csp_show_nocert_var.set(True)
            self.assertEqual(len(self.app.tree_csp.get_children()), 5)
            self.app.csp_show_nocert_var.set(False)
            self.assertEqual(self.app.tree_csp.get_children(), ('csp_0', 'csp_1'))
            scan.assert_not_called()

    def test_deletion_preview_contains_only_selection_and_no_scope_selector(self):
        self.app.csp_rows = [dict(container=str(i), cn=name, has_cert=True, is_expired=expired)
                             for i, (name, expired) in enumerate([
                                 ('Выделен действующий', False), ('Выделен просроченный', True),
                                 ('Не выделен', True)])]
        self.app._render_csp_filtered()
        self.app.tree_csp.selection_set('csp_0', 'csp_1')
        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)
        with patch.object(self.app, '_delete_csp_rows') as delete:
            for expired_only, expected in [(False, ['Выделен действующий', 'Выделен просроченный']),
                                            (True, ['Выделен просроченный'])]:
                self.app._preview_delete(expired_only)
                dialog = next(child for child in self.app.winfo_children() if isinstance(child, gui.tk.Toplevel))
                widgets = list(descendants(dialog))
                self.assertFalse(any(isinstance(widget, gui.ttk.Combobox) for widget in widgets))
                tree = next(widget for widget in widgets if isinstance(widget, gui.ttk.Treeview))
                self.assertEqual([tree.set(iid, 'cn') for iid in tree.get_children()], expected)
                confirm = next(widget for widget in widgets if isinstance(widget, gui.ttk.Button)
                               and widget.cget('text') == 'Удалить перечисленные контейнеры')
                confirm.invoke()
                self.assertEqual([row['cn'] for row in delete.call_args.args[0]], expected)
            delete.reset_mock()
            self.app.tree_csp.selection_remove(*self.app.tree_csp.selection())
            with patch.object(enhanced_ui.messagebox, 'showinfo') as info:
                self.app.csp_delete_selected()
                self.app.csp_delete_expired()
                self.assertEqual(info.call_count, 2)
            self.assertFalse(any(isinstance(child, gui.tk.Toplevel) for child in self.app.winfo_children()))
            delete.assert_not_called()


if __name__ == '__main__':
    unittest.main()
