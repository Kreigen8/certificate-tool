import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.x509.oid import NameOID

import cer_tool_gui as gui
import enhanced_ui
from csp_report import HEADERS, write_csp_report


class ReportTests(unittest.TestCase):
    def test_subject_fields_and_name_fallback(self):
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Учреждение «Тест»'),
            x509.NameAttribute(NameOID.TITLE, 'Директор'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'Другой CN'),
            x509.NameAttribute(NameOID.SURNAME, 'Иванов'),
            x509.NameAttribute(NameOID.GIVEN_NAME, 'Иван Иванович'),
        ])
        fields = gui.get_certificate_report_fields(SimpleNamespace(subject=subject))
        self.assertEqual(fields, dict(organization='Учреждение «Тест»', position='Директор',
                                      full_name='Иванов Иван Иванович'))
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Петров Петр')])
        self.assertEqual(gui.get_certificate_report_fields(SimpleNamespace(subject=subject)),
                         dict(organization='', position='', full_name='Петров Петр'))

    def test_xlsx_content_dates_and_literal_text(self):
        rows = [dict(has_cert=False),
                dict(has_cert=True, organization='=1+1 & <Тест>\x01', position='Директор',
                     full_name='Иванов Иван Иванович', end='2026-09-10'),
                dict(has_cert=True, end='')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.xlsx'
            self.assertEqual(write_csp_report(path, rows), 2)
            with zipfile.ZipFile(path) as archive:
                self.assertIsNone(archive.testzip())
                for name in archive.namelist():
                    ET.fromstring(archive.read(name))
                sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
            ns = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
            self.assertEqual([x.text for x in sheet.findall('.//s:row[@r="1"]//s:t', ns)], list(HEADERS))
            self.assertEqual(sheet.find('.//s:c[@r="B2"]//s:t', ns).text, '=1+1 & <Тест>')
            self.assertEqual(sheet.find('.//s:c[@r="B2"]', ns).get('t'), 'inlineStr')
            self.assertEqual(sheet.find('.//s:c[@r="E2"]/s:v', ns).text, '46275')
            self.assertEqual(sheet.find('s:autoFilter', ns).get('ref'), 'A1:E3')
            self.assertEqual(sheet.find('.//s:pane', ns).get('state'), 'frozen')
            self.assertEqual(len(sheet.findall('.//s:row', ns)), 3)
            before = path.read_bytes()
            with patch('csp_report.os.replace', side_effect=PermissionError('file open')):
                with self.assertRaises(PermissionError):
                    write_csp_report(path, rows)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(directory).iterdir()), [path])
            with self.assertRaises(ValueError):
                write_csp_report(path, [dict(has_cert=False)])
            self.assertEqual(path.read_bytes(), before)

    def test_button_exports_visible_order_cancel_and_error(self):
        with patch.object(gui.messagebox, 'showwarning'), \
             patch.object(gui.messagebox, 'showinfo') as info, \
             patch.object(gui.messagebox, 'showerror') as error, \
             patch.object(gui.filedialog, 'asksaveasfilename') as save, \
             patch.object(enhanced_ui, 'write_csp_report', return_value=2) as writer:
            app = gui.App()
            app.withdraw()
            try:
                app.csp_report_button.invoke()
                save.assert_not_called()
                info.assert_called_once()
                base = dict(scope='CurrentUser', provider='Test', container='container',
                            start='2026-01-01', end='2026-09-10', status=gui.STATUS_VALID,
                            has_cert=True)
                app.csp_rows = [dict(base, cn='Первый'), dict(base, cn='Второй'),
                                dict(base, cn='Скрытый'), dict(base, cn='Первый без сертификата', has_cert=False)]
                app._render_csp_filtered()
                # Restrict the displayed rows, then change their order in the table.
                app.search_csp_var.set('Первый')
                save.return_value = ''
                app.csp_report_button.invoke()
                writer.assert_not_called()
                app.search_csp_var.set('')
                iids = app.tree_csp.get_children('')
                app.tree_csp.detach(iids[2])
                app.tree_csp.move(iids[1], '', 0)
                save.return_value = 'test.xlsx'
                app.csp_report_button.invoke()
                self.assertEqual([row['cn'] for row in writer.call_args.args[1]], ['Второй', 'Первый'])
                self.assertIn('Записей: 2', app.status_var.get())
                writer.side_effect = PermissionError('file open')
                app.csp_report_button.invoke()
                error.assert_called_once()
            finally:
                app.destroy()


if __name__ == '__main__':
    unittest.main()
