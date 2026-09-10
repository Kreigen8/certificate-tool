"""Portable XLSX export for the CSP register (no Excel installation required)."""

import os
import re
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape


HEADERS = ("№", "Наименование учреждения", "Должность", "ФИО", "Срок действия ЭЦП")
_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _text_cell(ref, value, style):
    # Certificate attributes are literal text, including leading '=' characters.
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]", "", str(value or ""))[:32767]
    return (f'<c r="{ref}" s="{style}" t="inlineStr"><is>'
            f'<t xml:space="preserve">{escape(text)}</t></is></c>')


def write_csp_report(path, rows):
    """Save one row per certificate in caller order; return exported row count."""
    rows = [row for row in rows if row.get("has_cert")]
    if not rows:
        raise ValueError("Нет сертификатов для отчета.")
    if len(rows) > 1048575:
        raise ValueError("Слишком много строк для одного листа Excel.")
    sheet_rows = ['<row r="1" ht="34" customHeight="1">' + ''.join(
        _text_cell(f'{col}1', title, 1) for col, title in zip('ABCDE', HEADERS)
    ) + '</row>']
    for number, row in enumerate(rows, 1):
        r = number + 1
        texts = [row.get("organization", ""), row.get("position", ""), row.get("full_name", "")]
        # Leave enough height for long institution names and job titles.
        lines = max([1] + [sum(max(1, (len(line) + width - 1) // width)
                               for line in str(value or "").split('\n'))
                           for value, width in zip(texts, (48, 30, 32))])
        cells = [f'<c r="A{r}" s="3"><v>{number}</v></c>']
        cells.extend(_text_cell(f'{col}{r}', value, 2) for col, value in zip('BCD', texts))
        end = row.get("end", "")
        if end:
            date = datetime.strptime(end, "%Y-%m-%d")
            serial = (date - datetime(1899, 12, 30)).days
            cells.append(f'<c r="E{r}" s="4"><v>{serial}</v></c>')
        else:
            cells.append(_text_cell(f'E{r}', '', 3))
        sheet_rows.append(f'<row r="{r}" ht="{min(409, max(30, lines * 16 + 8))}" customHeight="1">'
                          + ''.join(cells) + '</row>')
    last = len(rows) + 1
    worksheet = f'''<worksheet xmlns="{_NS}">
<dimension ref="A1:E{last}"/>
<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<sheetFormatPr defaultRowHeight="30"/>
<cols><col min="1" max="1" width="7" customWidth="1"/><col min="2" max="2" width="55" customWidth="1"/><col min="3" max="3" width="36" customWidth="1"/><col min="4" max="4" width="38" customWidth="1"/><col min="5" max="5" width="24" customWidth="1"/></cols>
<sheetData>{''.join(sheet_rows)}</sheetData><autoFilter ref="A1:E{last}"/>
<pageMargins left="0.25" right="0.25" top="0.5" bottom="0.5" header="0.2" footer="0.2"/>
<pageSetup paperSize="9" orientation="landscape"/>
</worksheet>'''
    styles = f'''<styleSheet xmlns="{_NS}">
<numFmts count="1"><numFmt numFmtId="164" formatCode="dd.mm.yyyy"/></numFmts>
<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFD9E5F2"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border/><border><left style="thin"><color rgb="FFB8C4D0"/></left><right style="thin"><color rgb="FFB8C4D0"/></right><top style="thin"><color rgb="FFB8C4D0"/></top><bottom style="thin"><color rgb="FFB8C4D0"/></bottom></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="5">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
<xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>
</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'''
    parts = {
        '[Content_Types].xml': '''<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>''',
        '_rels/.rels': '''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>''',
        'xl/workbook.xml': f'''<workbook xmlns="{_NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="ЭЦП" sheetId="1" r:id="rId1"/></sheets></workbook>''',
        'xl/_rels/workbook.xml.rels': '''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>''',
        'xl/worksheets/sheet1.xml': worksheet,
        'xl/styles.xml': styles,
    }
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix='.xlsx', delete=False) as f:
            temporary = Path(f.name)
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, content in parts.items():
                archive.writestr(name, '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + content)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return len(rows)
