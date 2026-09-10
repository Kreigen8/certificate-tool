"""GUI workflows. Workers return data; only the UI thread accesses Tk."""
import os
import queue
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from certificate_utils import matches_csp_filter, parse_date
from csp_report import write_csp_report
from diagnostics import logger, configure_logging
from scanning import scan_csp, scan_files, scan_stores
from file_operations import find_container_folder_on_removable, build_container_zip_name, safe_output_path, zip_folder_with_root
import windows_crypto as crypto


class EnhancedAppMixin:
    def destroy(self):
        self._closing = True
        if hasattr(self, '_worker_cancel'):
            self._worker_cancel.set()
        for name in ('_poll_id', '_startup_warning_id'):
            timer = getattr(self, name, None)
            if timer:
                self.after_cancel(timer)
                setattr(self, name, None)
        super().destroy()

    def init_workflows(self):
        self._busy = False
        self._closing = False
        self._poll_id = None
        self._progress_text = ''
        self._worker_cancel = threading.Event()
        self._events = queue.Queue()
        self.log_path = configure_logging()
        self.protocol('WM_DELETE_WINDOW', self._close_app)

    def build_job_bar(self):
        bar = ttk.Frame(self, padding=(10, 3))
        bar.pack(fill='x', side='bottom')
        self.job_progress = ttk.Progressbar(bar, mode='indeterminate', length=180)
        self.cancel_button = ttk.Button(bar, text='Отменить загрузку', command=self._cancel_job, state='disabled')
        self.cancel_button.pack(side='left', padx=8)
        ttk.Button(bar, text='Журнал ошибок', command=self._open_log).pack(side='right')

    def _open_log(self):
        if self.log_path:
            try:
                os.startfile(self.log_path)
            except OSError as exc:
                messagebox.showerror('Журнал', str(exc), parent=self)

    def _close_app(self):
        if self._busy and not self._job_cancellable:
            messagebox.showinfo('Операция выполняется', 'Дождитесь завершения операции перед закрытием.', parent=self)
            return
        self._closing = True
        self._worker_cancel.set()
        if self._poll_id:
            self.after_cancel(self._poll_id)
            self._poll_id = None
        self.destroy()

    def _set_busy(self, busy):
        self._busy = busy
        if busy:
            self._disabled_widgets = []
            def visit(widget):
                for child in widget.winfo_children():
                    if isinstance(child, (ttk.Button, ttk.Checkbutton)):
                        if not child.instate(['disabled']):
                            self._disabled_widgets.append(child)
                            child.state(['disabled'])
                    visit(child)
            for tab in (self.tab_files, self.tab_store, self.tab_csp):
                visit(tab)
            self.job_progress.configure(value=0)
            self.job_progress.pack(side='left', before=self.cancel_button)
            self.job_progress.start(15)
            self.cancel_button.state(['!disabled'])
        else:
            for child in self._disabled_widgets:
                if child.winfo_exists():
                    child.state(['!disabled'])
            self.job_progress.stop()
            self.job_progress.configure(value=0)
            self.job_progress.pack_forget()
            self.cancel_button.state(['disabled'])

    def _cancel_job(self):
        self._worker_cancel.set()
        self.cancel_button.state(['disabled'])
        self.status_var.set('Отмена запрошена. Ожидание завершения текущего обращения к провайдеру…')

    def _run_job(self, title, work, done, cancellable=True):
        if self._busy:
            return False
        self._worker_cancel = threading.Event()
        self._job_cancellable = cancellable
        self._progress_text = title
        self._job_started = time.monotonic()
        self._set_busy(True)
        if not cancellable:
            self.cancel_button.state(['disabled'])
        self.status_var.set(title)
        self._job_done = done
        def worker():
            try:
                result = work(self._worker_cancel, lambda text: setattr(self, '_progress_text', text))
                self._events.put(('done', result))
            except Exception as exc:
                logger.exception('Background operation failed: %s', title)
                self._events.put(('error', str(exc)))
        threading.Thread(target=worker, name='certificate-worker', daemon=True).start()
        self._poll_id = self.after(100, self._poll_job)
        return True

    def _poll_job(self):
        self._poll_id = None
        if self._closing:
            return
        try:
            kind, result = self._events.get_nowait()
        except queue.Empty:
            if not self._worker_cancel.is_set():
                self.status_var.set(self._progress_text)
            self._poll_id = self.after(100, self._poll_job)
            return
        self._set_busy(False)
        if kind == 'error':
            self.status_var.set('Операция завершилась с ошибкой. Подробности в журнале.')
            messagebox.showerror('Ошибка', result, parent=self)
        else:
            self._job_done(result)
            elapsed = time.monotonic() - self._job_started
            suffix = ' Загрузка отменена; показан частичный результат.' if self._worker_cancel.is_set() else ''
            self.status_var.set(self.status_var.get() + f' Время: {elapsed:.1f} с.' + suffix)

    def files_show(self):
        root = Path(self.path_var.get()).expanduser()
        if not root.is_dir():
            messagebox.showerror('Ошибка', 'Папка не найдена.', parent=self)
            return
        recursive = self.recurse_var.get()
        def done(rows):
            self.files_rows = rows
            self._render_files_filtered()
            self.status_var.set(f'Файлы: {len(rows)}, ошибок: {sum(r["is_error"] for r in rows)}.')
        self._run_job('Чтение файлов…', lambda cancel, progress: scan_files(root, recursive, cancel, progress), done)

    def store_show(self):
        scopes, stores = self._get_selected_store_scopes_and_stores()
        if not scopes or not stores:
            messagebox.showinfo('Опции', 'Выберите область и хотя бы одно хранилище.', parent=self)
            return
        def done(rows):
            self.store_rows = rows
            self._render_store_filtered()
            self.status_var.set(f'Хранилища: {len(rows)}, ошибок: {sum(r["is_error"] for r in rows)}.')
        self._run_job('Чтение хранилищ…', lambda cancel, progress: scan_stores(scopes, stores, cancel, progress), done)

    def csp_show(self):
        scopes = self._get_csp_scopes()
        if not scopes:
            messagebox.showinfo('Опции', 'Выберите CurrentUser или LocalMachine.', parent=self)
            return
        def done(rows):
            self.tree_csp.selection_remove(*self.tree_csp.selection())
            self.csp_rows = rows
            self._render_csp_filtered()
        self._run_job('Поиск контейнеров…', lambda cancel, progress: scan_csp(scopes, cancel, progress), done)

    def _render_csp_filtered(self):
        if not hasattr(self, 'tree_csp'):
            return
        selected_ids = set(self.tree_csp.selection())
        self._clear_tree(self.tree_csp)
        shown = 0
        for index, row in enumerate(self.csp_rows):
            iid = f'csp_{index}'
            if self.tree_csp.exists(iid):
                self.tree_csp.delete(iid)
            row['_iid'] = iid
            if not matches_csp_filter(row, self.search_csp_var.get(), show_nocert=self.csp_show_nocert_var.get()):
                continue
            if row.get('error'):
                tag = 'error'
            elif row.get('is_expired'):
                tag = 'expired'
            elif row.get('is_future'):
                tag = 'future'
            elif row.get('has_cert') and row.get('days_left') is not None and row['days_left'] <= 30:
                tag = 'soon'
            elif not row.get('has_cert'):
                tag = 'nocert'
            else:
                tag = ''
            values = [row.get(col, '') for col in self.tree_csp['columns']]
            values = ['' if value is None else value for value in values]
            self.tree_csp.insert('', 'end', iid=iid, values=values, tags=(tag,) if tag else ())
            if iid in selected_ids:
                self.tree_csp.selection_add(iid)
            shown += 1
        if getattr(self, '_csp_sort', None):
            col, reverse = self._csp_sort
            self.sort_state_csp[col] = reverse
            self._sort_tree(self.tree_csp, col, self.sort_state_csp, self.csp_col_types)
        errors = sum(bool(row.get('error')) for row in self.csp_rows)
        self.status_var.set(f'Контейнеры: показано {shown} из {len(self.csp_rows)}; строк с ошибками: {errors}.')

    def _report_rows(self):
        iids = self.tree_csp.get_children('')
        return self._csp_rows_by_iids(iids)

    def csp_report(self):
        if self._busy:
            return
        rows = [row for row in self._report_rows() if row.get('has_cert')]
        if not rows:
            messagebox.showinfo('Отчет', 'В показанном списке нет сертификатов. Загрузите контейнеры и проверьте поиск.', parent=self)
            return
        filename = filedialog.asksaveasfilename(parent=self, title='Сохранить отчет по ЭЦП',
            defaultextension='.xlsx', filetypes=[('Книга Excel', '*.xlsx')],
            initialfile=f'Реестр_сроков_ЭЦП_{datetime.now():%Y-%m-%d}.xlsx')
        if not filename:
            return
        try:
            count = write_csp_report(filename, rows)
        except Exception as exc:
            logger.exception('Report export failed')
            messagebox.showerror('Отчет', f'Не удалось сохранить отчет.\n{exc}', parent=self)
            return
        self.status_var.set(f'Отчет сохранен: {filename}. Записей: {count}.')
        messagebox.showinfo('Отчет', f'Отчет сохранен:\n{filename}\n\nЗаписей: {count}.', parent=self)

    def _csp_details(self, event=None):
        if event is not None:
            iid = self.tree_csp.identify_row(event.y)
            rows = self._csp_rows_by_iids([iid]) if iid else []
        else:
            rows = self._csp_rows_by_iids(self.tree_csp.selection())
        if not rows:
            return
        dialog = tk.Toplevel(self)
        dialog.title('Сведения о контейнере')
        dialog.geometry('850x550')
        text = tk.Text(dialog, wrap='word', padx=12, pady=12)
        text.pack(fill='both', expand=True)
        row = rows[0]
        for col in self.tree_csp['columns']:
            value = row.get(col, '')
            if value is not None and value != '':
                text.insert('end', f'{self.tree_csp.heading(col, "text")}: {value}\n\n')
        text.configure(state='disabled')
        ttk.Button(dialog, text='Закрыть', command=dialog.destroy).pack(pady=8)

    def _deletion_candidates(self, expired_only):
        selected = set(self.tree_csp.selection())
        visible = [iid for iid in self.tree_csp.get_children('') if iid in selected]
        rows = self._csp_rows_by_iids(visible)
        return [row for row in rows if not row.get('provider_error') and row.get('container')
                and (not expired_only or row.get('is_expired'))]

    def csp_delete_expired(self):
        self._preview_delete(True)

    def csp_delete_selected(self):
        self._preview_delete(False)

    def _preview_delete(self, expired_only):
        if self._busy:
            return
        if not self.csp_rows:
            messagebox.showinfo('Удаление', 'Сначала загрузите контейнеры.', parent=self)
            return
        if not self.tree_csp.selection():
            messagebox.showinfo('Удаление', 'Выделите контейнеры в основной таблице.', parent=self)
            return
        candidates = self._deletion_candidates(expired_only)
        if not candidates:
            messagebox.showinfo('Удаление',
                'Среди выделенных нет просроченных контейнеров.' if expired_only
                else 'Среди выделенных нет контейнеров для удаления.', parent=self)
            return
        dialog = tk.Toplevel(self)
        dialog.title('Просмотр списка перед удалением')
        dialog.geometry('1000x520')
        dialog.transient(self)
        ttk.Label(dialog, text='Удаление контейнера удаляет закрытый ключ. Проверьте каждый объект в списке.',
                  padding=10).pack(fill='x')
        frame = ttk.Frame(dialog)
        frame.pack(fill='both', expand=True, padx=10)
        tree = ttk.Treeview(frame, columns=('cn', 'container', 'scope', 'provider', 'end'), show='headings')
        for key, title in zip(tree['columns'], ('Владелец', 'Контейнер', 'Область', 'Провайдер', 'Окончание')):
            tree.heading(key, text=title)
            tree.column(key, width=180, stretch=True)
        tree.pack(side='left', fill='both', expand=True)
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        scrollbar.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar.set)
        footer = ttk.Frame(dialog, padding=10)
        footer.pack(fill='x')
        ttk.Label(footer, text=f'Контейнеров к удалению: {len(candidates)}').pack(side='left')
        for row in candidates:
            tree.insert('', 'end', values=[row.get(key, '') for key in tree['columns']])
        def confirm():
            rows = list(candidates)
            dialog.destroy()
            self._delete_csp_rows(rows)
        ttk.Button(footer, text='Отмена', command=dialog.destroy).pack(side='right')
        execute = ttk.Button(footer, text='Удалить перечисленные контейнеры', command=confirm)
        execute.pack(side='right', padx=10)
        dialog.grab_set()

    def _delete_csp_rows(self, rows):
        def work(cancel, progress):
            removed, errors = [], []
            for index, row in enumerate(rows, 1):
                progress(f'Удаление: {index} из {len(rows)}')
                try:
                    if not crypto.delete_container(row['provider'], row['prov_type'], row['container'], row['machine']):
                        raise crypto.crypto_error('Удаление контейнера')
                    removed.append(row)
                    logger.info('Deleted container: %s / %s', row['provider'], row['container'])
                except Exception as exc:
                    errors.append(f'{row["container"]}: {exc}')
                    logger.exception('Container deletion failed: %s', row['container'])
            return removed, errors
        def done(result):
            removed, errors = result
            self.tree_csp.selection_remove(*self.tree_csp.selection())
            self.csp_rows = [row for row in self.csp_rows if row not in removed]
            self._render_csp_filtered()
            self.status_var.set(f'Удалено: {len(removed)}; ошибок: {len(errors)}.')
            if errors:
                messagebox.showerror('Удаление', '\n'.join(errors[:20]), parent=self)
        self._run_job('Удаление контейнеров…', work, done, cancellable=False)

    def _csp_zip_selected_container(self):
        if self._busy:
            return
        rows = self._csp_rows_by_iids(self.tree_csp.selection())
        if not rows:
            return
        if not self._csp_can_zip_rows(rows):
            messagebox.showinfo('ZIP', 'Выберите контейнеры на флешке с сертификатами и сроками действия.', parent=self)
            return
        def work(cancel, progress):
            created, errors = [], []
            for index, row in enumerate(rows, 1):
                progress(f'Архивация: {index} из {len(rows)}')
                try:
                    source = find_container_folder_on_removable(row.get('unique', ''), row.get('container', ''))
                    if not source:
                        raise OSError('Папка контейнера не найдена на подключенной флешке')
                    target = safe_output_path(source.parent, build_container_zip_name(row['cn'], row['end']), '.zip')
                    count = zip_folder_with_root(source, target)
                    created.append(str(target))
                    logger.info('Archive saved: %s; files=%s', target, count)
                except Exception as exc:
                    errors.append(f'{row["container"]}: {exc}')
                    logger.exception('Archive failed: %s', row['container'])
            return created, errors
        def done(result):
            created, errors = result
            self.status_var.set(f'ZIP: создано {len(created)}, ошибок {len(errors)}.')
            detail = '\n'.join(created[:20])
            if errors:
                detail += '\n\nОшибки:\n' + '\n'.join(errors[:20])
            messagebox.showinfo('ZIP', self.status_var.get() + '\n\n' + detail, parent=self)
        self._run_job('Архивация контейнеров…', work, done, cancellable=False)
