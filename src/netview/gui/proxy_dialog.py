from pathlib import Path
import shutil

from PySide6.QtCore import QProcess, QTimer
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QPlainTextEdit,
    QVBoxLayout,
)

from netview.core.proxy import HTTPProxy, ProxyError


class HTTPMessageDialog(QDialog):
    def __init__(self, entry, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{entry.method} · {entry.url}")
        self.resize(900, 650)
        layout = QVBoxLayout(self)
        summary = QLabel(
            f"Status: {entry.status if entry.status is not None else 'Failed'}"
            f"    ·    Request body: {entry.request_bytes} B"
            f"    ·    Response body: {entry.response_bytes} B"
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)
        warning = QLabel(
            "Captured messages may contain cookies or authorization data. "
            "They are kept in memory only; clear history or close NetView to discard them."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        tabs = QTabWidget()
        for title, raw in (
            ("Request", entry.request_message),
            ("Response", entry.response_message),
        ):
            view = QPlainTextEdit()
            view.setReadOnly(True)
            view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            view.setPlainText(raw.decode("utf-8", "replace") if raw else entry.note or "No message captured.")
            tabs.addTab(view, title)
        layout.addWidget(tabs)


class ProxyDialog(QDialog):
    def __init__(self, proxy: HTTPProxy, parent=None):
        super().__init__(parent)
        self.proxy = proxy
        self.setWindowTitle("NetView HTTP Proxy")
        self.resize(1050, 620)
        self.setMinimumSize(760, 440)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Local HTTP proxy for browser traffic. HTTPS uses an opaque CONNECT tunnel "
            "for now; its encrypted contents are not inspected."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Listen port"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(proxy.port or 8080)
        controls.addWidget(self.port_input)
        self.start_button = QPushButton("Start proxy")
        self.start_button.clicked.connect(self.start_proxy)
        self.stop_button = QPushButton("Stop proxy")
        self.stop_button.clicked.connect(self.stop_proxy)
        self.browser_button = QPushButton("Launch Chromium")
        self.browser_button.clicked.connect(self.launch_chromium)
        self.clear_button = QPushButton("Clear history")
        self.clear_button.clicked.connect(self.clear_history)
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.browser_button)
        controls.addWidget(self.clear_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.state_label = QLabel("Proxy stopped · binds to 127.0.0.1 only")
        self.state_label.setWordWrap(True)
        layout.addWidget(self.state_label)

        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(
            ["Time", "Method", "URL / target", "Status", "Request", "Response"]
        )
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.cellDoubleClicked.connect(self.show_entry)
        self.history_table.setAlternatingRowColors(True)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setColumnWidth(0, 105)
        self.history_table.setColumnWidth(1, 85)
        self.history_table.setColumnWidth(2, 450)
        self.history_table.setColumnWidth(3, 75)
        layout.addWidget(self.history_table, 1)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(500)
        self.refresh_timer.timeout.connect(self.refresh_history)
        self.refresh_timer.start()
        if self.proxy.running:
            host, port = self.proxy.address
            self.state_label.setText(
                f"Running on http://{host}:{port} · configure Chromium to use this proxy"
            )
        self._update_state()

    def start_proxy(self) -> None:
        if self.proxy.running:
            return
        self.proxy.port = self.port_input.value()
        try:
            host, port = self.proxy.start()
        except ProxyError as exc:
            QMessageBox.critical(self, "Proxy could not start", str(exc))
            return
        self.state_label.setText(
            f"Running on http://{host}:{port} · configure Chromium to use this proxy"
        )
        self._update_state()

    def stop_proxy(self) -> None:
        self.proxy.stop()
        self.state_label.setText("Proxy stopped")
        self._update_state()

    def launch_chromium(self) -> None:
        if not self.proxy.running:
            return
        browser = next(
            (shutil.which(name) for name in ("chromium", "chromium-browser", "google-chrome")
             if shutil.which(name)),
            None,
        )
        if browser is None:
            QMessageBox.information(
                self, "Chromium not found",
                "Install Chromium or configure your browser manually to use "
                f"http://127.0.0.1:{self.proxy.address[1]}",
            )
            return

        profile = Path.home() / ".cache" / "netview" / "chromium-proxy-profile"
        profile.mkdir(parents=True, exist_ok=True)
        port = self.proxy.address[1]
        arguments = [
            f"--user-data-dir={profile}",
            f"--proxy-server=http://127.0.0.1:{port}",
            "--proxy-bypass-list=<-loopback>",
            "--no-first-run",
            "--new-window",
            "http://neverssl.com",
        ]
        if not QProcess.startDetached(browser, arguments):
            QMessageBox.warning(self, "Chromium could not start", "Could not launch Chromium.")

    def show_entry(self, row: int, _column: int) -> None:
        entries = self.proxy.history
        if 0 <= row < len(entries):
            HTTPMessageDialog(entries[row], self).exec()

    def clear_history(self) -> None:
        self.proxy.clear_history()
        self.refresh_history()

    def refresh_history(self) -> None:
        entries = self.proxy.history
        self.history_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            values = (
                f"{entry.timestamp:.3f}",
                entry.method,
                entry.url,
                str(entry.status) if entry.status is not None else entry.note,
                f"{entry.request_bytes} B",
                f"{entry.response_bytes} B",
            )
            for column, value in enumerate(values):
                self.history_table.setItem(row, column, QTableWidgetItem(value))
        if entries:
            self.history_table.scrollToBottom()

    def _update_state(self) -> None:
        running = self.proxy.running
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.browser_button.setEnabled(running)
        self.port_input.setEnabled(not running)

    def closeEvent(self, event) -> None:
        self.refresh_timer.stop()
        event.accept()
