from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from netview.core.pipeline import ProcessedPacket
from netview.core.request_replay import RequestReplayError, send_loopback_request


_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}


def _safe_request(payload: bytes) -> tuple[str, bool]:
    text = payload.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    safe_lines = []
    removed = False
    in_headers = True

    for line in lines:
        if in_headers and not line:
            in_headers = False
            safe_lines.append(line)
            continue
        if in_headers and ":" in line:
            name = line.split(":", 1)[0].strip().lower()
            if name in _SENSITIVE_HEADERS:
                removed = True
                continue
        safe_lines.append(line)

    return "\r\n".join(safe_lines), removed


class RequestLabDialog(QDialog):
    def __init__(self, packet: ProcessedPacket, parent=None):
        super().__init__(parent)
        message = packet.dissection.http
        if message is None or not message.is_request:
            raise ValueError("Select an HTTP request packet first")

        self.setWindowTitle("HTTP Request Lab")
        self.resize(900, 700)
        self.setMinimumSize(680, 500)

        layout = QVBoxLayout(self)
        note = QLabel(
            "Requests are sent to this machine only (127.0.0.1 / ::1). "
            "Captured credentials are removed from the editor."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        target_form = QFormLayout()
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setPlaceholderText("127.0.0.1 or ::1")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(packet.destination_port or 80)
        target_form.addRow("Local target", self.host_input)
        target_form.addRow("Port", self.port_input)
        layout.addLayout(target_form)

        self.request_editor = QPlainTextEdit()
        self.request_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        request_text, removed = _safe_request(packet.dissection.payload)
        self.request_editor.setPlainText(request_text)
        layout.addWidget(QLabel("HTTP request"))
        layout.addWidget(self.request_editor, 2)

        self.response_view = QPlainTextEdit()
        self.response_view.setReadOnly(True)
        self.response_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(QLabel("Response (max 256 KiB)"))
        layout.addWidget(self.response_view, 1)

        if removed:
            layout.addWidget(QLabel("Cookie and authorization headers were stripped."))

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.send_button = QPushButton("Send to localhost")
        self.send_button.clicked.connect(self.send_request)
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        buttons.addWidget(self.send_button)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)

    def send_request(self) -> None:
        request = self.request_editor.toPlainText().replace("\r\n", "\n").replace("\n", "\r\n")
        try:
            response = send_loopback_request(
                self.host_input.text(),
                self.port_input.value(),
                request.encode("iso-8859-1", errors="replace"),
            )
        except RequestReplayError as exc:
            QMessageBox.warning(self, "Request not sent", str(exc))
            return

        self.response_view.setPlainText(
            response.decode("iso-8859-1", errors="replace")
            if response else "(No response data received)"
        )
