from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
)

from netview.core.streams import ReassembledDirection, TCPStream


class TCPStreamDialog(QDialog):
    def __init__(self, stream: TCPStream, parent=None):
        super().__init__(parent)
        self.stream = stream
        self.setWindowTitle(f"Follow TCP Stream — #{stream.stream_id}")
        self.resize(1050, 680)
        self.setMinimumSize(760, 480)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        summary = QLabel(
            f"<b>Stream #{stream.stream_id}</b><br>"
            f"{stream.key.endpoint_a} &nbsp; ↔ &nbsp; {stream.key.endpoint_b}<br>"
            f"{stream.packet_count:,} TCP packets · "
            f"{stream.payload_length:,} captured payload bytes"
        )
        summary.setTextFormat(Qt.TextFormat.RichText)
        summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(summary)

        tabs = QTabWidget()
        endpoint_a, endpoint_b = stream.key.endpoint_a, stream.key.endpoint_b
        tabs.addTab(
            self._direction_view(stream.directions[0]),
            f"{endpoint_a} → {endpoint_b}",
        )
        tabs.addTab(
            self._direction_view(stream.directions[1]),
            f"{endpoint_b} → {endpoint_a}",
        )
        layout.addWidget(tabs, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _direction_view(self, direction: ReassembledDirection) -> QPlainTextEdit:
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        view.setFont(QFont("monospace", 9))
        view.setPlainText(self._format_direction(direction))
        return view

    @classmethod
    def _format_direction(cls, direction: ReassembledDirection) -> str:
        lines = [
            (
                f"{direction.packet_count:,} packets · "
                f"{direction.payload_segment_count:,} payload segments · "
                f"{direction.payload_length:,} bytes reconstructed"
            )
        ]

        if direction.overlapping_bytes:
            lines.append(
                f"[Note: {direction.overlapping_bytes:,} overlapping/retransmitted "
                "payload bytes were observed.]"
            )

        if direction.truncated_packet_numbers:
            packet_numbers = ", ".join(
                str(number) for number in direction.truncated_packet_numbers[:20]
            )
            if len(direction.truncated_packet_numbers) > 20:
                packet_numbers += ", …"
            lines.append(
                "[Warning: payload was truncated in packet(s): "
                f"{packet_numbers}.]"
            )

        if not direction.chunks:
            lines.append("\nNo TCP application payload was captured in this direction.")
            return "\n".join(lines)

        gaps_by_start = {gap.end_offset: gap for gap in direction.gaps}
        for index, chunk in enumerate(direction.chunks):
            if index:
                gap = gaps_by_start.get(chunk.sequence_offset)
                if gap is not None:
                    lines.extend([
                        "",
                        (
                            f"[MISSING DATA: {gap.length:,} bytes between sequence "
                            f"offsets {gap.start_offset} and {gap.end_offset}.]"
                        ),
                        "",
                    ])
            lines.extend(cls._format_hex(chunk.data, chunk.sequence_offset))

        if direction.gaps:
            lines.append(
                f"\n{len(direction.gaps):,} sequence gap(s) detected. "
                "Missing bytes have not been fabricated."
            )

        return "\n".join(lines)

    @staticmethod
    def _format_hex(data: bytes, base_offset: int) -> list[str]:
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_part = "".join(
                chr(byte) if 32 <= byte <= 126 else "."
                for byte in chunk
            )
            lines.append(
                f"{base_offset + offset:08x}  {hex_part:<47}  |{ascii_part}|"
            )
        return lines
