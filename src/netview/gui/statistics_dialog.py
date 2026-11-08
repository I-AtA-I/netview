from collections import Counter

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netview.core.pipeline import ProcessedPacket


class StatisticsDialog(QDialog):
    def __init__(self, packets: list[ProcessedPacket], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Capture statistics")
        self.resize(980, 680)
        self.setMinimumSize(760, 520)
        self.setStyleSheet("""
            QDialog { background: #101820; color: #e5edf2; }
            QLabel { color: #e5edf2; }
            QTabWidget::pane { border: 1px solid #293943; border-radius: 8px; }
            QTabBar::tab { background: #17232c; color: #91a5b2; padding: 10px 18px; margin-right: 4px; }
            QTabBar::tab:selected { color: #72e0d0; background: #20343d; border-bottom: 2px solid #56cbbb; }
            QTableWidget { background: #131f28; color: #dce7ec; border: 1px solid #293943; gridline-color: #24343e; }
            QHeaderView::section { background: #1b2a34; color: #91a5b2; border: none; padding: 9px; }
            QProgressBar { background: #1c2b34; border: none; border-radius: 4px; text-align: center; color: #e5edf2; min-height: 16px; }
            QProgressBar::chunk { background: #45bfae; border-radius: 4px; }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 20)
        root.setSpacing(16)

        heading = QLabel("CAPTURE OVERVIEW")
        heading.setStyleSheet("color: #72e0d0; font-size: 9pt; font-weight: 700; letter-spacing: 2px;")
        root.addWidget(heading)

        protocols = Counter(packet.protocol for packet in packets)
        endpoints = Counter()
        ports = Counter()
        for packet in packets:
            endpoints[packet.source] += 1
            endpoints[packet.destination] += 1
            if packet.source_port is not None:
                ports[packet.source_port] += 1
            if packet.destination_port is not None:
                ports[packet.destination_port] += 1

        tcp_count = sum(packet.dissection.tcp is not None for packet in packets)
        udp_count = sum(packet.dissection.udp is not None for packet in packets)
        warning_count = sum(bool(packet.dissection.errors) for packet in packets)
        total_bytes = sum(packet.length for packet in packets)

        metrics = QGridLayout()
        metrics.setSpacing(10)
        values = [
            ("PACKETS", f"{len(packets):,}"),
            ("CAPTURED DATA", self._format_bytes(total_bytes)),
            ("TCP", f"{tcp_count:,}"),
            ("UDP", f"{udp_count:,}"),
            ("DISSECTION WARNINGS", f"{warning_count:,}"),
        ]
        for index, (label, value) in enumerate(values):
            card = QWidget()
            card.setStyleSheet("background: #17252e; border: 1px solid #293943; border-radius: 9px;")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 12, 14, 12)
            caption = QLabel(label)
            caption.setStyleSheet("color: #8da2af; font-size: 8pt; font-weight: 700;")
            number = QLabel(value)
            number.setStyleSheet("color: #e9f4f5; font-size: 19pt; font-weight: 700;")
            card_layout.addWidget(caption)
            card_layout.addWidget(number)
            metrics.addWidget(card, 0, index)
        root.addLayout(metrics)

        tabs = QTabWidget()
        tabs.addTab(self._protocol_view(protocols, len(packets)), "Protocols")
        tabs.addTab(self._table_view("Endpoint", "Packet appearances", endpoints.most_common(30)), "Endpoints")
        tabs.addTab(self._table_view("Port", "Packet appearances", ports.most_common(30)), "Ports")
        root.addWidget(tabs, 1)

        note = QLabel("Endpoint counts include both source and destination appearances. Statistics cover the full capture, not only filtered rows.")
        note.setStyleSheet("color: #8297a4; font-size: 8pt;")
        note.setWordWrap(True)
        root.addWidget(note)

    def _protocol_view(self, counts: Counter, total: int) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        for name, count in counts.most_common():
            row = QHBoxLayout()
            label = QLabel(name)
            label.setMinimumWidth(110)
            label.setStyleSheet("font-weight: 600;")
            bar = QProgressBar()
            bar.setRange(0, max(total, 1))
            bar.setValue(count)
            bar.setFormat(f"{count:,}  ·  {count / total:.1%}" if total else "0")
            row.addWidget(label)
            row.addWidget(bar, 1)
            layout.addLayout(row)
        layout.addStretch(1)
        return page

    def _table_view(self, first_header: str, second_header: str, rows: list[tuple]) -> QTableWidget:
        table = QTableWidget(len(rows), 2)
        table.setHorizontalHeaderLabels([first_header, second_header])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.horizontalHeader().setStretchLastSection(True)
        for row_index, (name, count) in enumerate(rows):
            table.setItem(row_index, 0, QTableWidgetItem(str(name)))
            item = QTableWidgetItem(f"{count:,}")
            item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            table.setItem(row_index, 1, item)
        return table

    @staticmethod
    def _format_bytes(value: int) -> str:
        size = float(value)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{value:,} B"
