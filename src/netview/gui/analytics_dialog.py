from datetime import datetime
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHeaderView,
    QLabel,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from netview.core.analytics import analyze_capture
from netview.core.pipeline import ProcessedPacket


class AnalyticsDialog(QDialog):
    def __init__(self, packets: tuple[ProcessedPacket, ...], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Capture analytics")
        self.resize(900, 620)
        stats = analyze_capture(packets)

        layout = QVBoxLayout(self)
        summary = QLabel(
            f"<b>{stats.packet_count:,}</b> packets · "
            f"<b>{stats.wire_bytes:,}</b> bytes on wire · "
            f"<b>{stats.duration:.3f}s</b> duration"
        )
        summary.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(summary)

        tabs = QTabWidget()
        tabs.addTab(self._table(
            ("Protocol", "Packets", "Bytes"),
            ((item.protocol, item.packets, item.bytes) for item in stats.protocols),
        ), "Protocols")
        tabs.addTab(self._table(
            ("Endpoint", "Packets", "Bytes"),
            ((item.endpoint, item.packets, item.bytes) for item in stats.top_talkers),
        ), "Top talkers")
        tabs.addTab(self._table(
            ("Protocol", "Endpoint A", "Endpoint B", "Packets", "Bytes"),
            ((item.protocol, item.endpoint_a, item.endpoint_b, item.packets, item.bytes)
             for item in stats.conversations),
        ), "Conversations")
        tabs.addTab(self._table(
            ("Time", "Packets", "Bytes"),
            ((datetime.fromtimestamp(item.timestamp).strftime("%H:%M:%S"),
              item.packets, item.bytes) for item in stats.timeline),
        ), "Timeline")
        layout.addWidget(tabs)

    @staticmethod
    def _table(headers, rows) -> QTableWidget:
        values = list(rows)
        table = QTableWidget(len(values), len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        for row, values_row in enumerate(values):
            for column, value in enumerate(values_row):
                table.setItem(row, column, QTableWidgetItem(str(value)))
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table
