from __future__ import annotations

from datetime import datetime
from typing import Iterable

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QDialog,
    QGridLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netview.core.analysis import (
    AnalysisCancelled,
    CaptureAnalysis,
    TrafficBucket,
    analyze_capture,
)
from netview.core.pipeline import ProcessedPacket


class AnalysisWorker(QThread):
    analysis_ready = Signal(object)
    analysis_failed = Signal(str)

    def __init__(self, packets: tuple[ProcessedPacket, ...], parent=None):
        super().__init__(parent)
        self.packets = packets

    def run(self) -> None:
        try:
            analysis = analyze_capture(
                self.packets,
                should_stop=self.isInterruptionRequested,
            )
        except AnalysisCancelled:
            return
        except Exception as exc:
            if not self.isInterruptionRequested():
                self.analysis_failed.emit(str(exc))
            return

        if not self.isInterruptionRequested():
            self.analysis_ready.emit(analysis)


def _time_label(timestamp: float) -> str:
    try:
        return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return f"{timestamp:.3g}"


class TrafficTimeline(QWidget):
    def __init__(self, buckets: tuple[TrafficBucket, ...], parent=None):
        super().__init__(parent)
        self.buckets = buckets
        self.setMinimumHeight(240)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#121e27"))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        margin_left, margin_right, margin_top, margin_bottom = 44, 18, 20, 42
        chart = self.rect().adjusted(
            margin_left, margin_top, -margin_right, -margin_bottom
        )

        painter.setPen(QPen(QColor("#30434d"), 1))
        for step in range(5):
            y = chart.bottom() - int(chart.height() * step / 4)
            painter.drawLine(chart.left(), y, chart.right(), y)

        if not self.buckets:
            painter.setPen(QColor("#9eb2bd"))
            painter.drawText(chart, Qt.AlignmentFlag.AlignCenter, "No packet timestamps available")
            painter.end()
            return

        maximum = max((bucket.packet_count for bucket in self.buckets), default=0)
        maximum = max(maximum, 1)
        slot_width = chart.width() / len(self.buckets)
        bar_width = max(2.0, slot_width * 0.68)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#45bfae"))
        for index, bucket in enumerate(self.buckets):
            bar_height = chart.height() * bucket.packet_count / maximum
            x = chart.left() + index * slot_width + (slot_width - bar_width) / 2
            y = chart.bottom() - bar_height
            painter.drawRoundedRect(
                int(x), int(y), max(1, int(bar_width)), max(1, int(bar_height)), 3, 3
            )

        painter.setPen(QColor("#91a5b2"))
        painter.drawText(4, chart.top() + 5, str(maximum))
        painter.drawText(4, chart.bottom(), "0")
        first = _time_label(self.buckets[0].start_timestamp)
        last = _time_label(self.buckets[-1].end_timestamp)
        painter.drawText(chart.left(), chart.bottom() + 28, first)
        painter.drawText(
            chart.right() - 90, chart.bottom() + 28, last
        )
        painter.setPen(QColor("#c5d3d9"))
        painter.drawText(
            chart.left(), 14, "Packets per interval"
        )
        painter.end()


class AnalysisDialog(QDialog):
    packet_requested = Signal(int)

    MAX_TABLE_ROWS = 5000

    def __init__(self, packets: Iterable[ProcessedPacket], parent=None):
        super().__init__(parent)
        self.packets = tuple(packets)
        self.analysis: CaptureAnalysis | None = None
        self._close_pending = False
        self.setWindowTitle("NetView — Analysis center")
        self.resize(1120, 760)
        self.setMinimumSize(860, 580)
        self.setStyleSheet("""
            QDialog { background: #101820; color: #e5edf2; }
            QLabel { color: #e5edf2; }
            QTabWidget::pane { border: 1px solid #293943; border-radius: 8px; }
            QTabBar::tab { background: #17232c; color: #91a5b2; padding: 10px 16px; margin-right: 4px; }
            QTabBar::tab:selected { color: #72e0d0; background: #20343d; border-bottom: 2px solid #56cbbb; }
            QTableWidget { background: #131f28; color: #dce7ec; border: 1px solid #293943; gridline-color: #24343e; selection-background-color: #24504f; }
            QHeaderView::section { background: #1b2a34; color: #91a5b2; border: none; padding: 8px; }
            QProgressBar { background: #1c2b34; border: none; border-radius: 4px; text-align: center; color: #e5edf2; min-height: 16px; }
            QProgressBar::chunk { background: #45bfae; border-radius: 4px; }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        heading = QLabel("CAPTURE ANALYSIS")
        heading.setStyleSheet("color: #72e0d0; font-size: 9pt; font-weight: 700; letter-spacing: 2px;")
        root.addWidget(heading)

        self._root_layout = root
        self._loading_label = QLabel("Analyzing capture…")
        self._loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._loading_label.setStyleSheet("color: #91a5b2; padding: 32px;")
        root.addWidget(self._loading_label)

        self._worker = AnalysisWorker(self.packets, self)
        self._worker.analysis_ready.connect(self._on_analysis_ready)
        self._worker.analysis_failed.connect(self._on_analysis_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_analysis_ready(self, analysis: CaptureAnalysis) -> None:
        if self._close_pending:
            return
        self.analysis = analysis
        self.packets = ()
        self._loading_label.deleteLater()
        self._loading_label = None

        tabs = QTabWidget()
        tabs.addTab(self._overview_page(), "Overview")
        tabs.addTab(self._conversations_page(), "Conversations")
        tabs.addTab(self._tcp_page(), "TCP diagnostics")
        tabs.addTab(self._protocol_page(), "Protocol intelligence")
        tabs.addTab(self._timeline_page(), "Traffic timeline")
        self._root_layout.addWidget(tabs, 1)

        note = QLabel(
            "Analysis covers the full capture, not only displayed rows. "
            "TCP labels are capture-based heuristics; a PCAP alone cannot prove packet loss. "
            "TLS information is handshake metadata only; encrypted application data is not decrypted."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #8297a4; font-size: 8pt;")
        self._root_layout.addWidget(note)

    def _on_analysis_failed(self, message: str) -> None:
        if self._loading_label is not None:
            self._loading_label.setText(f"Analysis failed: {message}")
        self.packets = ()

    def _on_worker_finished(self) -> None:
        self._worker = None
        if self._close_pending:
            self.close()

    def closeEvent(self, event) -> None:
        worker = self._worker
        if worker is not None and not worker.isFinished():
            self._close_pending = True
            worker.requestInterruption()
            if self._loading_label is not None:
                self._loading_label.setText("Cancelling analysis…")
            event.ignore()
            return
        event.accept()

    def _metric_cards(self, values: list[tuple[str, str]]) -> QWidget:
        page = QWidget()
        grid = QGridLayout(page)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)
        for index, (label, value) in enumerate(values):
            card = QWidget()
            card.setStyleSheet("background: #17252e; border: 1px solid #293943; border-radius: 9px;")
            layout = QVBoxLayout(card)
            layout.setContentsMargins(12, 10, 12, 10)
            caption = QLabel(label.upper())
            caption.setStyleSheet("color: #8da2af; font-size: 8pt; font-weight: 700;")
            number = QLabel(value)
            number.setStyleSheet("color: #e9f4f5; font-size: 18pt; font-weight: 700;")
            layout.addWidget(caption)
            layout.addWidget(number)
            grid.addWidget(card, index // 3, index % 3)
        return page

    def _overview_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(14)
        a = self.analysis
        assert a is not None
        layout.addWidget(self._metric_cards([
            ("Packets", f"{a.packet_count:,}"),
            ("Original bytes", self._format_bytes(a.byte_count)),
            ("TCP packets", f"{a.tcp_count:,}"),
            ("UDP packets", f"{a.udp_count:,}"),
            ("Conversations", f"{len(a.conversations):,}"),
            ("Dissection warnings", f"{a.warning_count:,}"),
        ]))

        section = QLabel("Protocol distribution")
        section.setStyleSheet("font-size: 11pt; font-weight: 700;")
        layout.addWidget(section)
        total = max(a.packet_count, 1)
        for name, count in a.protocol_counts[:12]:
            row = QWidget()
            row_layout = QGridLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            name_label = QLabel(name)
            name_label.setMinimumWidth(105)
            bar = QProgressBar()
            bar.setRange(0, total)
            bar.setValue(count)
            bar.setFormat(f"{count:,}  ·  {count / total:.1%}")
            row_layout.addWidget(name_label, 0, 0)
            row_layout.addWidget(bar, 0, 1)
            layout.addWidget(row)

        layout.addWidget(QLabel("Top endpoints by packet appearances"))
        endpoints = self._table(
            ["Endpoint", "Appearances"],
            [(name, f"{count:,}") for name, count in a.endpoint_counts[:10]],
        )
        layout.addWidget(endpoints, 1)
        return page

    def _conversations_page(self) -> QWidget:
        assert self.analysis is not None
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(QLabel("Double-click a conversation to jump to its first packet."))
        rows = []
        for item in self.analysis.conversations[:self.MAX_TABLE_ROWS]:
            duration = (
                max(0.0, item.last_timestamp - item.first_timestamp)
                if item.first_timestamp is not None and item.last_timestamp is not None
                else None
            )
            rows.append((
                item.transport,
                item.endpoint_a,
                item.endpoint_b,
                f"{item.packet_count:,}",
                self._format_bytes(item.byte_count),
                f"{duration:.3f} s" if duration is not None else "—",
                str(item.first_packet_number),
            ))
        table = self._table(
            ["Transport", "Endpoint A", "Endpoint B", "Packets", "Bytes", "Duration", "First frame"],
            rows,
        )
        table.cellDoubleClicked.connect(
            lambda row, _column: self._emit_packet_from_table(table, row, 6)
        )
        layout.addWidget(table, 1)
        if len(self.analysis.conversations) > self.MAX_TABLE_ROWS:
            layout.addWidget(QLabel(
                f"Showing the first {self.MAX_TABLE_ROWS:,} of "
                f"{len(self.analysis.conversations):,} conversations."
            ))
        return page

    def _tcp_page(self) -> QWidget:
        assert self.analysis is not None
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(QLabel(
            "Indicators are heuristic: they describe ordering and repetition in this capture, "
            "not confirmed network faults."
        ))
        rows = [
            (
                str(item.packet_number),
                item.category,
                item.conversation,
                item.detail,
            )
            for item in self.analysis.tcp_diagnostics[:self.MAX_TABLE_ROWS]
        ]
        table = self._table(["Frame", "Indicator", "Conversation", "Details"], rows)
        table.cellDoubleClicked.connect(
            lambda row, _column: self._emit_packet_from_table(table, row, 0)
        )
        layout.addWidget(table, 1)
        if len(self.analysis.tcp_diagnostics) > self.MAX_TABLE_ROWS:
            layout.addWidget(QLabel(
                f"Showing the first {self.MAX_TABLE_ROWS:,} of "
                f"{len(self.analysis.tcp_diagnostics):,} TCP diagnostics."
            ))
        if not rows:
            label = QLabel("No TCP sequence overlaps, out-of-order observations or repeated ACKs were identified.")
            label.setStyleSheet("color: #91a5b2;")
            layout.addWidget(label)
        return page

    def _protocol_page(self) -> QWidget:
        assert self.analysis is not None
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(QLabel(
            "DNS questions and responses, parsed HTTP/1 metadata, TLS handshake metadata and dissection warnings. "
            "Double-click a row to inspect its packet."
        ))
        rows = [
            (
                str(item.packet_number),
                item.protocol,
                item.source,
                item.destination,
                item.detail,
            )
            for item in self.analysis.protocol_events[:self.MAX_TABLE_ROWS]
        ]
        table = self._table(["Frame", "Type", "Source", "Destination", "Details"], rows)
        table.cellDoubleClicked.connect(
            lambda row, _column: self._emit_packet_from_table(table, row, 0)
        )
        layout.addWidget(table, 1)
        if len(self.analysis.protocol_events) > self.MAX_TABLE_ROWS:
            layout.addWidget(QLabel(
                f"Showing the first {self.MAX_TABLE_ROWS:,} of "
                f"{len(self.analysis.protocol_events):,} protocol events."
            ))
        return page

    def _timeline_page(self) -> QWidget:
        assert self.analysis is not None
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(QLabel(
            "Packet count per time interval. Empty intervals are retained; packets without timestamps are excluded."
        ))
        layout.addWidget(TrafficTimeline(self.analysis.traffic_buckets), 1)
        rows = []
        for bucket in self.analysis.traffic_buckets:
            start = _time_label(bucket.start_timestamp)
            end = _time_label(bucket.end_timestamp)
            rows.append((f"{start} – {end}", f"{bucket.packet_count:,}", self._format_bytes(bucket.byte_count)))
        layout.addWidget(self._table(["Interval", "Packets", "Bytes"], rows), 1)
        return page

    @staticmethod
    def _table(headers: list[str], rows: list[tuple[str, ...]]) -> QTableWidget:
        table = QTableWidget(len(rows), len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                if column_index == 0:
                    item.setData(Qt.ItemDataRole.UserRole, value)
                table.setItem(row_index, column_index, item)
        return table

    def _emit_packet_from_table(
        self, table: QTableWidget, row: int, packet_column: int
    ) -> None:
        item = table.item(row, packet_column)
        if item is None:
            return
        try:
            packet_number = int(item.text())
        except ValueError:
            return
        self.packet_requested.emit(packet_number)

    @staticmethod
    def _format_bytes(value: int) -> str:
        size = float(value)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{value:,} B"
