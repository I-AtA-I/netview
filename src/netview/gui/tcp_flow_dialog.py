from __future__ import annotations

from PySide6.QtCore import Qt, QPoint, QRect, QSize
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPolygon
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netview.core.tcp_flow import TCPFlowGraph


class TCPFlowGraphCanvas(QWidget):
    ROW_HEIGHT = 78
    TOP_MARGIN = 105
    BOTTOM_MARGIN = 34

    def __init__(self, graph: TCPFlowGraph, parent=None):
        super().__init__(parent)
        self.graph = graph
        self.setMinimumWidth(1080)
        self.setMinimumHeight(
            self.TOP_MARGIN + len(graph.events) * self.ROW_HEIGHT + self.BOTTOM_MARGIN
        )

    def sizeHint(self) -> QSize:
        return QSize(
            1080,
            self.TOP_MARGIN + len(self.graph.events) * self.ROW_HEIGHT + self.BOTTOM_MARGIN,
        )

    def minimumSizeHint(self) -> QSize:
        return self.sizeHint()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#101820"))

        width = max(self.width(), 1080)
        lane_a = 120
        lane_b = width - 120
        center = (lane_a + lane_b) // 2

        painter.setPen(QColor("#8297a4"))
        painter.setFont(QFont("Noto Sans", 8, QFont.Weight.Bold))
        painter.drawText(
            QRect(14, 20, lane_a + 18, 58),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            str(self.graph.key.endpoint_a),
        )
        painter.drawText(
            QRect(lane_b - 18, 20, width - lane_b + 4, 58),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            str(self.graph.key.endpoint_b),
        )

        painter.setPen(QPen(QColor("#344650"), 1, Qt.PenStyle.DashLine))
        painter.drawLine(lane_a, 82, lane_a, self.height() - 18)
        painter.drawLine(lane_b, 82, lane_b, self.height() - 18)

        for index, event in enumerate(self.graph.events):
            y = self.TOP_MARGIN + index * self.ROW_HEIGHT
            source_x = lane_a if event.direction == 0 else lane_b
            destination_x = lane_b if event.direction == 0 else lane_a
            if event.possible_overlap:
                color = QColor("#e5a15a")
            elif "RST" in event.flags:
                color = QColor("#e18b91")
            elif "SYN" in event.flags or "FIN" in event.flags:
                color = QColor("#86a9e8")
            else:
                color = QColor("#45bfae")

            painter.setPen(QPen(color, 2))
            painter.drawLine(source_x, y, destination_x, y)
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(QPoint(source_x, y), 5, 5)
            if destination_x > source_x:
                arrow = QPolygon([
                    QPoint(destination_x, y),
                    QPoint(destination_x - 12, y - 7),
                    QPoint(destination_x - 12, y + 7),
                ])
            else:
                arrow = QPolygon([
                    QPoint(destination_x, y),
                    QPoint(destination_x + 12, y - 7),
                    QPoint(destination_x + 12, y + 7),
                ])
            painter.drawPolygon(arrow)

            card = QRect(center - 250, y - 30, 500, 60)
            painter.setPen(QPen(QColor("#344650"), 1))
            painter.setBrush(QColor("#17252e"))
            painter.drawRoundedRect(card, 7, 7)

            elapsed = (
                f"+{event.elapsed_seconds:.6f}s"
                if event.elapsed_seconds is not None
                else "time unavailable"
            )
            painter.setPen(QColor("#e5edf2"))
            painter.setFont(QFont("Noto Sans", 8, QFont.Weight.Bold))
            painter.drawText(
                QRect(card.left() + 10, card.top() + 5, 155, 18),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                f"Frame #{event.packet_number}  {elapsed}",
            )

            details = f"Seq {event.sequence_number}"
            if event.acknowledgment_number is not None:
                details += f"   Ack {event.acknowledgment_number}"
            details += f"   Len {event.payload_length}"
            painter.setPen(QColor("#c5d3d9"))
            painter.setFont(QFont("monospace", 8))
            painter.drawText(
                QRect(card.left() + 10, card.top() + 25, card.width() - 20, 16),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                details,
            )

            status = ",".join(event.flags) or "no flags"
            if event.possible_overlap:
                status += "  ·  possible overlap"
            if event.truncated:
                status += "  ·  truncated"
            painter.setPen(color if event.possible_overlap or event.truncated else QColor("#91a5b2"))
            painter.setFont(QFont("Noto Sans", 7))
            painter.drawText(
                QRect(card.left() + 10, card.top() + 42, card.width() - 20, 14),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                status,
            )

        painter.end()


class TCPFlowGraphDialog(QDialog):
    def __init__(self, graph: TCPFlowGraph, parent=None):
        super().__init__(parent)
        self.graph = graph
        self.setWindowTitle("NetView — TCP Flow Graph")
        self.resize(1240, 820)
        self.setMinimumSize(900, 600)
        self.setStyleSheet("""
            QDialog { background: #101820; color: #e5edf2; }
            QLabel { color: #dce7ec; }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        heading = QLabel("TCP FLOW GRAPH")
        heading.setStyleSheet(
            "color: #72e0d0; font-size: 9pt; font-weight: 700; letter-spacing: 2px;"
        )
        root.addWidget(heading)

        duration = (
            f"{graph.duration_seconds:.6f} s"
            if graph.duration_seconds is not None
            else "timestamps unavailable"
        )
        self.summary_label = QLabel(
            f"{graph.key.endpoint_a}  ↔  {graph.key.endpoint_b}\n"
            f"{graph.packet_count:,} packets  ·  {duration}  ·  "
            f"{graph.overlap_count:,} possible overlap(s)"
        )
        summary = self.summary_label
        summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        summary.setStyleSheet(
            "background: #17252e; border: 1px solid #293943; border-radius: 8px;"
            "padding: 10px; color: #dce7ec;"
        )
        root.addWidget(summary)

        legend = QLabel(
            "Teal · packet  |  Blue · SYN / FIN  |  Orange · possible sequence overlap  |  Red · RST"
        )
        legend.setStyleSheet("color: #91a5b2; font-size: 8pt; padding: 2px 4px;")
        root.addWidget(legend)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setStyleSheet(
            "QScrollArea { background: #101820; }"
            "QScrollBar:vertical { background: #17252e; width: 12px; }"
            "QScrollBar::handle:vertical { background: #405762; border-radius: 5px; min-height: 24px; }"
            "QScrollBar:horizontal { background: #17252e; height: 12px; }"
            "QScrollBar::handle:horizontal { background: #405762; border-radius: 5px; min-width: 24px; }"
        )
        self.canvas = TCPFlowGraphCanvas(graph)
        scroll.setWidget(self.canvas)
        root.addWidget(scroll, 1)

        note = QLabel(
            "Possible overlap is inferred from repeated TCP sequence ranges in capture order; "
            "it is a heuristic, not proof of packet loss or retransmission."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #8297a4; font-size: 8pt;")
        root.addWidget(note)
