from datetime import datetime

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont

from netview.core.pipeline import ProcessedPacket
from netview.filters import CompiledFilter, compile_filter


class PacketTableModel(QAbstractTableModel):
    HEADERS = (
        "No.",
        "Time",
        "Source",
        "Destination",
        "Protocol",
        "Length",
        "Info",
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: list[ProcessedPacket] = []
        self._visible: list[ProcessedPacket] = []
        self._filter: CompiledFilter | None = None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._visible)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal and 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]

        if orientation == Qt.Orientation.Vertical:
            return str(section + 1)

        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._visible)):
            return None

        packet = self._visible[index.row()]

        if role == Qt.ItemDataRole.DisplayRole:
            values = (
                packet.number,
                self._format_timestamp(packet.timestamp),
                packet.source,
                packet.destination,
                packet.protocol,
                packet.length,
                packet.info,
            )
            if 0 <= index.column() < len(values):
                return str(values[index.column()])

        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 4:
            colors = {
                "TCP": "#72c8e8",
                "UDP": "#72e0d0",
                "DNS": "#c6a6f2",
                "mDNS": "#c6a6f2",
                "LLMNR": "#c6a6f2",
                "HTTP": "#e8bd75",
                "TLS": "#8fb8ff",
                "ARP": "#d7a7e8",
                "ICMP": "#e59b86",
                "ICMPv6": "#e59b86",
                "IPv6": "#80c9c0",
            }
            return QColor("#e58d91" if packet.dissection.errors else colors.get(packet.protocol, "#a9bac3"))

        if role == Qt.ItemDataRole.FontRole and index.column() == 4:
            font = QFont()
            font.setWeight(QFont.Weight.DemiBold)
            return font

        if role == Qt.ItemDataRole.ToolTipRole:
            return (
                f"Packet {packet.number}\n"
                f"Captured: {packet.captured_length} bytes\n"
                f"Original: {packet.length} bytes\n"
                f"Link type: {packet.record.link_type}"
            )

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if index.column() in (0, 5):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        return None

    @staticmethod
    def _format_timestamp(timestamp: float | None) -> str:
        if timestamp is None:
            return "—"
        try:
            return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")
        except (OverflowError, OSError, ValueError):
            return str(timestamp)

    def append_packets(self, packets: list[ProcessedPacket]) -> None:
        if not packets:
            return

        first = len(self._packets)
        last = first + len(packets) - 1
        self.beginInsertRows(QModelIndex(), first, last)
        self._packets.extend(packets)
        if self._filter is None:
            self._visible.extend(packets)
        else:
            self._visible.extend(
                packet for packet in packets if self._filter.matches(packet)
            )
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._packets.clear()
        self._visible.clear()
        self._filter = None
        self.endResetModel()

    def apply_filter(self, expression: str) -> int:
        expression = expression.strip()
        compiled = compile_filter(expression) if expression else None
        visible = (
            self._packets
            if compiled is None
            else [packet for packet in self._packets if compiled.matches(packet)]
        )

        self.beginResetModel()
        self._filter = compiled
        self._visible = list(visible)
        self.endResetModel()
        return len(self._visible)

    def packet_at(self, row: int) -> ProcessedPacket | None:
        if 0 <= row < len(self._visible):
            return self._visible[row]
        return None

    def iter_packets(self):
        """Iterate over all captured packets, regardless of display filter."""
        return iter(self._packets)

    @property
    def total_count(self) -> int:
        return len(self._packets)

    @property
    def visible_count(self) -> int:
        return len(self._visible)
