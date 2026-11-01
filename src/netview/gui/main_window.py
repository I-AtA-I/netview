from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont, QKeySequence
from PySide6.QtWidgets import (
    QFileDialog,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netview.capture import LiveCaptureError, list_interfaces
from netview.core.dissector import ETHERTYPE_NAMES
from netview.capture.export import CaptureExportError, export_capture
from netview.gui.analytics_dialog import AnalyticsDialog
from netview.gui.request_lab import RequestLabDialog
from netview.core.proxy import HTTPProxy
from netview.gui.proxy_dialog import ProxyDialog
from netview.core.tls import cipher_suite_name, tls_version_name
from netview.core.pipeline import ProcessedPacket
from netview.core.streams import tcp_stream_key_for_packet
from netview.filters import FilterSyntaxError
from netview.gui.table_model import PacketTableModel

from .live_worker import LiveCaptureWorker
from .stream_dialog import TCPStreamDialog
from .stream_worker import TCPStreamWorker
from .worker import CaptureLoadWorker


APP_STYLE = """
QMainWindow, QWidget {
    background: #15131b;
    color: #e7e2ed;
    font-family: "Inter", "Noto Sans", sans-serif;
    font-size: 10pt;
}
QMenuBar, QMenu {
    background: #1c1923;
    color: #e7e2ed;
}
QMenuBar::item:selected, QMenu::item:selected {
    background: #393047;
}
QToolBar {
    background: #1c1923;
    border: none;
    spacing: 8px;
    padding: 7px;
}
QLineEdit, QPlainTextEdit, QTreeWidget, QTableView {
    background: #100e15;
    color: #e7e2ed;
    border: 1px solid #302a3a;
    border-radius: 5px;
    selection-background-color: #49385f;
    selection-color: #ffffff;
}
QLineEdit {
    padding: 8px 10px;
}
QLineEdit:focus, QPlainTextEdit:focus, QTreeWidget:focus, QTableView:focus {
    border: 1px solid #9275b8;
}
QPushButton {
    background: #30283b;
    color: #eee8f6;
    border: 1px solid #493d59;
    border-radius: 5px;
    padding: 7px 13px;
}
QPushButton:hover {
    background: #40344f;
}
QPushButton:pressed {
    background: #514064;
}
QPushButton:disabled {
    color: #77717f;
    background: #211e27;
}
QHeaderView::section {
    background: #211d29;
    color: #c9bfd7;
    border: none;
    border-right: 1px solid #302a3a;
    border-bottom: 1px solid #393142;
    padding: 8px 7px;
    font-weight: 600;
}
QTableView {
    gridline-color: #282330;
    alternate-background-color: #17141e;
}
QTableView::item {
    padding: 5px;
}
QTreeWidget::item {
    padding: 3px;
}
QStatusBar {
    background: #1c1923;
    color: #aaa1b5;
    border-top: 1px solid #302a3a;
}
QSplitter::handle {
    background: #302a3a;
}
QSplitter::handle:horizontal {
    width: 4px;
}
QSplitter::handle:vertical {
    height: 4px;
}
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetView — Network Protocol Analyzer")
        self.resize(1440, 900)
        self.setMinimumSize(980, 620)
        self.setStyleSheet(APP_STYLE)
        self.setAcceptDrops(True)

        self.model = PacketTableModel(self)
        self._worker: CaptureLoadWorker | None = None
        self._live_worker: LiveCaptureWorker | None = None
        self._live_interface: str | None = None
        self._live_capture_error = False
        self._current_path: Path | None = None
        self._selected_packet: ProcessedPacket | None = None
        self._stream_worker: TCPStreamWorker | None = None
        self.proxy = HTTPProxy()

        self._build_actions()
        self._build_ui()
        self.refresh_interfaces()
        self._update_capture_controls()
        self._update_counts()

    def _build_actions(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        self.open_action = QAction("Open capture…", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(self.open_capture_dialog)
        file_menu.addAction(self.open_action)

        self.close_action = QAction("Close capture", self)
        self.close_action.setShortcut(QKeySequence("Ctrl+W"))
        self.close_action.triggered.connect(self.close_capture)
        file_menu.addAction(self.close_action)

        self.export_action = QAction("Export capture as…", self)
        self.export_action.setShortcut(QKeySequence("Ctrl+Shift+S"))
        self.export_action.triggered.connect(self.export_capture_dialog)
        self.export_action.setEnabled(False)
        file_menu.addAction(self.export_action)

        capture_menu = self.menuBar().addMenu("&Capture")
        self.start_capture_action = QAction("Start live capture", self)
        self.start_capture_action.triggered.connect(self.start_live_capture)
        capture_menu.addAction(self.start_capture_action)

        self.stop_capture_action = QAction("Stop live capture", self)
        self.stop_capture_action.triggered.connect(self.stop_live_capture)
        capture_menu.addAction(self.stop_capture_action)

        analyze_menu = self.menuBar().addMenu("&Analyze")
        self.analytics_action = QAction("Capture analytics…", self)
        self.analytics_action.triggered.connect(self.show_analytics)
        self.analytics_action.setEnabled(False)
        analyze_menu.addAction(self.analytics_action)

        self.proxy_action = QAction("HTTP Proxy…", self)
        self.proxy_action.triggered.connect(self.open_proxy)
        analyze_menu.addAction(self.proxy_action)

        self.request_lab_action = QAction("HTTP Request Lab…", self)
        self.request_lab_action.triggered.connect(self.open_request_lab)
        self.request_lab_action.setEnabled(False)
        analyze_menu.addAction(self.request_lab_action)
        analyze_menu.addSeparator()

        self.follow_stream_action = QAction("Follow TCP Stream", self)
        self.follow_stream_action.setShortcut(QKeySequence("Ctrl+Shift+T"))
        self.follow_stream_action.triggered.connect(self.follow_tcp_stream)
        self.follow_stream_action.setEnabled(False)
        analyze_menu.addAction(self.follow_stream_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def _build_ui(self) -> None:
        central = QWidget(self)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(9)

        heading = QHBoxLayout()
        title = QLabel("NetView")
        title.setStyleSheet("font-size: 18pt; font-weight: 700; color: #f0eaf8;")
        subtitle = QLabel("NETWORK PROTOCOL ANALYZER")
        subtitle.setStyleSheet("font-size: 8pt; letter-spacing: 1px; color: #9b8eaa;")
        heading.addWidget(title)
        heading.addSpacing(10)
        heading.addWidget(subtitle)
        heading.addStretch(1)

        self.file_label = QLabel("No capture loaded")
        self.file_label.setStyleSheet("color: #a99db7;")
        self.file_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        heading.addWidget(self.file_label)
        root.addLayout(heading)

        capture_row = QHBoxLayout()
        capture_row.setSpacing(8)
        capture_label = QLabel("Interface")
        capture_label.setStyleSheet("color: #bdb2ca; font-weight: 600;")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(220)
        self.interface_combo.setToolTip(
            "Select one local interface you own or are authorized to monitor."
        )
        self.refresh_interfaces_button = QPushButton("Refresh")
        self.refresh_interfaces_button.clicked.connect(self.refresh_interfaces)
        self.start_capture_button = QPushButton("Start capture")
        self.start_capture_button.clicked.connect(self.start_live_capture)
        self.stop_capture_button = QPushButton("Stop")
        self.stop_capture_button.clicked.connect(self.stop_live_capture)
        self.capture_state_label = QLabel("Live capture stopped · promiscuous mode off")
        self.capture_state_label.setStyleSheet("color: #847a90; font-size: 9pt;")
        capture_row.addWidget(capture_label)
        capture_row.addWidget(self.interface_combo)
        capture_row.addWidget(self.refresh_interfaces_button)
        capture_row.addWidget(self.start_capture_button)
        capture_row.addWidget(self.stop_capture_button)
        capture_row.addWidget(self.capture_state_label, 1)
        root.addLayout(capture_row)

        filter_row = QHBoxLayout()
        filter_label = QLabel("Display filter")
        filter_label.setStyleSheet("color: #bdb2ca; font-weight: 600;")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(
            "e.g. tcp.port == 443 or dns.qry.name == example.com"
        )
        self.filter_input.returnPressed.connect(self.apply_filter)
        self.apply_button = QPushButton("Apply")
        self.apply_button.clicked.connect(self.apply_filter)
        self.clear_filter_button = QPushButton("Clear")
        self.clear_filter_button.clicked.connect(self.clear_filter)
        self.follow_stream_button = QPushButton("Follow TCP Stream")
        self.follow_stream_button.setToolTip(
            "Reassemble both directions of the selected IPv4/TCP conversation (Ctrl+Shift+T)."
        )
        self.follow_stream_button.clicked.connect(self.follow_tcp_stream)
        self.follow_stream_button.setEnabled(False)
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.filter_input, 1)
        filter_row.addWidget(self.apply_button)
        filter_row.addWidget(self.clear_filter_button)
        filter_row.addWidget(self.follow_stream_button)
        root.addLayout(filter_row)

        self.filter_status = QLabel("Filters: dns, http, tls, arp, ipv6, tcp, udp, icmp, app metadata, addresses, ports")
        self.filter_status.setStyleSheet("color: #847a90; font-size: 9pt;")
        root.addWidget(self.filter_status)

        self.packet_table = QTableView()
        self.packet_table.setModel(self.model)
        self.packet_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setShowGrid(False)
        self.packet_table.setSortingEnabled(False)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setColumnWidth(0, 70)
        self.packet_table.setColumnWidth(1, 145)
        self.packet_table.setColumnWidth(2, 170)
        self.packet_table.setColumnWidth(3, 170)
        self.packet_table.setColumnWidth(4, 100)
        self.packet_table.setColumnWidth(5, 85)
        self.packet_table.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )

        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Packet details", "Value"])
        self.details_tree.setColumnWidth(0, 255)
        self.details_tree.setAlternatingRowColors(True)

        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setPlaceholderText("Select a packet to inspect its bytes.")
        self.hex_view.setFont(QFont("monospace", 9))

        lower_splitter = QSplitter(Qt.Orientation.Horizontal)
        lower_splitter.addWidget(self.details_tree)
        lower_splitter.addWidget(self.hex_view)
        lower_splitter.setStretchFactor(0, 1)
        lower_splitter.setStretchFactor(1, 1)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(self.packet_table)
        main_splitter.addWidget(lower_splitter)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 2)
        main_splitter.setSizes([540, 300])
        root.addWidget(main_splitter, 1)

        self.setCentralWidget(central)
        self.count_status = QLabel("0 displayed / 0 total")
        self.count_status.setStyleSheet("color: #b7a9c7; padding: 0 8px;")
        self.statusBar().addPermanentWidget(self.count_status)
        self.statusBar().showMessage("Ready — open a PCAP or PCAPNG file")


    def export_capture_dialog(self) -> None:
        if not self.model.total_count:
            return

        filename, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export capture",
            str(Path.home() / "capture.pcap"),
            "PCAP (*.pcap);;CSV (*.csv);;JSON (*.json)",
        )
        if not filename:
            return

        path = Path(filename).expanduser()
        if not path.suffix:
            extension = selected_filter.partition("*.")[2].partition(")")[0]
            if extension:
                path = path.with_suffix(f".{extension}")

        try:
            count = export_capture(path, self.model.iter_packets())
        except (OSError, CaptureExportError) as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return

        self.statusBar().showMessage(f"Exported {count:,} packets to {path.name}")
        QMessageBox.information(
            self,
            "Export complete",
            f"Exported {count:,} packets to {path}",
        )

    def show_analytics(self) -> None:
        packets = tuple(self.model.iter_packets())
        if not packets:
            return
        AnalyticsDialog(packets, self).exec()

    def open_proxy(self) -> None:
        ProxyDialog(self.proxy, self).exec()

    def open_request_lab(self) -> None:
        packet = self._selected_packet
        if packet is None or packet.dissection.http is None or not packet.dissection.http.is_request:
            return
        RequestLabDialog(packet, self).exec()

    def open_capture_dialog(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Open packet capture",
            str(Path.home()),
            "Capture files (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if filename:
            self.load_capture(filename)

    def load_capture(self, filename: str | Path) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        if self._live_worker is not None and self._live_worker.isRunning():
            return

        path = Path(filename).expanduser()
        self._current_path = path
        self.file_label.setText(path.name)
        self.model.clear()
        self._clear_packet_details()
        self.filter_input.clear()
        self.filter_input.setEnabled(False)
        self.apply_button.setEnabled(False)
        self.clear_filter_button.setEnabled(False)
        self.open_action.setEnabled(False)
        self.close_action.setEnabled(False)
        self.filter_status.setStyleSheet("color: #847a90; font-size: 9pt;")
        self.filter_status.setText("Loading capture…")
        self.statusBar().showMessage(f"Loading {path}…")

        self._worker = CaptureLoadWorker(path, self)
        self._worker.batch_ready.connect(self._on_packet_batch)
        self._worker.load_finished.connect(self._on_load_finished)
        self._worker.load_failed.connect(self._on_load_failed)
        self._worker.finished.connect(self._on_worker_thread_finished)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()
        self._update_capture_controls()

    def _on_packet_batch(self, packets: list[ProcessedPacket]) -> None:
        self.model.append_packets(packets)
        self.statusBar().showMessage(
            f"Loading… {self.model.total_count:,} packets processed"
        )
        self._update_counts()

    def _on_load_finished(self, count: int) -> None:
        self.filter_status.setText("Capture loaded. Enter a display filter or leave it empty.")
        self.statusBar().showMessage(
            f"Loaded {count:,} packets from {self._current_path.name if self._current_path else 'capture'}"
        )
        self._update_counts()

    def _on_worker_thread_finished(self) -> None:
        self._worker = None
        self._set_loading_state(False)

    def _on_load_failed(self, message: str) -> None:
        self.filter_status.setText("Capture loading failed.")
        self.filter_status.setStyleSheet("color: #e18b91; font-size: 9pt;")
        self.statusBar().showMessage("Capture loading failed")
        QMessageBox.critical(self, "Could not read capture", message)

    def _set_loading_state(self, loading: bool) -> None:
        self.filter_input.setEnabled(not loading)
        self.apply_button.setEnabled(not loading)
        self.clear_filter_button.setEnabled(not loading)
        self._update_capture_controls()

    def _update_capture_controls(self) -> None:
        loading = self._worker is not None
        capturing = self._live_worker is not None
        analyzing = self._stream_worker is not None
        idle = not loading and not capturing and not analyzing
        has_interfaces = self.interface_combo.count() > 0
        has_selected_tcp = (
            self._selected_packet is not None
            and self._selected_packet.dissection.ipv4 is not None
            and self._selected_packet.dissection.tcp is not None
        )

        self.interface_combo.setEnabled(idle)
        self.refresh_interfaces_button.setEnabled(idle)
        self.start_capture_button.setEnabled(idle and has_interfaces)
        self.stop_capture_button.setEnabled(capturing)
        self.start_capture_action.setEnabled(idle and has_interfaces)
        self.stop_capture_action.setEnabled(capturing)
        self.open_action.setEnabled(idle)
        has_packets = self.model.total_count > 0
        self.close_action.setEnabled(idle and has_packets)
        self.export_action.setEnabled(idle and has_packets)
        self.analytics_action.setEnabled(idle and has_packets)
        has_http_request = (
            self._selected_packet is not None
            and self._selected_packet.dissection.http is not None
            and self._selected_packet.dissection.http.is_request
        )
        self.request_lab_action.setEnabled(idle and has_http_request)
        self.follow_stream_action.setEnabled(idle and has_selected_tcp)
        self.follow_stream_button.setEnabled(idle and has_selected_tcp)

    def refresh_interfaces(self) -> None:
        current = self.interface_combo.currentText()
        try:
            interfaces = list_interfaces()
        except LiveCaptureError as exc:
            self.interface_combo.clear()
            self.capture_state_label.setText("Could not list interfaces")
            self.statusBar().showMessage(str(exc))
            self._update_capture_controls()
            return

        self.interface_combo.clear()
        self.interface_combo.addItems(interfaces)
        if current and current in interfaces:
            self.interface_combo.setCurrentText(current)

        if interfaces:
            self.capture_state_label.setText(
                "Ready · capture only on an authorized interface · promiscuous mode off"
            )
        else:
            self.capture_state_label.setText("No network interfaces found")

        self._update_capture_controls()

    def start_live_capture(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        if self._live_worker is not None and self._live_worker.isRunning():
            return

        interface = self.interface_combo.currentText().strip()
        if not interface:
            QMessageBox.warning(self, "No interface selected", "Select a network interface first.")
            return

        self.model.clear()
        self._clear_packet_details()
        self.filter_input.clear()
        self.filter_input.setStyleSheet("")
        self._current_path = None
        self._live_interface = interface
        self._live_capture_error = False
        self.file_label.setText(f"Live capture · {interface}")
        self.filter_status.setStyleSheet("color: #9b8eaa; font-size: 9pt;")
        self.filter_status.setText("Capturing live packets. Enter a display filter or leave it empty.")

        self._live_worker = LiveCaptureWorker(interface, self)
        self._live_worker.batch_ready.connect(self._on_live_packet_batch)
        self._live_worker.capture_failed.connect(self._on_live_capture_failed)
        self._live_worker.finished.connect(self._on_live_capture_finished)
        self._live_worker.finished.connect(self._live_worker.deleteLater)

        self.capture_state_label.setText(f"Capturing on {interface} · promiscuous mode off")
        self.statusBar().showMessage(f"Starting live capture on {interface}…")
        self._live_worker.start()
        self._update_capture_controls()

    def stop_live_capture(self) -> None:
        if self._live_worker is None or not self._live_worker.isRunning():
            return

        self.stop_capture_button.setEnabled(False)
        self.stop_capture_action.setEnabled(False)
        self.capture_state_label.setText("Stopping live capture…")
        self.statusBar().showMessage("Stopping live capture…")
        self._live_worker.stop()

    def _on_live_packet_batch(self, packets: list[ProcessedPacket]) -> None:
        self.model.append_packets(packets)
        self._update_counts()
        interface = self._live_interface or "interface"
        self.statusBar().showMessage(
            f"Capturing on {interface} · {self.model.total_count:,} packets"
        )

    def _on_live_capture_failed(self, message: str) -> None:
        self._live_capture_error = True
        self.capture_state_label.setText("Live capture failed")
        self.filter_status.setStyleSheet("color: #e18b91; font-size: 9pt;")
        self.filter_status.setText(f"Live capture error: {message}")
        self.statusBar().showMessage("Live capture failed")
        QMessageBox.critical(self, "Live capture failed", message)

    def _on_live_capture_finished(self) -> None:
        interface = self._live_interface or "interface"
        self._live_worker = None
        self._update_capture_controls()

        if not self._live_capture_error:
            self.capture_state_label.setText(f"Stopped · {self.model.total_count:,} packets captured")
            self.statusBar().showMessage(
                f"Live capture stopped on {interface} · {self.model.total_count:,} packets"
            )

        if self.model.total_count:
            self.file_label.setText(f"Live capture · {interface} (stopped)")

    def apply_filter(self) -> None:
        expression = self.filter_input.text()
        try:
            visible = self.model.apply_filter(expression)
        except FilterSyntaxError as exc:
            self.filter_input.setStyleSheet(
                "QLineEdit { border: 1px solid #c66b75; background: #21151c; }"
            )
            self.filter_status.setStyleSheet("color: #e18b91; font-size: 9pt;")
            self.filter_status.setText(f"Invalid filter: {exc}")
            return

        self.filter_input.setStyleSheet("")
        self.filter_status.setStyleSheet("color: #9b8eaa; font-size: 9pt;")
        if expression.strip():
            self.filter_status.setText(
                f"Filter matched {visible:,} of {self.model.total_count:,} packets"
            )
        else:
            self.filter_status.setText("Displaying all packets")
        self._clear_packet_details()
        self._update_counts()

    def clear_filter(self) -> None:
        self.filter_input.clear()
        self.apply_filter()

    def close_capture(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        if self._live_worker is not None and self._live_worker.isRunning():
            return
        self.model.clear()
        self._current_path = None
        self._live_interface = None
        self.file_label.setText("No capture loaded")
        self.filter_input.clear()
        self.filter_status.setText(
            "Filters: arp, ipv6, tcp, udp, icmp, IP addresses, ports, flags, frame length"
        )
        self.filter_status.setStyleSheet("color: #847a90; font-size: 9pt;")
        self._clear_packet_details()
        self._set_loading_state(False)
        self.close_action.setEnabled(False)
        self.capture_state_label.setText("Live capture stopped · promiscuous mode off")
        self.statusBar().showMessage("Capture closed")
        self._update_capture_controls()
        self._update_counts()

    def _on_selection_changed(self, *_args) -> None:
        index = self.packet_table.currentIndex()
        packet = self.model.packet_at(index.row()) if index.isValid() else None
        if packet is None:
            self._clear_packet_details()
            return
        self._show_packet_details(packet)

    def _clear_packet_details(self) -> None:
        self._selected_packet = None
        self.details_tree.clear()
        self.hex_view.clear()
        self._update_capture_controls()

    def _show_packet_details(self, packet: ProcessedPacket) -> None:
        self._selected_packet = packet
        self.details_tree.clear()

        record = packet.record
        result = packet.dissection

        self._add_section("Frame", [
            ("Packet number", record.number),
            ("Timestamp", record.timestamp if record.timestamp is not None else "Unavailable"),
            ("Captured length", f"{record.captured_length} bytes"),
            ("Original length", f"{record.original_length} bytes"),
            ("Link type", record.link_type),
        ])

        if result.ethernet is not None:
            eth = result.ethernet
            item = self._add_section("Ethernet II", [
                ("Destination", eth.destination_mac),
                ("Source", eth.source_mac),
                ("Type / Length", f"0x{eth.type_or_length:04x}"),
                ("Decoded type", ETHERTYPE_NAMES.get(eth.type_or_length, "IEEE 802.3 length field" if eth.ether_type is None else "Unknown EtherType")),
                ("Payload offset", f"{eth.payload_offset} bytes"),
            ])
            for index, tag in enumerate(eth.vlan_tags, start=1):
                vlan = QTreeWidgetItem(item, [f"802.1Q VLAN tag {index}", ""])
                self._add_child(vlan, "TPID", f"0x{tag.tpid:04x}")
                self._add_child(vlan, "VLAN ID", tag.vlan_id)
                self._add_child(vlan, "Priority", tag.priority)
                self._add_child(vlan, "Drop eligible", tag.drop_eligible)

        if result.arp is not None:
            arp = result.arp
            self._add_section("Address Resolution Protocol", [
                ("Hardware type", f"{arp.hardware_type_name} ({arp.hardware_type})"),
                ("Protocol type", f"{arp.protocol_type_name} (0x{arp.protocol_type:04x})"),
                ("Hardware size", arp.hardware_length),
                ("Protocol size", arp.protocol_length),
                ("Opcode", f"{arp.operation} ({arp.opcode})"),
                ("Sender MAC address", arp.sender_hardware_address),
                ("Sender protocol address", arp.sender_protocol_address),
                ("Target MAC address", arp.target_hardware_address),
                ("Target protocol address", arp.target_protocol_address),
            ])

        if result.ipv4 is not None:
            ip = result.ipv4
            self._add_section("Internet Protocol Version 4", [
                ("Source address", ip.source_ip),
                ("Destination address", ip.destination_ip),
                ("Header length", f"{ip.header_length} bytes"),
                ("Total length", f"{ip.total_length} bytes"),
                ("DSCP", ip.dscp),
                ("ECN", ip.ecn),
                ("Identification", f"0x{ip.identification:04x}"),
                ("Reserved flag", ip.reserved_flag),
                ("Don't fragment", ip.dont_fragment),
                ("More fragments", ip.more_fragments),
                ("Fragment offset", f"{ip.fragment_offset * 8} bytes"),
                ("TTL", ip.ttl),
                ("Protocol number", ip.protocol),
                ("Header checksum", f"0x{ip.header_checksum:04x}"),
                ("Truncated", ip.is_truncated),
            ])

        if result.ipv6 is not None:
            ip = result.ipv6
            item = self._add_section("Internet Protocol Version 6", [
                ("Source address", ip.source_ip),
                ("Destination address", ip.destination_ip),
                ("Traffic class", ip.traffic_class),
                ("Flow label", f"0x{ip.flow_label:05x}"),
                ("Payload length", f"{ip.payload_length} bytes"),
                ("Initial next header", ip.next_header),
                ("Upper-layer protocol", ip.upper_layer_protocol),
                ("Hop limit", ip.hop_limit),
                ("Fragment offset", f"{ip.fragment_offset} bytes"),
                ("More fragments", ip.more_fragments),
                ("Fragment identification", ip.fragment_identification if ip.fragment_identification is not None else "N/A"),
                ("Truncated", ip.is_truncated),
            ])
            for index, extension in enumerate(ip.extension_headers, start=1):
                ext_item = QTreeWidgetItem(item, [f"Extension {index}: {extension.name}", ""])
                self._add_child(ext_item, "Next header", extension.next_header)
                self._add_child(ext_item, "Offset", f"{extension.offset} bytes")
                self._add_child(ext_item, "Length", f"{extension.length} bytes")
                if extension.fragment_offset is not None:
                    self._add_child(ext_item, "Fragment offset", f"{extension.fragment_offset} bytes")
                    self._add_child(ext_item, "More fragments", extension.more_fragments)
                    self._add_child(ext_item, "Identification", extension.fragment_identification)

        if result.icmp is not None:
            icmp = result.icmp
            self._add_section(
                "Internet Control Message Protocol" if icmp.version == 4 else "Internet Control Message Protocol v6",
                [
                    ("Type", f"{icmp.type_name} ({icmp.type})"),
                    ("Code", icmp.code),
                    ("Checksum", f"0x{icmp.checksum:04x}"),
                    ("Identifier", icmp.identifier if icmp.identifier is not None else "N/A"),
                    ("Sequence number", icmp.sequence_number if icmp.sequence_number is not None else "N/A"),
                    ("Header length", f"{icmp.header_length} bytes"),
                ],
            )

        if result.tcp is not None:
            tcp = result.tcp
            self._add_section("Transmission Control Protocol", [
                ("Source port", tcp.source_port),
                ("Destination port", tcp.destination_port),
                ("Sequence number", tcp.sequence_number),
                ("Acknowledgment number", tcp.acknowledgment_number),
                ("Header length", f"{tcp.header_length} bytes"),
                ("Reserved", tcp.reserved),
                ("NS", tcp.ns),
                ("Flags", ", ".join(tcp.active_flags) or "None"),
                ("Window size", tcp.window_size),
                ("Checksum", f"0x{tcp.checksum:04x}"),
                ("Urgent pointer", tcp.urgent_pointer),
                ("Options", tcp.options.hex(" ") or "None"),
            ])

        if result.udp is not None:
            udp = result.udp
            self._add_section("User Datagram Protocol", [
                ("Source port", udp.source_port),
                ("Destination port", udp.destination_port),
                ("Length", f"{udp.length} bytes"),
                ("Checksum", f"0x{udp.checksum:04x}"),
                ("Captured length", f"{udp.captured_length} bytes"),
                ("Truncated", udp.is_truncated),
            ])

        if result.dns is not None:
            dns = result.dns
            dns_item = self._add_section("Domain Name System", [
                ("Transaction ID", f"0x{dns.transaction_id:04x}"),
                ("Message type", "Response" if dns.is_response else "Query"),
                ("Opcode", dns.opcode),
                ("Authoritative", dns.authoritative),
                ("Truncated", dns.truncated),
                ("Recursion desired", dns.recursion_desired),
                ("Recursion available", dns.recursion_available),
                ("Response code", f"{dns.rcode_name} ({dns.rcode})"),
                ("Questions", len(dns.questions)),
                ("Answers", len(dns.answers)),
                ("Authorities", len(dns.authorities)),
                ("Additional records", len(dns.additionals)),
                ("TCP length framing", dns.tcp_framed),
            ])
            for index, question in enumerate(dns.questions, start=1):
                question_item = QTreeWidgetItem(dns_item, [f"Question {index}", ""])
                self._add_child(question_item, "Name", question.name)
                self._add_child(question_item, "Type", f"{question.type_name} ({question.qtype})")
                self._add_child(question_item, "Class", question.qclass)
            for section_name, records in (
                ("Answer", dns.answers),
                ("Authority", dns.authorities),
                ("Additional", dns.additionals),
            ):
                for index, record in enumerate(records, start=1):
                    record_item = QTreeWidgetItem(dns_item, [f"{section_name} {index}: {record.name}", ""])
                    self._add_child(record_item, "Type", f"{record.type_name} ({record.record_type})")
                    self._add_child(record_item, "Class", record.record_class)
                    self._add_child(record_item, "TTL", f"{record.ttl} seconds")
                    self._add_child(record_item, "Data length", f"{record.data_length} bytes")
                    self._add_child(record_item, "Data", record.data)

        if result.http is not None:
            http = result.http
            fields = [
                ("Message type", "Request" if http.is_request else "Response"),
                ("Version", http.version),
                ("Method", http.method or "N/A"),
                ("Request target", http.target or "N/A"),
                ("Status code", http.status_code if http.status_code is not None else "N/A"),
                ("Reason", http.reason or "N/A"),
                ("Host", http.host or "N/A"),
                ("Content-Type", http.content_type or "N/A"),
                ("Content-Length", http.content_length if http.content_length is not None else "N/A"),
                ("Server", http.server or "N/A"),
                ("Connection", http.connection or "N/A"),
                ("Transfer-Encoding", http.transfer_encoding or "N/A"),
                ("Parsed headers", http.header_count),
                ("Header block complete", http.headers_complete),
            ]
            self._add_section("Hypertext Transfer Protocol", fields)

        if result.tls is not None:
            tls = result.tls
            fields = [
                ("Record content type", f"{tls.content_type_name} ({tls.content_type})"),
                ("Record legacy version", f"{tls.version_name} (0x{tls.legacy_version:04x})"),
                ("Record length", f"{tls.record_length} bytes"),
                ("Captured record payload", f"{tls.captured_length} bytes"),
                ("Record truncated", tls.is_truncated),
                ("Handshake type", tls.handshake_name or "N/A"),
                ("Handshake length", tls.handshake_length if tls.handshake_length is not None else "N/A"),
                ("Handshake truncated", tls.handshake_is_truncated),
            ]
            tls_item = self._add_section("Transport Layer Security", fields)
            if tls.client_hello is not None:
                hello = tls.client_hello
                hello_item = QTreeWidgetItem(tls_item, ["Client Hello", ""])
                self._add_child(hello_item, "Legacy version", tls_version_name(hello.legacy_version))
                self._add_child(hello_item, "Server Name (SNI)", hello.server_name or "N/A")
                self._add_child(hello_item, "ALPN", ", ".join(hello.alpn_protocols) or "N/A")
                self._add_child(hello_item, "Supported versions", ", ".join(tls_version_name(v) for v in hello.supported_versions) or "N/A")
                self._add_child(hello_item, "Cipher suites", len(hello.cipher_suites))
                for cipher in hello.cipher_suites:
                    self._add_child(hello_item, f"Cipher 0x{cipher:04x}", cipher_suite_name(cipher))
            if tls.server_hello is not None:
                hello = tls.server_hello
                hello_item = QTreeWidgetItem(tls_item, ["Server Hello", ""])
                negotiated = hello.negotiated_version or hello.legacy_version
                self._add_child(hello_item, "Negotiated version", tls_version_name(negotiated))
                self._add_child(hello_item, "Cipher suite", cipher_suite_name(hello.cipher_suite))
                self._add_child(hello_item, "ALPN", hello.alpn_protocol or "N/A")
                self._add_child(hello_item, "Compression method", hello.compression_method)

        if result.errors:
            self._add_section("Dissection warnings", [
                (f"Warning {index}", message)
                for index, message in enumerate(result.errors, start=1)
            ])

        payload_item = self._add_section("Payload", [
            ("Captured payload length", f"{len(result.payload)} bytes"),
        ])
        if result.payload:
            self._add_child(payload_item, "Preview", result.payload[:32].hex(" "))

        self.details_tree.expandToDepth(1)
        self.hex_view.setPlainText(self._format_hex(record.data))
        self._update_capture_controls()

    def follow_tcp_stream(self) -> None:
        if self._stream_worker is not None:
            return

        packet = self._selected_packet
        if packet is None:
            return

        key_result = tcp_stream_key_for_packet(packet)
        if key_result is None:
            QMessageBox.information(
                self,
                "TCP stream unavailable",
                "Select an IPv4/TCP packet first.",
            )
            return

        stream_key, _direction = key_result
        packets = tuple(self.model.iter_packets())
        if not packets:
            return

        self.statusBar().showMessage("Reassembling TCP stream…")
        self.filter_status.setText(
            "Reassembling the selected TCP conversation from all captured packets…"
        )
        self._stream_worker = TCPStreamWorker(packets, stream_key, self)
        self._stream_worker.stream_ready.connect(self._on_stream_ready)
        self._stream_worker.analysis_failed.connect(self._on_stream_failed)
        self._stream_worker.finished.connect(self._on_stream_worker_finished)
        self._stream_worker.finished.connect(self._stream_worker.deleteLater)
        self._update_capture_controls()
        self._stream_worker.start()

    def _on_stream_ready(self, stream) -> None:
        if stream is None:
            QMessageBox.information(
                self,
                "TCP stream not found",
                "No packets for the selected TCP conversation were found in the capture.",
            )
            return

        dialog = TCPStreamDialog(stream, self)
        dialog.exec()

    def _on_stream_failed(self, message: str) -> None:
        QMessageBox.critical(self, "TCP stream reconstruction failed", message)
        self.statusBar().showMessage("TCP stream reconstruction failed")

    def _on_stream_worker_finished(self) -> None:
        self._stream_worker = None
        self._update_capture_controls()
        self.statusBar().showMessage("TCP stream analysis finished")

    def _add_section(self, title: str, fields: list[tuple[str, object]]) -> QTreeWidgetItem:
        section = QTreeWidgetItem(self.details_tree, [title, ""])
        section.setFlags(section.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        for name, value in fields:
            self._add_child(section, name, value)
        return section

    @staticmethod
    def _add_child(parent: QTreeWidgetItem, name: str, value: object) -> None:
        QTreeWidgetItem(parent, [str(name), str(value)])

    @staticmethod
    def _format_hex(data: bytes) -> str:
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_part = "".join(
                chr(byte) if 32 <= byte <= 126 else "."
                for byte in chunk
            )
            lines.append(f"{offset:08x}  {hex_part:<47}  |{ascii_part}|")
        return "\n".join(lines)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        if path:
            self.load_capture(path)
            event.acceptProposedAction()

    def closeEvent(self, event) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.requestInterruption()
            self._worker.wait()
        if self._live_worker is not None and self._live_worker.isRunning():
            self._live_worker.stop()
            self._live_worker.wait()
        if self._stream_worker is not None and self._stream_worker.isRunning():
            self._stream_worker.wait()
        self.proxy.stop()
        event.accept()

    def _update_counts(self) -> None:
        self.count_status.setText(
            f"{self.model.visible_count:,} displayed / {self.model.total_count:,} total"
        )
