from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QFont, QKeySequence, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTreeWidget,
    QTreeWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from netview.capture import LiveCaptureError, list_interfaces
from netview.capture.export import export_packets as write_export
from netview.core.dissector import ETHERTYPE_NAMES
from netview.core.tls import cipher_suite_name, tls_version_name
from netview.core.pipeline import ProcessedPacket
from netview.core.streams import tcp_stream_key_for_packet
from netview.core.tcp_flow import tcp_flow_key_for_packet
from netview.filters import FilterSyntaxError
from netview.gui.table_model import PacketTableModel

from .analysis_dialog import AnalysisDialog
from .annotations import annotation_sidecar_path, load_annotations, save_annotations
from .live_worker import LiveCaptureWorker
from .filter_manager import FilterManagerDialog
from .stream_dialog import TCPStreamDialog
from .stream_worker import TCPStreamWorker
from .tcp_flow_dialog import TCPFlowGraphDialog
from .tcp_flow_worker import TCPFlowWorker
from .worker import CaptureLoadWorker


APP_STYLE = """
QMainWindow, QWidget {
    background: #101820;
    color: #e5edf2;
    font-family: "Inter", "Noto Sans", sans-serif;
    font-size: 10pt;
}
QFrame#sidebar { background: #14212a; border-right: 1px solid #293943; }
QMenuBar, QMenu {
    background: #14212a;
    color: #dce7ec;
    border: none;
}
QMenuBar::item { padding: 7px 11px; }
QMenuBar::item:selected, QMenu::item:selected { background: #20343d; color: #72e0d0; }
QLineEdit, QPlainTextEdit, QTreeWidget, QTableView {
    background: #121e27;
    color: #dce7ec;
    border: 1px solid #293943;
    border-radius: 7px;
    selection-background-color: #24504f;
    selection-color: #f4ffff;
}
QLineEdit { padding: 9px 12px; }
QLineEdit:focus, QPlainTextEdit:focus, QTreeWidget:focus, QTableView:focus {
    border: 1px solid #45bfae;
}
QPushButton {
    background: #1c3039;
    color: #dce7ec;
    border: 1px solid #344b55;
    border-radius: 7px;
    padding: 8px 14px;
    font-weight: 600;
}
QPushButton:hover { background: #27434b; border-color: #4d8d87; }
QPushButton:pressed { background: #1c4b4b; }
QPushButton:disabled { color: #657781; background: #17232b; border-color: #26343c; }
QHeaderView::section {
    background: #1b2a34;
    color: #9eb2bd;
    border: none;
    border-right: 1px solid #293943;
    border-bottom: 1px solid #344650;
    padding: 10px 8px;
    font-weight: 700;
}
QTableView { gridline-color: #22323b; alternate-background-color: #16232c; }
QTableView::item { padding: 6px; }
QTreeWidget::item { padding: 4px; }
QStatusBar {
    background: #14212a;
    color: #91a5b2;
    border-top: 1px solid #293943;
}
QSplitter::handle { background: #293943; }
QSplitter::handle:horizontal { width: 5px; }
QSplitter::handle:vertical { height: 5px; }
QComboBox {
    background: #17252e;
    color: #dce7ec;
    border: 1px solid #344b55;
    border-radius: 7px;
    padding: 8px 10px;
}
QComboBox QAbstractItemView { background: #17252e; color: #dce7ec; selection-background-color: #24504f; }
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
        self._live_capture_stopping = False
        self._current_path: Path | None = None
        self._selected_packet: ProcessedPacket | None = None
        self._annotations: dict[int, str] = {}
        self._hex_data_length = 0
        self._stream_worker: TCPStreamWorker | None = None
        self._flow_worker: TCPFlowWorker | None = None
        self._flow_failed = False

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

        self.save_annotations_action = QAction("Save packet notes…", self)
        self.save_annotations_action.setShortcut(QKeySequence("Ctrl+Shift+E"))
        self.save_annotations_action.triggered.connect(self.save_packet_notes)
        file_menu.addAction(self.save_annotations_action)
        export_menu = file_menu.addMenu("Export packets")
        self.export_all_action = QAction("All packets…", self)
        self.export_all_action.triggered.connect(
            lambda: self.export_capture_packets(displayed_only=False)
        )
        export_menu.addAction(self.export_all_action)
        self.export_displayed_action = QAction("Displayed packets…", self)
        self.export_displayed_action.triggered.connect(
            lambda: self.export_capture_packets(displayed_only=True)
        )
        export_menu.addAction(self.export_displayed_action)

        edit_menu = self.menuBar().addMenu("&Edit")
        self.find_action = QAction("Find packet…", self)
        self.find_action.setShortcut(QKeySequence("Ctrl+F"))
        self.find_action.triggered.connect(self.find_packet)
        edit_menu.addAction(self.find_action)
        edit_menu.addSeparator()
        self.manage_filters_action = QAction("Saved filters…", self)
        self.manage_filters_action.triggered.connect(self.open_filter_manager)
        edit_menu.addAction(self.manage_filters_action)

        capture_menu = self.menuBar().addMenu("&Capture")
        self.start_capture_action = QAction("Start live capture", self)
        self.start_capture_action.triggered.connect(self.start_live_capture)
        capture_menu.addAction(self.start_capture_action)

        self.pause_capture_action = QAction("Pause live capture", self)
        self.pause_capture_action.setShortcut(QKeySequence("Ctrl+P"))
        self.pause_capture_action.triggered.connect(self.toggle_live_capture_pause)
        capture_menu.addAction(self.pause_capture_action)

        self.stop_capture_action = QAction("Stop live capture", self)
        self.stop_capture_action.triggered.connect(self.stop_live_capture)
        capture_menu.addAction(self.stop_capture_action)

        analyze_menu = self.menuBar().addMenu("&Analyze")
        self.statistics_action = QAction("Analysis center", self)
        self.statistics_action.setShortcut(QKeySequence("Ctrl+Shift+S"))
        self.statistics_action.triggered.connect(self.show_analysis_center)
        self.statistics_action.setEnabled(False)
        analyze_menu.addAction(self.statistics_action)
        analyze_menu.addSeparator()
        self.mark_packet_action = QAction("Add / edit packet note…", self)
        self.mark_packet_action.setShortcut(QKeySequence("Ctrl+B"))
        self.mark_packet_action.triggered.connect(self.mark_packet_note)
        analyze_menu.addAction(self.mark_packet_action)
        self.clear_packet_note_action = QAction("Remove packet note", self)
        self.clear_packet_note_action.triggered.connect(self.remove_packet_note)
        analyze_menu.addAction(self.clear_packet_note_action)
        analyze_menu.addSeparator()
        self.follow_stream_action = QAction("Follow TCP Stream", self)
        self.follow_stream_action.setShortcut(QKeySequence("Ctrl+Shift+T"))
        self.follow_stream_action.triggered.connect(self.follow_tcp_stream)
        self.follow_stream_action.setEnabled(False)
        analyze_menu.addAction(self.follow_stream_action)
        self.tcp_flow_action = QAction("TCP Flow Graph", self)
        self.tcp_flow_action.setShortcut(QKeySequence("Ctrl+Shift+G"))
        self.tcp_flow_action.triggered.connect(self.show_tcp_flow_graph)
        self.tcp_flow_action.setEnabled(False)
        analyze_menu.addAction(self.tcp_flow_action)

        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def _build_ui(self) -> None:
        central = QWidget(self)
        shell = QHBoxLayout(central)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(248)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 22, 20, 20)
        side.setSpacing(12)

        brand = QLabel("netview")
        brand.setStyleSheet("font-size: 23pt; font-weight: 800; color: #edf7f8; letter-spacing: -1px;")
        tagline = QLabel("NETWORK OBSERVABILITY")
        tagline.setStyleSheet("font-size: 8pt; font-weight: 700; letter-spacing: 2px; color: #72e0d0;")
        side.addWidget(brand)
        side.addWidget(tagline)
        side.addSpacing(24)

        section = QLabel("CAPTURE SOURCE")
        section.setStyleSheet("font-size: 8pt; font-weight: 700; letter-spacing: 1px; color: #8297a4;")
        side.addWidget(section)

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(190)
        self.interface_combo.setToolTip(
            "Select one local interface you own or are authorized to monitor."
        )
        side.addWidget(self.interface_combo)

        self.refresh_interfaces_button = QPushButton("↻  Refresh interfaces")
        self.refresh_interfaces_button.clicked.connect(self.refresh_interfaces)
        side.addWidget(self.refresh_interfaces_button)

        self.start_capture_button = QPushButton("▶  Start live capture")
        self.start_capture_button.setStyleSheet(
            "QPushButton { background: #1d514d; border-color: #347f76; color: #eafffb; }"
            "QPushButton:hover { background: #27665f; }"
        )
        self.start_capture_button.clicked.connect(self.start_live_capture)
        side.addWidget(self.start_capture_button)

        self.pause_capture_button = QPushButton("Ⅱ  Pause capture")
        self.pause_capture_button.setToolTip(
            "Temporarily pause packet collection without ending this capture session (Ctrl+P)."
        )
        self.pause_capture_button.clicked.connect(self.toggle_live_capture_pause)
        side.addWidget(self.pause_capture_button)

        self.stop_capture_button = QPushButton("■  Stop capture")
        self.stop_capture_button.clicked.connect(self.stop_live_capture)
        side.addWidget(self.stop_capture_button)

        side.addSpacing(16)
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("color: #293943;")
        side.addWidget(divider)

        section = QLabel("SESSION STATUS")
        section.setStyleSheet("font-size: 8pt; font-weight: 700; letter-spacing: 1px; color: #8297a4;")
        side.addWidget(section)
        self.capture_state_label = QLabel("Live capture stopped\nPromiscuous mode off")
        self.capture_state_label.setWordWrap(True)
        self.capture_state_label.setStyleSheet(
            "background: #17252e; border: 1px solid #293943; border-radius: 8px;"
            "padding: 12px; color: #9eb2bd; font-size: 9pt;"
        )
        side.addWidget(self.capture_state_label)
        side.addStretch(1)

        footer = QLabel("NETVIEW 1.0  ·  PACKET ANALYSIS")
        footer.setStyleSheet("font-size: 7pt; color: #607580; letter-spacing: 1px;")
        side.addWidget(footer)
        shell.addWidget(sidebar)

        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(24, 20, 24, 18)
        root.setSpacing(12)

        heading = QHBoxLayout()
        heading.setSpacing(12)
        title = QLabel("Packet workspace")
        title.setStyleSheet("font-size: 20pt; font-weight: 750; color: #edf7f8;")
        heading.addWidget(title)
        heading.addStretch(1)
        self.file_label = QLabel("No capture loaded")
        self.file_label.setStyleSheet("color: #9eb2bd;")
        self.file_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        heading.addWidget(self.file_label)
        root.addLayout(heading)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)
        filter_label = QLabel("FILTER")
        filter_label.setStyleSheet("color: #72e0d0; font-size: 8pt; font-weight: 700; letter-spacing: 1px;")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText(
            "tcp.port == 443   ·   dns.qry.name == example.com   ·   tls"
        )
        self.filter_input.returnPressed.connect(self.apply_filter)
        self.apply_button = QPushButton("Apply filter")
        self.apply_button.clicked.connect(self.apply_filter)
        self.clear_filter_button = QPushButton("Reset")
        self.clear_filter_button.clicked.connect(self.clear_filter)
        self.follow_stream_button = QPushButton("Follow TCP stream")
        self.follow_stream_button.setToolTip(
            "Reassemble both directions of the selected IPv4/IPv6 TCP conversation (Ctrl+Shift+T)."
        )
        self.follow_stream_button.clicked.connect(self.follow_tcp_stream)
        self.follow_stream_button.setEnabled(False)
        filter_row.addWidget(filter_label)
        filter_row.addWidget(self.filter_input, 1)
        filter_row.addWidget(self.apply_button)
        filter_row.addWidget(self.clear_filter_button)
        filter_row.addWidget(self.follow_stream_button)
        root.addLayout(filter_row)

        self.filter_status = QLabel(
            "Filter by protocol, addresses, ports, DNS, HTTP or TLS metadata"
        )
        self.filter_status.setStyleSheet("color: #8297a4; font-size: 9pt;")
        root.addWidget(self.filter_status)

        self.packet_table = QTableView()
        self.packet_table.setModel(self.model)
        self.packet_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setShowGrid(False)
        self.packet_table.setSortingEnabled(False)
        self.packet_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(
            self.show_packet_context_menu
        )
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setColumnWidth(0, 64)
        self.packet_table.setColumnWidth(1, 145)
        self.packet_table.setColumnWidth(2, 155)
        self.packet_table.setColumnWidth(3, 155)
        self.packet_table.setColumnWidth(4, 95)
        self.packet_table.setColumnWidth(5, 78)
        self.packet_table.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )

        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Decoded layer", "Field value"])
        self.details_tree.setColumnWidth(0, 255)
        self.details_tree.setAlternatingRowColors(True)
        self.details_tree.currentItemChanged.connect(self._on_detail_field_changed)

        self.hex_status = QLabel("Select a decoded field to highlight its bytes.")
        self.hex_status.setStyleSheet("color: #8297a4; font-size: 8pt; padding: 2px 4px;")
        self.hex_view = QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_view.setPlaceholderText("Select a packet to inspect its bytes.")
        self.hex_view.setFont(QFont("monospace", 9))

        lower_splitter = QSplitter(Qt.Orientation.Horizontal)
        hex_panel = QWidget()
        hex_layout = QVBoxLayout(hex_panel)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.setSpacing(4)
        hex_layout.addWidget(self.hex_status)
        hex_layout.addWidget(self.hex_view, 1)

        lower_splitter.addWidget(self.details_tree)
        lower_splitter.addWidget(hex_panel)
        lower_splitter.setStretchFactor(0, 1)
        lower_splitter.setStretchFactor(1, 1)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(self.packet_table)
        main_splitter.addWidget(lower_splitter)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 2)
        main_splitter.setSizes([540, 300])
        root.addWidget(main_splitter, 1)

        shell.addWidget(content, 1)
        self.setCentralWidget(central)
        self.count_status = QLabel("0 displayed / 0 total")
        self.count_status.setStyleSheet("color: #9eb2bd; padding: 0 8px;")
        self.statusBar().addPermanentWidget(self.count_status)
        self.statusBar().showMessage("Ready — open a PCAP or PCAPNG file")

    def open_filter_manager(self) -> None:
        dialog = FilterManagerDialog(self.filter_input.text(), self)
        dialog.filter_applied.connect(self._set_filter_expression)
        dialog.exec()

    def _set_filter_expression(self, expression: str) -> None:
        self.filter_input.setText(expression)
        self.apply_filter()

    def _copy_text(self, value: str) -> None:
        QApplication.clipboard().setText(value)

    def _build_packet_context_menu(self, packet: ProcessedPacket) -> QMenu:
        menu = QMenu(self)
        filter_menu = menu.addMenu("Apply as Filter")
        choices: list[tuple[str, str]] = [
            ("This packet number", f"frame.number == {packet.number}"),
        ]
        dissection = packet.dissection
        if dissection.ipv4 is not None:
            choices.extend((
                ("IPv4 source", f"ip.src == {dissection.ipv4.source_ip}"),
                ("IPv4 destination", f"ip.dst == {dissection.ipv4.destination_ip}"),
            ))
        if dissection.ipv6 is not None:
            choices.extend((
                ("IPv6 source", f"ipv6.src == {dissection.ipv6.source_ip}"),
                ("IPv6 destination", f"ipv6.dst == {dissection.ipv6.destination_ip}"),
            ))
        if dissection.ethernet is not None:
            choices.extend((
                ("Ethernet source", f"eth.src == {dissection.ethernet.source_mac}"),
                ("Ethernet destination", f"eth.dst == {dissection.ethernet.destination_mac}"),
            ))
        if dissection.tcp is not None:
            tcp = dissection.tcp
            choices.extend((
                ("TCP source port", f"tcp.srcport == {tcp.source_port}"),
                ("TCP destination port", f"tcp.dstport == {tcp.destination_port}"),
                ("Either TCP source port", f"tcp.port == {tcp.source_port}"),
                ("Either TCP destination port", f"tcp.port == {tcp.destination_port}"),
            ))
        if dissection.udp is not None:
            udp = dissection.udp
            choices.extend((
                ("UDP source port", f"udp.srcport == {udp.source_port}"),
                ("UDP destination port", f"udp.dstport == {udp.destination_port}"),
                ("Either UDP source port", f"udp.port == {udp.source_port}"),
                ("Either UDP destination port", f"udp.port == {udp.destination_port}"),
            ))
        protocol_filter = packet.protocol.casefold()
        if protocol_filter in {
            "arp", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6",
            "dns", "mdns", "llmnr", "http", "tls",
        }:
            choices.insert(0, ("Protocol: " + packet.protocol, protocol_filter))
        for label, expression in choices:
            action = filter_menu.addAction(label)
            action.triggered.connect(
                lambda _checked=False, value=expression: self._set_filter_expression(value)
            )

        flow_key = tcp_flow_key_for_packet(packet)
        stream_key = tcp_stream_key_for_packet(packet)
        if flow_key is not None or stream_key is not None:
            menu.addSeparator()
            if flow_key is not None:
                menu.addAction("TCP Flow Graph", self.show_tcp_flow_graph)
            if stream_key is not None:
                menu.addAction("Follow TCP Stream", self.follow_tcp_stream)
        menu.addSeparator()
        menu.addAction("Add / edit packet note…", self.mark_packet_note)
        menu.addSeparator()
        menu.addAction("Copy source", lambda: self._copy_text(packet.source))
        menu.addAction("Copy destination", lambda: self._copy_text(packet.destination))
        menu.addAction(
            "Copy packet summary",
            lambda: self._copy_text(
                f"#{packet.number} {packet.source} → {packet.destination} "
                f"{packet.protocol} {packet.info}"
            ),
        )
        menu.addAction(
            "Copy packet bytes (hex)",
            lambda: self._copy_text(packet.record.data.hex(" ")),
        )
        return menu

    def show_packet_context_menu(self, position) -> None:
        index = self.packet_table.indexAt(position)
        if not index.isValid():
            return
        self.packet_table.setCurrentIndex(index)
        packet = self.model.packet_at(index.row())
        if packet is None:
            return
        menu = self._build_packet_context_menu(packet)
        menu.exec(self.packet_table.viewport().mapToGlobal(position))

    def export_capture_packets(self, displayed_only: bool) -> None:
        if displayed_only:
            packets = tuple(
                packet
                for row in range(self.model.visible_count)
                if (packet := self.model.packet_at(row)) is not None
            )
            scope = "displayed"
        else:
            packets = tuple(self.model.iter_packets())
            scope = "all"
        if not packets:
            QMessageBox.information(self, "Nothing to export", "There are no packets in this selection.")
            return

        filename, selected_filter = QFileDialog.getSaveFileName(
            self,
            f"Export {scope} packets",
            str(Path.home() / "netview-export.pcapng"),
            "PCAPNG capture (*.pcapng);;Classic PCAP capture (*.pcap);;CSV table (*.csv)",
        )
        if not filename:
            return
        destination = Path(filename).expanduser()
        if not destination.suffix:
            suffix = ".csv" if "CSV" in selected_filter else (
                ".pcap" if "Classic PCAP" in selected_filter else ".pcapng"
            )
            destination = destination.with_suffix(suffix)

        try:
            write_export(destination, packets)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Packet export failed", str(exc))
            return

        self.statusBar().showMessage(
            f"Exported {len(packets):,} {scope} packet(s) to {destination}"
        )

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
            self.statusBar().showMessage("A capture is already being loaded.")
            return
        if self._live_worker is not None and self._live_worker.isRunning():
            self.statusBar().showMessage("Stop live capture before opening another capture.")
            return

        path = Path(filename).expanduser()
        self._current_path = path
        self._annotations = {}
        try:
            self._annotations = load_annotations(annotation_sidecar_path(path))
        except ValueError as exc:
            QMessageBox.warning(self, "Packet notes could not be loaded", str(exc))
        self.file_label.setText(path.name)
        self.model.clear()
        self.model.set_annotations(self._annotations)
        self._clear_packet_details()
        self.filter_input.clear()
        self.filter_input.setEnabled(False)
        self.apply_button.setEnabled(False)
        self.clear_filter_button.setEnabled(False)
        self.open_action.setEnabled(False)
        self.close_action.setEnabled(False)
        self.filter_status.setStyleSheet("color: #8297a4; font-size: 9pt;")
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
        # QThread references can outlive the worker thread briefly while Qt
        # delivers queued finished/deleteLater events. UI availability must
        # follow the actual thread state, not whether the Python reference exists.
        loading = self._worker is not None and self._worker.isRunning()
        capturing = self._live_worker is not None and self._live_worker.isRunning()
        analyzing = (
            (self._stream_worker is not None and self._stream_worker.isRunning())
            or (self._flow_worker is not None and self._flow_worker.isRunning())
        )
        idle = not loading and not capturing and not analyzing
        # Analysis operates on a snapshot of packets already in the model.
        # It does not need the live-capture worker to exit: the GUI owns all
        # model updates, and stream reconstruction receives an immutable tuple.
        packet_tools_available = not loading and self.model.total_count > 0
        has_interfaces = self.interface_combo.count() > 0
        has_selected_tcp = (
            self._selected_packet is not None
            and tcp_stream_key_for_packet(self._selected_packet) is not None
        )
        has_selected_tcp_flow = (
            self._selected_packet is not None
            and tcp_flow_key_for_packet(self._selected_packet) is not None
        )

        self.interface_combo.setEnabled(idle)
        self.refresh_interfaces_button.setEnabled(idle)
        self.start_capture_button.setEnabled(idle and has_interfaces)
        worker_can_pause = self._live_worker is not None and self._live_worker.can_pause
        paused = self._live_worker.is_paused if self._live_worker is not None else False
        pause_label = "▶  Resume capture" if paused else "Ⅱ  Pause capture"
        self.pause_capture_button.setText(pause_label)
        self.pause_capture_action.setText("Resume live capture" if paused else "Pause live capture")
        self.pause_capture_button.setEnabled(worker_can_pause)
        self.pause_capture_action.setEnabled(worker_can_pause)
        can_stop = capturing and not self._live_capture_stopping
        self.stop_capture_button.setEnabled(can_stop)
        self.start_capture_action.setEnabled(idle and has_interfaces)
        self.pause_capture_action.setEnabled(worker_can_pause and not self._live_capture_stopping)
        self.stop_capture_action.setEnabled(can_stop)
        self.open_action.setEnabled(idle)
        self.close_action.setEnabled(idle and self.model.total_count > 0)
        has_packets = self.model.total_count > 0 and not loading
        self.export_all_action.setEnabled(has_packets)
        self.export_displayed_action.setEnabled(has_packets and self.model.visible_count > 0)
        self.follow_stream_action.setEnabled(
            packet_tools_available and not analyzing and has_selected_tcp
        )
        self.tcp_flow_action.setEnabled(
            packet_tools_available and not analyzing and has_selected_tcp_flow
        )
        self.statistics_action.setEnabled(packet_tools_available)
        self.follow_stream_button.setEnabled(
            packet_tools_available and not analyzing and has_selected_tcp
        )
        has_selection = self._selected_packet is not None
        self.mark_packet_action.setEnabled(packet_tools_available and has_selection)
        self.clear_packet_note_action.setEnabled(
            packet_tools_available and has_selection
            and self._selected_packet.number in self._annotations
        )
        self.save_annotations_action.setEnabled(
            packet_tools_available and bool(self._annotations)
        )

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
            self.statusBar().showMessage("Wait for the current capture to finish loading.")
            return
        if self._live_worker is not None and self._live_worker.isRunning():
            self.statusBar().showMessage("A live capture is already running.")
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
        self._annotations = {}
        self.model.set_annotations(self._annotations)
        self._live_interface = interface
        self._live_capture_error = False
        self._live_capture_stopping = False
        self.file_label.setText(f"Live capture · {interface}")
        self.filter_status.setStyleSheet("color: #91a5b2; font-size: 9pt;")
        self.filter_status.setText("Capturing live packets. Enter a display filter or leave it empty.")

        self._live_worker = LiveCaptureWorker(interface, self)
        self._live_worker.batch_ready.connect(self._on_live_packet_batch)
        self._live_worker.capture_failed.connect(self._on_live_capture_failed)
        self._live_worker.capture_started.connect(self._on_live_capture_started)
        self._live_worker.paused_changed.connect(self._on_live_capture_state_changed)
        self._live_worker.finished.connect(self._on_live_capture_finished)
        self._live_worker.finished.connect(self._live_worker.deleteLater)

        self.capture_state_label.setText(f"Capturing on {interface} · promiscuous mode off")
        self.statusBar().showMessage(f"Starting live capture on {interface}…")
        self._live_worker.start()
        self._update_capture_controls()

    def toggle_live_capture_pause(self) -> None:
        worker = self._live_worker
        if worker is None or not worker.can_pause:
            return
        try:
            if worker.is_paused:
                worker.resume()
            else:
                worker.pause()
        except LiveCaptureError as exc:
            QMessageBox.warning(self, "Live capture control failed", str(exc))
            self._update_capture_controls()

    def _on_live_capture_started(self) -> None:
        interface = self._live_interface or "interface"
        self.capture_state_label.setText(
            f"Capturing on {interface} · promiscuous mode off"
        )
        self.statusBar().showMessage(f"Capturing on {interface}…")
        self._update_capture_controls()

    def _on_live_capture_state_changed(self, paused: bool) -> None:
        interface = self._live_interface or "interface"
        if paused:
            self.capture_state_label.setText(
                f"Paused on {interface}\n{self.model.total_count:,} packets retained"
            )
            self.statusBar().showMessage(
                f"Capture paused on {interface} · {self.model.total_count:,} packets retained"
            )
        else:
            self.capture_state_label.setText(
                f"Capturing on {interface} · promiscuous mode off"
            )
            self.statusBar().showMessage(
                f"Capture resumed on {interface} · {self.model.total_count:,} packets"
            )
        self._update_capture_controls()

    def stop_live_capture(self) -> None:
        if self._live_worker is None or not self._live_worker.isRunning():
            return

        self.stop_capture_button.setEnabled(False)
        self.pause_capture_button.setEnabled(False)
        self.pause_capture_action.setEnabled(False)
        self.stop_capture_action.setEnabled(False)
        self.capture_state_label.setText("Stopping live capture…")
        self.statusBar().showMessage("Stopping live capture…")
        self._live_capture_stopping = True
        self._live_worker.stop()
        self._update_capture_controls()

    def _on_live_packet_batch(self, packets: list[ProcessedPacket]) -> None:
        self.model.append_packets(packets)
        self._update_counts()
        interface = self._live_interface or "interface"
        paused = self._live_worker is not None and self._live_worker.is_paused
        state = "Paused" if paused else "Capturing"
        self.statusBar().showMessage(
            f"{state} on {interface} · {self.model.total_count:,} packets"
        )
        self._update_capture_controls()

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
        self._live_capture_stopping = False
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
        self.filter_status.setStyleSheet("color: #91a5b2; font-size: 9pt;")
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
        self._annotations = {}
        self.model.set_annotations(self._annotations)
        self._current_path = None
        self._live_interface = None
        self.file_label.setText("No capture loaded")
        self.filter_input.clear()
        self.filter_status.setText(
            "Filters: arp, ipv6, tcp, udp, icmp, IP addresses, ports, flags, frame length"
        )
        self.filter_status.setStyleSheet("color: #8297a4; font-size: 9pt;")
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
        self.hex_view.setExtraSelections([])
        self._hex_data_length = 0
        self.hex_status.setText("Select a decoded field to highlight its bytes.")
        self._update_capture_controls()

    def _show_packet_details(self, packet: ProcessedPacket) -> None:
        self._selected_packet = packet
        self.details_tree.clear()

        record = packet.record
        result = packet.dissection
        network_offset = result.ethernet.payload_offset if result.ethernet is not None else 0
        transport_offset = network_offset
        if result.ipv4 is not None:
            transport_offset += result.ipv4.header_length
        elif result.ipv6 is not None:
            transport_offset += result.ipv6.upper_layer_offset

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
            ], byte_ranges={
                "Destination": (0, 6),
                "Source": (6, 6),
                "Type / Length": (12, 2),
            })
            for index, tag in enumerate(eth.vlan_tags, start=1):
                vlan = QTreeWidgetItem(item, [f"802.1Q VLAN tag {index}", ""])
                self._add_child(vlan, "TPID", f"0x{tag.tpid:04x}")
                self._add_child(vlan, "VLAN ID", tag.vlan_id)
                self._add_child(vlan, "Priority", tag.priority)
                self._add_child(vlan, "Drop eligible", tag.drop_eligible)

        if result.arp is not None:
            arp = result.arp
            arp_ranges = {
                "Hardware type": (network_offset, 2),
                "Protocol type": (network_offset + 2, 2),
                "Hardware size": (network_offset + 4, 1),
                "Protocol size": (network_offset + 5, 1),
                "Opcode": (network_offset + 6, 2),
            }
            if arp.hardware_length == 6 and arp.protocol_length == 4:
                arp_ranges.update({
                    "Sender MAC address": (network_offset + 8, 6),
                    "Sender protocol address": (network_offset + 14, 4),
                    "Target MAC address": (network_offset + 18, 6),
                    "Target protocol address": (network_offset + 24, 4),
                })
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
            ], byte_ranges=arp_ranges)

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
                ("Fragment offset", f"{ip.fragment_offset} bytes"),
                ("TTL", ip.ttl),
                ("Protocol number", ip.protocol),
                ("Header checksum", f"0x{ip.header_checksum:04x}"),
                ("Truncated", ip.is_truncated),
            ], byte_ranges={
                "Identification": (network_offset + 4, 2),
                "TTL": (network_offset + 8, 1),
                "Protocol number": (network_offset + 9, 1),
                "Source address": (network_offset + 12, 4),
                "Destination address": (network_offset + 16, 4),
            })

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
            ], byte_ranges={
                "Payload length": (network_offset + 4, 2),
                "Initial next header": (network_offset + 6, 1),
                "Hop limit": (network_offset + 7, 1),
                "Source address": (network_offset + 8, 16),
                "Destination address": (network_offset + 24, 16),
            })
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
                byte_ranges={
                    "Type": (transport_offset, 1),
                    "Code": (transport_offset + 1, 1),
                    "Checksum": (transport_offset + 2, 2),
                },
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
            ], byte_ranges={
                "Source port": (transport_offset, 2),
                "Destination port": (transport_offset + 2, 2),
                "Sequence number": (transport_offset + 4, 4),
                "Acknowledgment number": (transport_offset + 8, 4),
                "Flags": (transport_offset + 13, 1),
                "Window size": (transport_offset + 14, 2),
                "Checksum": (transport_offset + 16, 2),
            })

        if result.udp is not None:
            udp = result.udp
            self._add_section("User Datagram Protocol", [
                ("Source port", udp.source_port),
                ("Destination port", udp.destination_port),
                ("Length", f"{udp.length} bytes"),
                ("Checksum", f"0x{udp.checksum:04x}"),
                ("Captured length", f"{udp.captured_length} bytes"),
                ("Truncated", udp.is_truncated),
            ], byte_ranges={
                "Source port": (transport_offset, 2),
                "Destination port": (transport_offset + 2, 2),
                "Length": (transport_offset + 4, 2),
                "Checksum": (transport_offset + 6, 2),
            })

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
        self._hex_data_length = len(record.data)
        self.hex_view.setExtraSelections([])
        self.hex_status.setText(
            f"{len(record.data):,} bytes · select a decoded field to highlight its captured byte range"
        )
        self._update_capture_controls()

    def _on_detail_field_changed(self, item, *_args) -> None:
        if item is None:
            self.hex_view.setExtraSelections([])
            return
        byte_range = item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(byte_range, (tuple, list)) or len(byte_range) != 2:
            self.hex_view.setExtraSelections([])
            self.hex_status.setText("This decoded field has no mapped byte range.")
            return
        self._highlight_packet_bytes(int(byte_range[0]), int(byte_range[1]))

    def _highlight_packet_bytes(self, offset: int, length: int) -> None:
        selections = []
        if offset < 0 or length <= 0 or offset >= self._hex_data_length:
            self.hex_view.setExtraSelections([])
            return
        end = min(offset + length, self._hex_data_length)
        current = offset
        while current < end:
            block_number = current // 16
            byte_column = current % 16
            count = min(end - current, 16 - byte_column)
            block = self.hex_view.document().findBlockByNumber(block_number)
            if not block.isValid():
                break
            cursor = QTextCursor(self.hex_view.document())
            start = block.position() + 10 + byte_column * 3
            cursor.setPosition(start)
            cursor.setPosition(start + count * 3 - 1, QTextCursor.MoveMode.KeepAnchor)
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format = QTextCharFormat()
            selection.format.setBackground(QColor("#35685f"))
            selection.format.setForeground(QColor("#ffffff"))
            selections.append(selection)
            current += count
        self.hex_view.setExtraSelections(selections)
        self.hex_status.setText(f"Bytes {offset:,}–{end - 1:,} · length {end - offset:,} bytes")

    def show_analysis_center(self) -> None:
        packets = tuple(self.model.iter_packets())
        if not packets:
            return
        dialog = AnalysisDialog(packets, self)
        dialog.packet_requested.connect(self.jump_to_packet)
        dialog.exec()

    def jump_to_packet(self, packet_number: int) -> None:
        row = self.model.row_for_packet_number(packet_number)
        if row < 0 and self.filter_input.text().strip():
            self.filter_input.clear()
            self.apply_filter()
            row = self.model.row_for_packet_number(packet_number)
        if row < 0:
            return
        index = self.model.index(row, 0)
        self.packet_table.setCurrentIndex(index)
        self.packet_table.scrollTo(index)
        self.statusBar().showMessage(f"Selected packet #{packet_number}")

    def find_packet(self) -> None:
        query, accepted = QInputDialog.getText(
            self, "Find packet", "Search packet fields, addresses or protocol metadata:"
        )
        needle = query.strip().casefold()
        if not accepted or not needle:
            return
        packets = tuple(self.model.iter_packets())
        if not packets:
            return
        start_number = self._selected_packet.number if self._selected_packet else 0
        ordered = [packet for packet in packets if packet.number > start_number]
        ordered.extend(packet for packet in packets if packet.number <= start_number)
        for packet in ordered:
            parts = [
                str(packet.number), packet.source, packet.destination,
                packet.protocol, packet.info,
                str(packet.source_port or ""), str(packet.destination_port or ""),
                *packet.dissection.errors,
            ]
            dns = packet.dissection.dns
            if dns is not None:
                parts.extend(question.name for question in dns.questions)
                parts.extend(record.data for record in dns.answers)
            http = packet.dissection.http
            if http is not None:
                parts.extend((http.host or "", http.target or "", http.method or "", str(http.status_code or "")))
            tls = packet.dissection.tls
            if tls is not None and tls.client_hello is not None:
                parts.append(tls.client_hello.server_name or "")
            if needle in " ".join(parts).casefold():
                self.jump_to_packet(packet.number)
                return
        QMessageBox.information(self, "No match", f'No packet matched "{query}".')

    def mark_packet_note(self) -> None:
        packet = self._selected_packet
        if packet is None:
            return
        current = self._annotations.get(packet.number, "")
        note, accepted = QInputDialog.getMultiLineText(
            self, f"Packet #{packet.number} note",
            "Add a note or leave it empty to remove the note:", current,
        )
        if not accepted:
            return
        if note.strip():
            self._annotations[packet.number] = note.strip()
        else:
            self._annotations.pop(packet.number, None)
        self.model.set_annotations(self._annotations)
        self._update_capture_controls()
        self.statusBar().showMessage(f"Packet note updated for #{packet.number}; save notes to keep them.")

    def remove_packet_note(self) -> None:
        if self._selected_packet is None:
            return
        number = self._selected_packet.number
        self._annotations.pop(number, None)
        self.model.set_annotations(self._annotations)
        self._update_capture_controls()
        self.statusBar().showMessage(f"Packet note removed from #{number}")

    def save_packet_notes(self) -> None:
        if not self._annotations:
            QMessageBox.information(self, "No packet notes", "There are no packet notes to save.")
            return
        default_path = (
            str(annotation_sidecar_path(self._current_path))
            if self._current_path is not None
            else str(Path.home() / "netview-notes.json")
        )
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save packet notes", default_path, "NetView notes (*.netview.json *.json)"
        )
        if not filename:
            return
        try:
            save_annotations(filename, self._annotations)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Could not save packet notes", str(exc))
            return
        self.statusBar().showMessage(f"Saved {len(self._annotations):,} packet note(s) to {filename}")

    def show_tcp_flow_graph(self) -> None:
        if self._flow_worker is not None and self._flow_worker.isRunning():
            return

        packet = self._selected_packet
        if packet is None:
            return
        key_result = tcp_flow_key_for_packet(packet)
        if key_result is None:
            QMessageBox.information(
                self,
                "TCP Flow Graph unavailable",
                "Select an unfragmented IPv4 or IPv6 TCP packet first.",
            )
            return

        flow_key, _direction = key_result
        packets = tuple(self.model.iter_packets())
        if not packets:
            return

        self.statusBar().showMessage("Building TCP Flow Graph…")
        self._flow_failed = False
        self._flow_worker = TCPFlowWorker(packets, flow_key, self)
        self._flow_worker.graph_ready.connect(self._on_tcp_flow_graph_ready)
        self._flow_worker.analysis_failed.connect(self._on_tcp_flow_graph_failed)
        self._flow_worker.finished.connect(self._on_tcp_flow_worker_finished)
        self._flow_worker.finished.connect(self._flow_worker.deleteLater)
        self._flow_worker.start()
        self._update_capture_controls()

    def _on_tcp_flow_graph_ready(self, graph) -> None:
        if graph is None:
            QMessageBox.information(
                self,
                "TCP conversation not found",
                "No packets for the selected TCP conversation were found in this capture.",
            )
            return
        dialog = TCPFlowGraphDialog(graph, self)
        dialog.exec()

    def _on_tcp_flow_graph_failed(self, message: str) -> None:
        self._flow_failed = True
        QMessageBox.critical(self, "TCP Flow Graph failed", message)
        self.statusBar().showMessage("TCP Flow Graph failed")

    def _on_tcp_flow_worker_finished(self) -> None:
        self._flow_worker = None
        self._update_capture_controls()
        if self._flow_failed:
            self.statusBar().showMessage("TCP Flow Graph failed")
        else:
            self.statusBar().showMessage("TCP Flow Graph ready")

    def follow_tcp_stream(self) -> None:
        if self._stream_worker is not None and self._stream_worker.isRunning():
            return

        packet = self._selected_packet
        if packet is None:
            return

        key_result = tcp_stream_key_for_packet(packet)
        if key_result is None:
            QMessageBox.information(
                self,
                "TCP stream unavailable",
                "Select an unfragmented IPv4 or IPv6 TCP packet first.",
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

    def _add_section(
        self,
        title: str,
        fields: list[tuple[str, object]],
        byte_ranges: dict[str, tuple[int, int]] | None = None,
    ) -> QTreeWidgetItem:
        section = QTreeWidgetItem(self.details_tree, [title, ""])
        section.setFlags(section.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        for name, value in fields:
            self._add_child(section, name, value, (byte_ranges or {}).get(name))
        return section

    @staticmethod
    def _add_child(
        parent: QTreeWidgetItem,
        name: str,
        value: object,
        byte_range: tuple[int, int] | None = None,
    ) -> None:
        item = QTreeWidgetItem(parent, [str(name), str(value)])
        if byte_range is not None:
            item.setData(0, Qt.ItemDataRole.UserRole, byte_range)

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
        if self._flow_worker is not None and self._flow_worker.isRunning():
            self._flow_worker.wait()
        event.accept()

    def _update_counts(self) -> None:
        self.count_status.setText(
            f"{self.model.visible_count:,} displayed / {self.model.total_count:,} total"
        )
