from PySide6.QtCore import QThread, Signal

from netview.core.pipeline import ProcessedPacket
from netview.core.streams import TCPStreamKey
from netview.core.tcp_flow import TCPFlowGraph, build_tcp_flow_graph


class TCPFlowWorker(QThread):
    graph_ready = Signal(object)
    analysis_failed = Signal(str)

    def __init__(
        self,
        packets: tuple[ProcessedPacket, ...],
        target_key: TCPStreamKey,
        parent=None,
    ):
        super().__init__(parent)
        self.packets = packets
        self.target_key = target_key

    def run(self) -> None:
        try:
            graph: TCPFlowGraph | None = build_tcp_flow_graph(
                self.packets,
                self.target_key,
                should_stop=self.isInterruptionRequested,
            )
            if not self.isInterruptionRequested():
                self.graph_ready.emit(graph)
        except Exception as exc:
            if not self.isInterruptionRequested():
                self.analysis_failed.emit(str(exc))
