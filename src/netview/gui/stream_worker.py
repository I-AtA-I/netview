from PySide6.QtCore import QThread, Signal

from netview.core.pipeline import ProcessedPacket
from netview.core.streams import TCPStream, TCPStreamKey, build_tcp_stream


class TCPStreamWorker(QThread):
    stream_ready = Signal(object)
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
            stream: TCPStream | None = build_tcp_stream(
                self.packets,
                self.target_key,
            )
            self.stream_ready.emit(stream)
        except Exception as exc:
            self.analysis_failed.emit(str(exc))
