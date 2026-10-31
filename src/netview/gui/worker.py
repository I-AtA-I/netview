from pathlib import Path

from PySide6.QtCore import QThread, Signal

from netview.capture import iter_capture_file
from netview.core.pipeline import ProcessedPacket, process_packet


class CaptureLoadWorker(QThread):
    batch_ready = Signal(list)
    load_finished = Signal(int)
    load_failed = Signal(str)

    BATCH_SIZE = 500

    def __init__(self, path: str | Path, parent=None):
        super().__init__(parent)
        self.path = Path(path)

    def run(self) -> None:
        count = 0
        batch: list[ProcessedPacket] = []

        try:
            for record in iter_capture_file(self.path):
                if self.isInterruptionRequested():
                    break

                batch.append(process_packet(record))
                count += 1

                if len(batch) >= self.BATCH_SIZE:
                    self.batch_ready.emit(batch)
                    batch = []

            if batch:
                self.batch_ready.emit(batch)

            self.load_finished.emit(count)
        except Exception as exc:
            self.load_failed.emit(str(exc))
