from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import threading
from time import monotonic

from PySide6.QtCore import QThread, Signal

from netview.capture import LiveCaptureError, iter_pcap_stream
from netview.capture.live import find_dumpcap
from netview.core.pipeline import ProcessedPacket, process_packet


class LiveCaptureWorker(QThread):
    """Run dumpcap and forward captured packets to the GUI."""

    batch_ready = Signal(list)
    capture_failed = Signal(str)
    capture_started = Signal()
    paused_changed = Signal(bool)

    FLUSH_INTERVAL_SECONDS = 0.1

    def __init__(self, interface: str, parent=None):
        super().__init__(parent)
        self.interface = interface
        self._stop_event = threading.Event()
        self._reader_done = threading.Event()
        self._batch_lock = threading.Lock()
        self._process_lock = threading.Lock()
        self._pending: list[ProcessedPacket] = []
        self._process: subprocess.Popen | None = None
        self._reader_error: Exception | None = None
        self._paused = False

    @property
    def is_paused(self) -> bool:
        with self._process_lock:
            return self._paused

    @property
    def can_pause(self) -> bool:
        with self._process_lock:
            process = self._process
            return (
                os.name in {"posix", "nt"}
                and process is not None
                and process.poll() is None
                and not self._reader_done.is_set()
                and not self._stop_event.is_set()
            )

    def pause(self) -> None:
        if os.name not in {"posix", "nt"}:
            raise LiveCaptureError(
                "Pausing live capture is not supported on this operating system."
            )

        with self._process_lock:
            process = self._process
            if process is None or process.poll() is not None:
                raise LiveCaptureError("The live capture process is not running.")
            if self._paused:
                return
            if self._stop_event.is_set() or self._reader_done.is_set():
                raise LiveCaptureError("The live capture is already stopping.")

            if os.name == "posix":
                try:
                    process.send_signal(signal.SIGSTOP)
                except OSError as exc:
                    raise LiveCaptureError(
                        f"Could not pause dumpcap: {exc}"
                    ) from exc

            # On Windows, keep reading dumpcap's output but discard packets
            # until resume() is called. This prevents the stdout pipe from filling.
            self._paused = True

        self.paused_changed.emit(True)

    def resume(self) -> None:
        if os.name not in {"posix", "nt"}:
            raise LiveCaptureError(
                "Resuming live capture is not supported on this operating system."
            )

        with self._process_lock:
            process = self._process
            if process is None or process.poll() is not None:
                was_paused = self._paused
                self._paused = False
                process_stopped = True
            else:
                process_stopped = False
                was_paused = False

                if not self._paused:
                    return
                if self._stop_event.is_set() or self._reader_done.is_set():
                    raise LiveCaptureError("The live capture is already stopping.")

                if os.name == "posix":
                    try:
                        process.send_signal(signal.SIGCONT)
                    except OSError as exc:
                        raise LiveCaptureError(
                            f"Could not resume dumpcap: {exc}"
                        ) from exc

                self._paused = False

        if process_stopped:
            if was_paused:
                self.paused_changed.emit(False)
            raise LiveCaptureError("The live capture process is no longer running.")

        self.paused_changed.emit(False)

    def stop(self) -> None:
        self._stop_event.set()
        was_paused = False

        with self._process_lock:
            process = self._process
            if process is None:
                return

            if self._paused:
                if process.poll() is None and os.name == "posix":
                    try:
                        process.send_signal(signal.SIGCONT)
                    except OSError:
                        pass

                self._paused = False
                was_paused = True

            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    pass

        if was_paused:
            self.paused_changed.emit(False)

    def _read_capture_output(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            self._reader_error = LiveCaptureError(
                "dumpcap capture stream is unavailable"
            )
            self._reader_done.set()
            return

        try:
            for record in iter_pcap_stream(process.stdout):
                if self._stop_event.is_set():
                    break

                with self._process_lock:
                    if self._paused:
                        continue

                processed = process_packet(record)

                # Check the pause state again after processing. If Pause was
                # pressed in the meantime, this packet must not be retained.
                with self._process_lock:
                    if self._paused or self._stop_event.is_set():
                        continue

                    with self._batch_lock:
                        self._pending.append(processed)

        except Exception as exc:
            if not self._stop_event.is_set():
                self._reader_error = exc
        finally:
            self._reader_done.set()

    def _flush_pending(self) -> None:
        with self._batch_lock:
            if not self._pending:
                return

            batch = self._pending
            self._pending = []

        self.batch_ready.emit(batch)

    @staticmethod
    def _format_dumpcap_error(
        stderr_text: str,
        interface: str,
        returncode: int,
    ) -> str:
        detail = stderr_text.strip()
        lowered = detail.lower()

        if "permission denied" in lowered or "operation not permitted" in lowered:
            return (
                f"dumpcap does not have permission to capture on {interface}. "
                "On Arch Linux, make sure your account is in the wireshark group, "
                "then log out of your desktop session and log back in."
            )

        if detail:
            return detail

        return f"dumpcap stopped with exit status {returncode}"

    def run(self) -> None:
        executable = find_dumpcap()
        if executable is None:
            self.capture_failed.emit(
                "dumpcap was not found. On Arch Linux, install it with: "
                "sudo pacman -S wireshark-cli"
            )
            return

        # Keep promiscuous mode off and use PCAP output for the packet reader.
        command = [
            executable,
            "-Q",
            "-p",
            "-i",
            self.interface,
            "-F",
            "pcap",
            "-w",
            "-",
        ]

        try:
            with tempfile.TemporaryFile(mode="w+b") as stderr_file:
                try:
                    self._process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=stderr_file,
                        bufsize=0,
                    )
                except OSError as exc:
                    self.capture_failed.emit(f"Could not start dumpcap: {exc}")
                    return

                reader = threading.Thread(
                    target=self._read_capture_output,
                    name="netview-dumpcap-reader",
                    daemon=True,
                )
                reader.start()
                self.capture_started.emit()

                stop_started_at: float | None = None
                forced_stop = False

                while not self._reader_done.wait(self.FLUSH_INTERVAL_SECONDS):
                    self._flush_pending()

                    process = self._process
                    if self._stop_event.is_set() and process is not None:
                        if process.poll() is None:
                            if stop_started_at is None:
                                stop_started_at = monotonic()
                                try:
                                    process.terminate()
                                except OSError:
                                    pass
                            elif (
                                not forced_stop
                                and monotonic() - stop_started_at >= 1.0
                            ):
                                forced_stop = True
                                try:
                                    process.kill()
                                except OSError:
                                    pass

                reader.join(timeout=2)
                self._flush_pending()

                process = self._process
                returncode = process.wait(timeout=3) if process is not None else 1

                stderr_file.seek(0)
                stderr_text = stderr_file.read().decode(
                    "utf-8",
                    errors="replace",
                )

                if self._reader_error is not None and not self._stop_event.is_set():
                    if returncode != 0 and stderr_text.strip():
                        message = self._format_dumpcap_error(
                            stderr_text,
                            self.interface,
                            returncode,
                        )
                    else:
                        message = str(self._reader_error)

                    self.capture_failed.emit(message)

                elif returncode != 0 and not self._stop_event.is_set():
                    self.capture_failed.emit(
                        self._format_dumpcap_error(
                            stderr_text,
                            self.interface,
                            returncode,
                        )
                    )

        except subprocess.TimeoutExpired:
            process = self._process
            if process is not None:
                process.kill()
                process.wait()

            if not self._stop_event.is_set():
                self.capture_failed.emit("dumpcap did not stop cleanly")

        finally:
            process = self._process

            with self._process_lock:
                self._paused = False

            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()

                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()