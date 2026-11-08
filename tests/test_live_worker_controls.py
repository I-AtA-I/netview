import os
import signal
from types import SimpleNamespace

import pytest

from netview.capture import LiveCaptureError
from netview.gui.live_worker import LiveCaptureWorker


posix_only = pytest.mark.skipif(
    os.name != "posix",
    reason="This test checks POSIX process signals.",
)

windows_only = pytest.mark.skipif(
    os.name != "nt",
    reason="This test checks Windows-specific behavior.",
)


class FakeProcess:
    def __init__(self):
        self.signals = []
        self.terminated = False

    def poll(self):
        return None

    def send_signal(self, value):
        self.signals.append(value)

    def terminate(self):
        self.terminated = True


def attach_running_process(worker):
    process = FakeProcess()
    worker._process = process
    return process


@posix_only
def test_pause_and_resume_keep_same_dumpcap_process():
    worker = LiveCaptureWorker("eth0")
    process = attach_running_process(worker)
    states = []
    worker.paused_changed.connect(states.append)

    assert worker.can_pause
    worker.pause()

    assert worker.is_paused
    assert process.signals == [signal.SIGSTOP]

    worker.resume()

    assert not worker.is_paused
    assert process.signals == [signal.SIGSTOP, signal.SIGCONT]
    assert worker._process is process
    assert states == [True, False]


@posix_only
def test_repeated_pause_and_resume_are_idempotent():
    worker = LiveCaptureWorker("eth0")
    process = attach_running_process(worker)

    worker.pause()
    worker.pause()
    worker.resume()
    worker.resume()

    assert process.signals == [signal.SIGSTOP, signal.SIGCONT]


@posix_only
def test_stop_while_paused_resumes_process_before_terminating():
    worker = LiveCaptureWorker("eth0")
    process = attach_running_process(worker)
    worker.pause()

    worker.stop()

    assert worker._stop_event.is_set()
    assert process.signals == [signal.SIGSTOP, signal.SIGCONT]
    assert process.terminated
    assert not worker.is_paused


@posix_only
def test_pause_requires_a_running_capture_process():
    worker = LiveCaptureWorker("eth0")

    with pytest.raises(LiveCaptureError, match="not running"):
        worker.pause()


@posix_only
def test_resume_of_dead_paused_process_resets_ui_state():
    class DeadProcess(FakeProcess):
        def poll(self):
            return 1

    worker = LiveCaptureWorker("eth0")
    worker._process = DeadProcess()
    worker._paused = True
    states = []
    worker.paused_changed.connect(states.append)

    with pytest.raises(LiveCaptureError, match="no longer running"):
        worker.resume()

    assert not worker.is_paused
    assert states == [False]


@posix_only
def test_capture_cannot_be_paused_after_reader_finishes():
    worker = LiveCaptureWorker("eth0")
    attach_running_process(worker)
    worker._reader_done.set()

    assert not worker.can_pause

    with pytest.raises(LiveCaptureError, match="stopping"):
        worker.pause()


@windows_only
def test_windows_pause_and_resume_keep_dumpcap_running():
    worker = LiveCaptureWorker("eth0")
    process = attach_running_process(worker)
    states = []
    worker.paused_changed.connect(states.append)

    assert worker.can_pause

    worker.pause()

    assert worker.is_paused
    assert worker.can_pause
    assert process.signals == []
    assert not process.terminated

    worker.resume()

    assert not worker.is_paused
    assert process.signals == []
    assert not process.terminated

    worker.pause()
    worker.stop()

    assert worker._stop_event.is_set()
    assert not worker.is_paused
    assert process.signals == []
    assert process.terminated
    assert states == [True, False, True, False]


def test_reader_discards_packets_while_paused(monkeypatch):
    worker = LiveCaptureWorker("eth0")
    worker._process = SimpleNamespace(stdout=object())
    worker._paused = True

    records = [object(), object()]

    monkeypatch.setattr(
        "netview.gui.live_worker.iter_pcap_stream",
        lambda _stream: iter(records),
    )

    def unexpected_processing(_record):
        pytest.fail("Packets must not be processed while capture is paused.")

    monkeypatch.setattr(
        "netview.gui.live_worker.process_packet",
        unexpected_processing,
    )

    worker._read_capture_output()

    assert worker._pending == []
    assert worker._reader_done.is_set()