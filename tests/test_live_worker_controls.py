import signal

import pytest

from netview.capture import LiveCaptureError
from netview.gui.live_worker import LiveCaptureWorker


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


def test_repeated_pause_and_resume_are_idempotent():
    worker = LiveCaptureWorker("eth0")
    process = attach_running_process(worker)

    worker.pause()
    worker.pause()
    worker.resume()
    worker.resume()

    assert process.signals == [signal.SIGSTOP, signal.SIGCONT]


def test_stop_while_paused_resumes_process_before_terminating():
    worker = LiveCaptureWorker("eth0")
    process = attach_running_process(worker)
    worker.pause()

    worker.stop()

    assert worker._stop_event.is_set()
    assert process.signals == [signal.SIGSTOP, signal.SIGCONT]
    assert process.terminated
    assert not worker.is_paused


def test_pause_requires_a_running_capture_process():
    worker = LiveCaptureWorker("eth0")

    with pytest.raises(LiveCaptureError, match="not running"):
        worker.pause()


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


def test_capture_cannot_be_paused_after_reader_finishes():
    worker = LiveCaptureWorker("eth0")
    attach_running_process(worker)
    worker._reader_done.set()

    assert not worker.can_pause
    with pytest.raises(LiveCaptureError, match="stopping"):
        worker.pause()
