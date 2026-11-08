from types import SimpleNamespace

from netview.gui.main_window import MainWindow


class FinishedWorker:
    can_pause = False
    is_paused = False

    def isRunning(self):
        return False


def test_actions_reenable_when_workers_have_finished(qtbot, monkeypatch):
    monkeypatch.setattr("netview.gui.main_window.list_interfaces", lambda: ["lo"])

    window = MainWindow()
    qtbot.addWidget(window)

    packet = SimpleNamespace(
        number=1,
        dissection=SimpleNamespace(
            ipv4=SimpleNamespace(
                is_fragment=False,
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
            ),
            ipv6=None,
            tcp=SimpleNamespace(source_port=50000, destination_port=80),
        ),
    )
    window.model.append_packets([packet])
    window._selected_packet = packet

    # Simulate the short period where the Python references still exist but
    # the QThreads have already stopped and Qt is processing finished events.
    window._worker = FinishedWorker()
    window._live_worker = FinishedWorker()
    window._stream_worker = FinishedWorker()

    window._update_capture_controls()

    assert window.statistics_action.isEnabled()
    assert window.follow_stream_action.isEnabled()
    assert window.follow_stream_button.isEnabled()
    assert window.start_capture_button.isEnabled()
    assert window.open_action.isEnabled()

    window.close()


class RunningWorker:
    can_pause = False
    is_paused = False

    def __init__(self):
        self.running = True

    def isRunning(self):
        return self.running

    def stop(self):
        self.running = False

    def wait(self):
        return True



def test_close_requests_analysis_worker_interruption_without_blocking(qtbot, monkeypatch):
    from PySide6.QtCore import QThread

    class InterruptibleWorker(QThread):
        def run(self):
            while not self.isInterruptionRequested():
                self.msleep(5)
            self.msleep(150)

    monkeypatch.setattr("netview.gui.main_window.list_interfaces", lambda: ["lo"])
    window = MainWindow()
    qtbot.addWidget(window)
    worker = InterruptibleWorker(window)
    window._stream_worker = worker
    window.show()
    worker.start()
    qtbot.waitUntil(worker.isRunning, timeout=3000)

    window.close()

    assert worker.isInterruptionRequested()
    assert window.isVisible()
    qtbot.waitUntil(lambda: not worker.isRunning(), timeout=3000)
    qtbot.waitUntil(lambda: not window.isVisible(), timeout=3000)


def test_packet_tools_remain_available_during_live_capture(qtbot, monkeypatch):
    monkeypatch.setattr("netview.gui.main_window.list_interfaces", lambda: ["lo"])

    window = MainWindow()
    qtbot.addWidget(window)

    packet = SimpleNamespace(
        number=1,
        dissection=SimpleNamespace(
            ipv4=SimpleNamespace(
                is_fragment=False,
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
            ),
            ipv6=None,
            tcp=SimpleNamespace(source_port=50000, destination_port=80),
        ),
    )
    window._selected_packet = packet
    window._live_worker = RunningWorker()

    # The first live batch must refresh Analyze actions without relying on
    # a later Stop/finished signal or a separate UI event.
    window._on_live_packet_batch([packet])

    assert window.statistics_action.isEnabled()
    assert window.follow_stream_action.isEnabled()
    assert window.follow_stream_button.isEnabled()
    assert not window.start_capture_button.isEnabled()
    assert not window.open_action.isEnabled()
    assert window.stop_capture_button.isEnabled()

    window.close()
