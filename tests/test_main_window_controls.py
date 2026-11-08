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
        dissection=SimpleNamespace(ipv4=object(), tcp=object()),
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

    def isRunning(self):
        return True

    def stop(self):
        pass

    def wait(self):
        return True


def test_packet_tools_remain_available_while_capture_worker_stops(qtbot, monkeypatch):
    monkeypatch.setattr("netview.gui.main_window.list_interfaces", lambda: ["lo"])

    window = MainWindow()
    qtbot.addWidget(window)

    packet = SimpleNamespace(
        number=1,
        dissection=SimpleNamespace(ipv4=object(), tcp=object()),
    )
    window.model.append_packets([packet])
    window._selected_packet = packet
    window._live_worker = RunningWorker()
    window._live_capture_stopping = True

    window._update_capture_controls()

    assert window.statistics_action.isEnabled()
    assert window.follow_stream_action.isEnabled()
    assert window.follow_stream_button.isEnabled()
    assert not window.start_capture_button.isEnabled()
    assert not window.open_action.isEnabled()
    assert not window.stop_capture_button.isEnabled()

    window.close()
