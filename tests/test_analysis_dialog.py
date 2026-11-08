from threading import Event

from PySide6.QtCore import QThread

from netview.core.analysis import AnalysisCancelled
from netview.gui.analysis_dialog import AnalysisDialog


def test_analysis_dialog_populates_after_background_calculation(qtbot):
    dialog = AnalysisDialog([])
    qtbot.addWidget(dialog)
    dialog.show()

    qtbot.waitUntil(lambda: dialog.analysis is not None, timeout=3000)

    assert dialog.analysis.packet_count == 0
    dialog.close()


def test_analysis_dialog_cancels_worker_when_closed(qtbot, monkeypatch):
    started = Event()

    def blocked_analysis(_packets, *, should_stop):
        started.set()
        while not should_stop():
            QThread.msleep(5)
        raise AnalysisCancelled

    monkeypatch.setattr("netview.gui.analysis_dialog.analyze_capture", blocked_analysis)
    dialog = AnalysisDialog([])
    qtbot.addWidget(dialog)
    dialog.show()

    qtbot.waitUntil(started.is_set, timeout=3000)
    dialog.close()

    assert dialog.isVisible()
    qtbot.waitUntil(lambda: not dialog.isVisible(), timeout=3000)
