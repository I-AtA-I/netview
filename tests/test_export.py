import csv
import json

import pytest

from netview.capture.export import CaptureExportError, export_capture
from netview.capture.pcap import iter_capture_file
from netview.core import PacketRecord, process_packet


FRAME = bytes.fromhex("aabbccddeeff1122334455660800")


def _packet(number=1, link_type=1):
    record = PacketRecord(number, 1.25, len(FRAME), len(FRAME), link_type, FRAME)
    return process_packet(record)


def test_export_csv(tmp_path):
    path = tmp_path / "capture.csv"
    assert export_capture(path, [_packet()]) == 1
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["number"] == "1"
    assert rows[0]["protocol"] == "Unknown"


def test_export_json(tmp_path):
    path = tmp_path / "capture.json"
    export_capture(path, [_packet()])
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data[0]["timestamp"] == 1.25
    assert data[0]["captured_length"] == len(FRAME)


def test_export_rejects_mixed_linktypes(tmp_path):
    with pytest.raises(CaptureExportError):
        export_capture(tmp_path / "capture.pcap", [_packet(1, 1), _packet(2, 101)])


def test_export_rejects_empty_capture(tmp_path):
    with pytest.raises(CaptureExportError):
        export_capture(tmp_path / "capture.csv", [])


def test_export_pcap_round_trip(tmp_path):
    path = tmp_path / "capture.pcap"
    export_capture(path, [_packet()])
    packets = list(iter_capture_file(path))
    assert len(packets) == 1
    assert packets[0].data == FRAME
    assert packets[0].link_type == 1
