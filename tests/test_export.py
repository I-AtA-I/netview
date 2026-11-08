import csv

import pytest

from netview.capture import iter_capture_file
from netview.capture.export import export_packets, write_pcap, write_pcapng
from netview.core import PacketRecord, process_packet


def make_packet(number=1, *, link_type=1, timestamp=1234.56789, data=None):
    raw = data if data is not None else bytes.fromhex(
        "aabbccddeeff11223344556688b5" + "01020304"
    )
    record = PacketRecord(
        number=number,
        timestamp=timestamp,
        captured_length=len(raw),
        original_length=len(raw) + 4,
        link_type=link_type,
        data=raw,
    )
    return process_packet(record)


def test_classic_pcap_export_round_trips_packet_metadata(tmp_path):
    packet = make_packet()
    path = tmp_path / "export.pcap"

    write_pcap(path, [packet])
    loaded = list(iter_capture_file(path))

    assert len(loaded) == 1
    assert loaded[0].data == packet.record.data
    assert loaded[0].link_type == packet.record.link_type
    assert loaded[0].captured_length == packet.record.captured_length
    assert loaded[0].original_length == packet.record.original_length
    assert loaded[0].timestamp == pytest.approx(packet.timestamp, abs=0.000001)


def test_classic_pcap_rejects_mixed_link_types(tmp_path):
    packets = [make_packet(1, link_type=1), make_packet(2, link_type=101)]
    with pytest.raises(ValueError, match="one link type"):
        write_pcap(tmp_path / "mixed.pcap", packets)


def test_pcapng_export_supports_multiple_link_types(tmp_path):
    packets = [
        make_packet(1, link_type=1, timestamp=1234.25),
        make_packet(2, link_type=101, timestamp=1234.75),
    ]
    path = tmp_path / "mixed.pcapng"

    write_pcapng(path, packets)
    loaded = list(iter_capture_file(path))

    assert [packet.link_type for packet in loaded] == [1, 101]
    assert [packet.data for packet in loaded] == [
        packet.record.data for packet in packets
    ]
    assert loaded[0].timestamp == pytest.approx(1234.25)
    assert loaded[1].timestamp == pytest.approx(1234.75)


def test_export_dispatches_csv_and_writes_packet_metadata(tmp_path):
    packet = make_packet(timestamp=None)
    path = tmp_path / "export.csv"

    export_packets(path, [packet])

    with path.open(encoding="utf-8-sig", newline="") as source:
        rows = list(csv.DictReader(source))

    assert len(rows) == 1
    assert rows[0]["Number"] == "1"
    assert rows[0]["Protocol"] == packet.protocol
    assert rows[0]["Captured length"] == str(packet.captured_length)
    assert rows[0]["Timestamp"] == ""


def test_export_requires_supported_extension(tmp_path):
    with pytest.raises(ValueError, match="extension"):
        export_packets(tmp_path / "export.bin", [make_packet()])


def test_export_rejects_empty_packet_list(tmp_path):
    with pytest.raises(ValueError, match="no packets"):
        write_pcap(tmp_path / "empty.pcap", [])
