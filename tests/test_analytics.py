import pytest

from netview.core import PacketRecord, process_packet
from netview.core.analytics import analyze_capture


def _packet(number, timestamp, src, dst, protocol=17, payload=b"x"):
    udp = (
        (12000).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (20 + len(udp)).to_bytes(2, "big")
    ip[8] = 64
    ip[9] = protocol
    ip[12:16] = bytes(src)
    ip[16:20] = bytes(dst)
    frame = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + bytes(ip) + udp
    record = PacketRecord(number, timestamp, len(frame), len(frame), 1, frame)
    return process_packet(record)


def test_analyze_capture_totals_and_protocols():
    packets = [
        _packet(1, 10.1, (192, 0, 2, 1), (198, 51, 100, 2)),
        _packet(2, 11.2, (192, 0, 2, 1), (198, 51, 100, 2)),
    ]
    stats = analyze_capture(packets)

    assert stats.packet_count == 2
    assert stats.captured_bytes == sum(p.record.captured_length for p in packets)
    assert stats.wire_bytes == stats.captured_bytes
    assert stats.duration == pytest.approx(1.1)
    assert stats.protocols[0].protocol == "UDP"
    assert stats.protocols[0].packets == 2
    assert stats.conversations[0].packets == 2
    assert stats.timeline[0].packets == 1


def test_analyze_empty_capture():
    stats = analyze_capture([])
    assert stats.packet_count == 0
    assert stats.start_time is None
    assert stats.protocols == ()


def test_analyze_rejects_invalid_bucket():
    with pytest.raises(ValueError):
        analyze_capture([], bucket_seconds=0)
