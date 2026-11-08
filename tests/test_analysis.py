from netview.core import PacketRecord, process_packet
from netview.core.analysis import analyze_capture


MAC_DST = bytes.fromhex("aabbccddeeff")
MAC_SRC = bytes.fromhex("112233445566")


def make_tcp_packet(
    number,
    *,
    source="10.0.0.1",
    destination="10.0.0.2",
    source_port=50000,
    destination_port=80,
    sequence=100,
    acknowledgment=0,
    flags=0x18,
    payload=b"",
    timestamp=None,
):
    tcp = bytearray(20)
    tcp[0:2] = source_port.to_bytes(2, "big")
    tcp[2:4] = destination_port.to_bytes(2, "big")
    tcp[4:8] = sequence.to_bytes(4, "big")
    tcp[8:12] = acknowledgment.to_bytes(4, "big")
    tcp[12] = 0x50
    tcp[13] = flags

    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (20 + len(tcp) + len(payload)).to_bytes(2, "big")
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = bytes(int(part) for part in source.split("."))
    ip[16:20] = bytes(int(part) for part in destination.split("."))

    frame = MAC_DST + MAC_SRC + b"\x08\x00" + bytes(ip) + bytes(tcp) + payload
    record = PacketRecord(
        number=number,
        timestamp=timestamp,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    )
    return process_packet(record)


def test_analysis_groups_bidirectional_conversation():
    packets = [
        make_tcp_packet(1, payload=b"hello", timestamp=10.0),
        make_tcp_packet(
            2,
            source="10.0.0.2",
            destination="10.0.0.1",
            source_port=80,
            destination_port=50000,
            sequence=900,
            payload=b"world",
            timestamp=11.0,
        ),
    ]

    result = analyze_capture(packets)

    assert result.packet_count == 2
    assert result.tcp_count == 2
    assert result.udp_count == 0
    assert len(result.conversations) == 1
    assert result.conversations[0].packet_count == 2
    assert result.conversations[0].byte_count == sum(packet.length for packet in packets)


def test_analysis_reports_overlapping_tcp_payload_as_heuristic():
    packets = [
        make_tcp_packet(1, sequence=100, payload=b"abcdef"),
        make_tcp_packet(2, sequence=103, payload=b"defghi"),
    ]

    result = analyze_capture(packets)

    assert len(result.tcp_diagnostics) == 1
    assert result.tcp_diagnostics[0].category == "Possible retransmission / overlap"
    assert result.tcp_diagnostics[0].packet_number == 2


def test_analysis_reports_repeated_ack_without_claiming_packet_loss():
    packets = [
        make_tcp_packet(1, flags=0x10, sequence=10, acknowledgment=200),
        make_tcp_packet(2, flags=0x10, sequence=10, acknowledgment=200),
        make_tcp_packet(3, flags=0x10, sequence=10, acknowledgment=200),
    ]

    result = analyze_capture(packets)

    assert [item.category for item in result.tcp_diagnostics] == [
        "Repeated ACK",
        "Repeated ACK",
    ]


def test_analysis_builds_timeline_and_endpoint_counts():
    packets = [
        make_tcp_packet(1, payload=b"a", timestamp=100.0),
        make_tcp_packet(2, payload=b"bb", timestamp=101.0),
        make_tcp_packet(3, payload=b"ccc", timestamp=103.0),
    ]

    result = analyze_capture(packets)

    assert sum(bucket.packet_count for bucket in result.traffic_buckets) == 3
    assert sum(bucket.byte_count for bucket in result.traffic_buckets) == result.byte_count
    assert result.endpoint_counts[0][1] >= 3


def test_empty_analysis_is_valid():
    result = analyze_capture([])

    assert result.packet_count == 0
    assert result.conversations == ()
    assert result.tcp_diagnostics == ()
    assert result.traffic_buckets == ()
