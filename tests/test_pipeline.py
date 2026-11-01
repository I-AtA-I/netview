from netview.core import (
    PacketRecord,
    iter_processed_packets,
    process_packet,
)


DST = bytes.fromhex("aabbccddeeff")
SRC = bytes.fromhex("112233445566")


def make_tcp_packet(number=1):
    tcp = bytearray(20)
    tcp[0:2] = (12345).to_bytes(2, "big")
    tcp[2:4] = (443).to_bytes(2, "big")
    tcp[4:8] = (1000).to_bytes(4, "big")
    tcp[8:12] = (2000).to_bytes(4, "big")
    tcp[12] = 0x50
    tcp[13] = 0x18

    payload = b"hello"

    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (20 + len(tcp) + len(payload)).to_bytes(2, "big")
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = bytes([192, 0, 2, 1])
    ip[16:20] = bytes([198, 51, 100, 2])

    frame = DST + SRC + b"\x08\x00" + bytes(ip) + bytes(tcp) + payload

    return PacketRecord(
        number=number,
        timestamp=1234.5,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    )


def make_udp_packet():
    payload = b"dns"

    udp = (
        (5353).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )

    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (20 + len(udp)).to_bytes(2, "big")
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = bytes([192, 0, 2, 1])
    ip[16:20] = bytes([198, 51, 100, 2])

    frame = DST + SRC + b"\x08\x00" + bytes(ip) + udp

    return PacketRecord(
        number=1,
        timestamp=None,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    )


def test_process_tcp_packet():
    processed = process_packet(make_tcp_packet())

    assert processed.number == 1
    assert processed.timestamp == 1234.5
    assert processed.protocol == "TCP"
    assert processed.source == "192.0.2.1"
    assert processed.destination == "198.51.100.2"
    assert processed.source_port == 12345
    assert processed.destination_port == 443
    assert processed.length == processed.captured_length
    assert "ACK" in processed.info
    assert "PSH" in processed.info
    assert processed.dissection.errors == ()


def test_process_udp_packet():
    processed = process_packet(make_udp_packet())

    assert processed.protocol == "UDP"
    assert processed.timestamp is None
    assert processed.source_port == 5353
    assert processed.destination_port == 53
    assert processed.info == "5353 → 53 Len=3"


def test_process_unknown_ethertype():
    frame = DST + SRC + b"\x88\xb5" + b"\x00" * 10

    packet = PacketRecord(
        number=1,
        timestamp=1.0,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    )

    processed = process_packet(packet)

    assert processed.protocol == "EtherType 0x88b5"
    assert processed.source == "11:22:33:44:55:66"
    assert processed.destination == "aa:bb:cc:dd:ee:ff"
    assert processed.source_port is None


def test_process_malformed_packet():
    packet = PacketRecord(
        number=1,
        timestamp=1.0,
        captured_length=5,
        original_length=5,
        link_type=1,
        data=b"\x00" * 5,
    )

    processed = process_packet(packet)

    assert processed.protocol == "Unknown"
    assert processed.source == "—"
    assert processed.dissection.errors
    assert processed.info.startswith("Ethernet:")


def test_iter_processed_packets():
    packets = [
        make_tcp_packet(number=1),
        make_udp_packet(),
        make_tcp_packet(number=3),
    ]

    processed = list(iter_processed_packets(iter(packets)))

    assert len(processed) == 3
    assert [packet.number for packet in processed] == [1, 1, 3]
    assert [packet.protocol for packet in processed] == [
        "TCP",
        "UDP",
        "TCP",
    ]


def test_pipeline_is_lazy():
    processed = iter_processed_packets(
        make_tcp_packet(number=i)
        for i in range(1, 4)
    )

    first = next(processed)

    assert first.number == 1
    assert first.protocol == "TCP"

    second = next(processed)

    assert second.number == 2
