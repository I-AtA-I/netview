from ipaddress import IPv6Address

from netview.core import PacketRecord, process_packet
from netview.core.streams import build_tcp_streams, tcp_stream_key_for_packet


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
    flags=0x18,
    payload=b"",
    declared_payload_length=None,
    timestamp=None,
):
    tcp = bytearray(20)
    tcp[0:2] = source_port.to_bytes(2, "big")
    tcp[2:4] = destination_port.to_bytes(2, "big")
    tcp[4:8] = sequence.to_bytes(4, "big")
    tcp[12] = 0x50
    tcp[13] = flags

    ip = bytearray(20)
    ip[0] = 0x45
    expected_payload = (
        len(payload)
        if declared_payload_length is None
        else declared_payload_length
    )
    ip_total_length = 20 + len(tcp) + expected_payload
    ip[2:4] = ip_total_length.to_bytes(2, "big")
    ip[8] = 64
    ip[9] = 6
    ip[12:16] = bytes(int(part) for part in source.split("."))
    ip[16:20] = bytes(int(part) for part in destination.split("."))

    frame = MAC_DST + MAC_SRC + b"\x08\x00" + bytes(ip) + bytes(tcp) + payload
    record = PacketRecord(
        number=number,
        timestamp=timestamp,
        captured_length=len(frame),
        original_length=max(len(frame), 14 + ip_total_length),
        link_type=1,
        data=frame,
    )
    return process_packet(record)


def make_ipv6_tcp_packet(
    number,
    *,
    source="2001:db8::1",
    destination="2001:db8::2",
    source_port=50000,
    destination_port=80,
    sequence=100,
    flags=0x18,
    payload=b"",
    timestamp=None,
):
    tcp = bytearray(20)
    tcp[0:2] = source_port.to_bytes(2, "big")
    tcp[2:4] = destination_port.to_bytes(2, "big")
    tcp[4:8] = sequence.to_bytes(4, "big")
    tcp[12] = 0x50
    tcp[13] = flags

    ip = bytearray(40)
    ip[0] = 0x60
    ip[4:6] = (len(tcp) + len(payload)).to_bytes(2, "big")
    ip[6] = 6
    ip[7] = 64
    ip[8:24] = IPv6Address(source).packed
    ip[24:40] = IPv6Address(destination).packed

    frame = MAC_DST + MAC_SRC + b"\x86\xdd" + bytes(ip) + bytes(tcp) + payload
    record = PacketRecord(
        number=number,
        timestamp=timestamp,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    )
    return process_packet(record)


def test_reassemble_bidirectional_stream():
    packets = [
        make_tcp_packet(1, sequence=100, payload=b"hello"),
        make_tcp_packet(
            2,
            source="10.0.0.2",
            destination="10.0.0.1",
            source_port=80,
            destination_port=50000,
            sequence=900,
            payload=b"world",
        ),
    ]

    streams = build_tcp_streams(packets)

    assert len(streams) == 1
    stream = streams[0]
    assert stream.packet_count == 2
    assert stream.directions[0].chunks[0].data == b"hello"
    assert stream.directions[1].chunks[0].data == b"world"
    assert stream.payload_length == 10


def test_reassemble_bidirectional_ipv6_stream():
    packets = [
        make_ipv6_tcp_packet(1, sequence=100, payload=b"hello"),
        make_ipv6_tcp_packet(
            2,
            source="2001:db8::2",
            destination="2001:db8::1",
            source_port=80,
            destination_port=50000,
            sequence=900,
            payload=b"world",
        ),
    ]

    streams = build_tcp_streams(packets)

    assert len(streams) == 1
    stream = streams[0]
    assert stream.packet_count == 2
    assert stream.directions[0].chunks[0].data == b"hello"
    assert stream.directions[1].chunks[0].data == b"world"
    assert stream.payload_length == 10


def test_out_of_order_segments_are_reassembled():
    packets = [
        make_tcp_packet(1, sequence=103, payload=b"def"),
        make_tcp_packet(2, sequence=100, payload=b"abc"),
    ]

    direction = build_tcp_streams(packets)[0].directions[0]

    assert len(direction.chunks) == 1
    assert direction.chunks[0].sequence_offset == -3
    assert direction.chunks[0].data == b"abcdef"
    assert direction.gaps == ()


def test_missing_sequence_range_is_reported_as_gap():
    packets = [
        make_tcp_packet(1, sequence=100, payload=b"abc"),
        make_tcp_packet(2, sequence=106, payload=b"ghi"),
    ]

    direction = build_tcp_streams(packets)[0].directions[0]

    assert [chunk.data for chunk in direction.chunks] == [b"abc", b"ghi"]
    assert len(direction.gaps) == 1
    assert direction.gaps[0].start_offset == 3
    assert direction.gaps[0].end_offset == 6
    assert direction.gaps[0].length == 3


def test_overlapping_retransmitted_bytes_are_counted():
    packets = [
        make_tcp_packet(1, sequence=100, payload=b"abcdef"),
        make_tcp_packet(2, sequence=103, payload=b"defghi"),
    ]

    direction = build_tcp_streams(packets)[0].directions[0]

    assert direction.chunks[0].data == b"abcdefghi"
    assert direction.overlapping_bytes == 3
    assert direction.gaps == ()


def test_duplicate_segment_does_not_duplicate_payload():
    packets = [
        make_tcp_packet(1, sequence=100, payload=b"same"),
        make_tcp_packet(2, sequence=100, payload=b"same"),
    ]

    direction = build_tcp_streams(packets)[0].directions[0]

    assert direction.chunks[0].data == b"same"
    assert direction.payload_length == 4
    assert direction.overlapping_bytes == 4


def test_sequence_number_wraparound():
    packets = [
        make_tcp_packet(1, sequence=0xFFFFFFFE, payload=b"ab"),
        make_tcp_packet(2, sequence=0, payload=b"cd"),
    ]

    direction = build_tcp_streams(packets)[0].directions[0]

    assert len(direction.chunks) == 1
    assert direction.chunks[0].data == b"abcd"
    assert direction.gaps == ()


def test_syn_consumes_one_sequence_number():
    packets = [
        make_tcp_packet(1, sequence=100, flags=0x02),
        make_tcp_packet(2, sequence=101, flags=0x18, payload=b"hi"),
    ]

    stream = build_tcp_streams(packets)[0]
    direction = stream.directions[0]

    assert direction.packet_count == 2
    assert direction.payload_segment_count == 1
    assert direction.chunks[0].sequence_offset == 0
    assert direction.chunks[0].data == b"hi"


def test_truncated_tcp_payload_is_reported():
    packet = make_tcp_packet(
        7,
        sequence=100,
        payload=b"abc",
        declared_payload_length=8,
    )

    direction = build_tcp_streams([packet])[0].directions[0]

    assert direction.chunks[0].data == b"abc"
    assert direction.truncated_packet_numbers == (7,)


def test_empty_ack_packet_still_counts_in_stream():
    packet = make_tcp_packet(1, flags=0x10, sequence=100, payload=b"")

    stream = build_tcp_streams([packet])[0]
    direction = stream.directions[0]

    assert stream.packet_count == 1
    assert direction.packet_count == 1
    assert direction.payload_segment_count == 0
    assert direction.chunks == ()


def test_non_tcp_packets_do_not_create_streams():
    tcp = make_tcp_packet(1)
    # Mutate the IPv4 protocol field to UDP; the TCP parser is not reached.
    frame = bytearray(tcp.record.data)
    frame[23] = 17
    udp_like = process_packet(
        PacketRecord(
            number=2,
            timestamp=1.0,
            captured_length=len(frame),
            original_length=len(frame),
            link_type=1,
            data=bytes(frame),
        )
    )

    assert build_tcp_streams([udp_like]) == []


def test_flow_key_is_direction_independent():
    forward = make_tcp_packet(1)
    reverse = make_tcp_packet(
        2,
        source="10.0.0.2",
        destination="10.0.0.1",
        source_port=80,
        destination_port=50000,
    )

    forward_key, forward_direction = tcp_stream_key_for_packet(forward)
    reverse_key, reverse_direction = tcp_stream_key_for_packet(reverse)

    assert forward_key == reverse_key
    assert forward_direction == 0
    assert reverse_direction == 1


def test_different_tcp_tuples_create_separate_streams():
    packets = [
        make_tcp_packet(1),
        make_tcp_packet(2, destination_port=443),
    ]

    streams = build_tcp_streams(packets)

    assert len(streams) == 2
    assert [stream.stream_id for stream in streams] == [0, 1]


def test_build_only_selected_stream():
    from netview.core.streams import build_tcp_stream

    first = make_tcp_packet(1, sequence=100, payload=b"one")
    second = make_tcp_packet(2, destination_port=443, sequence=200, payload=b"two")
    third = make_tcp_packet(3, sequence=103, payload=b"-more")
    target_key, _ = tcp_stream_key_for_packet(first)

    stream = build_tcp_stream([first, second, third], target_key)

    assert stream is not None
    assert stream.key == target_key
    assert stream.stream_id == 0
    assert stream.directions[0].chunks[0].data == b"one-more"


def test_selected_stream_keeps_global_stream_id():
    from netview.core.streams import build_tcp_stream

    other = make_tcp_packet(1, destination_port=443, sequence=100, payload=b"x")
    target = make_tcp_packet(2, destination_port=80, sequence=200, payload=b"y")
    target_key, _ = tcp_stream_key_for_packet(target)

    stream = build_tcp_stream([other, target], target_key)

    assert stream is not None
    assert stream.stream_id == 1


def test_ip_fragment_is_excluded_until_ip_reassembly_exists():
    packet = make_tcp_packet(1, sequence=100, payload=b"part")
    frame = bytearray(packet.record.data)
    # IPv4 flags/fragment offset field: set MF on the first fragment.
    frame[20:22] = (0x2000).to_bytes(2, "big")
    fragment = process_packet(
        PacketRecord(
            number=2,
            timestamp=1.0,
            captured_length=len(frame),
            original_length=len(frame),
            link_type=1,
            data=bytes(frame),
        )
    )

    assert fragment.dissection.tcp is not None
    assert build_tcp_streams([fragment]) == []
