from ipaddress import IPv6Address

from netview.core import PacketRecord, process_packet
from netview.core.streams import StreamEndpoint, TCPStreamKey
from netview.core.tcp_flow import build_tcp_flow_graph, tcp_flow_key_for_packet


MAC_DST = bytes.fromhex("aabbccddeeff")
MAC_SRC = bytes.fromhex("112233445566")


def make_ipv4_tcp(
    number,
    *,
    source="10.0.0.1",
    destination="10.0.0.2",
    source_port=50000,
    destination_port=443,
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
    return process_packet(PacketRecord(
        number=number,
        timestamp=timestamp,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    ))


def make_ipv6_tcp(number, *, source="2001:db8::1", destination="2001:db8::2",
                  source_port=50000, destination_port=443, sequence=10,
                  acknowledgment=0, flags=0x18, payload=b"", timestamp=None):
    tcp = bytearray(20)
    tcp[0:2] = source_port.to_bytes(2, "big")
    tcp[2:4] = destination_port.to_bytes(2, "big")
    tcp[4:8] = sequence.to_bytes(4, "big")
    tcp[8:12] = acknowledgment.to_bytes(4, "big")
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
    return process_packet(PacketRecord(
        number=number,
        timestamp=timestamp,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    ))


def test_flow_graph_tracks_bidirectional_packets_and_time():
    packets = [
        make_ipv4_tcp(1, sequence=100, flags=0x02, timestamp=20.0),
        make_ipv4_tcp(2, source="10.0.0.2", destination="10.0.0.1",
                      source_port=443, destination_port=50000, sequence=700,
                      acknowledgment=101, flags=0x10, timestamp=20.01),
        make_ipv4_tcp(3, sequence=101, acknowledgment=701,
                      flags=0x18, payload=b"hello", timestamp=20.02),
    ]
    key, _ = tcp_flow_key_for_packet(packets[0])

    graph = build_tcp_flow_graph(packets, key)

    assert graph is not None
    assert graph.packet_count == 3
    assert graph.duration_seconds == 0.02
    assert [event.direction for event in graph.events] == [0, 1, 0]
    assert graph.events[1].acknowledgment_number == 101
    assert graph.events[2].sequence_offset == 0
    assert graph.events[2].payload_length == 5
    assert graph.events[0].flags == ("SYN",)


def test_flow_graph_marks_sequence_overlap_as_heuristic():
    packets = [
        make_ipv4_tcp(1, sequence=100, payload=b"abcdef", timestamp=1.0),
        make_ipv4_tcp(2, sequence=103, payload=b"defghi", timestamp=2.0),
    ]
    key, _ = tcp_flow_key_for_packet(packets[0])

    graph = build_tcp_flow_graph(packets, key)

    assert graph is not None
    assert graph.overlap_count == 1
    assert graph.events[1].possible_overlap


def test_flow_graph_supports_ipv6_tcp():
    packets = [
        make_ipv6_tcp(1, sequence=10, payload=b"one", timestamp=5.0),
        make_ipv6_tcp(2, source="2001:db8::2", destination="2001:db8::1",
                      source_port=443, destination_port=50000, sequence=20,
                      acknowledgment=13, flags=0x10, timestamp=5.5),
    ]
    key, direction = tcp_flow_key_for_packet(packets[0])

    graph = build_tcp_flow_graph(packets, key)

    assert direction == 0
    assert graph is not None
    assert graph.packet_count == 2
    assert graph.events[1].direction == 1
    assert graph.events[1].acknowledgment_number == 13
    assert graph.duration_seconds == 0.5


def test_flow_graph_does_not_mix_other_tcp_conversations():
    first = make_ipv4_tcp(1)
    other = make_ipv4_tcp(2, destination_port=80)
    key, _ = tcp_flow_key_for_packet(first)

    graph = build_tcp_flow_graph([first, other], key)

    assert graph is not None
    assert [event.packet_number for event in graph.events] == [1]


def test_flow_graph_returns_none_when_no_matching_conversation():
    packet = make_ipv4_tcp(1)
    other = make_ipv4_tcp(2, destination_port=80)
    other_key, _ = tcp_flow_key_for_packet(other)

    assert build_tcp_flow_graph([packet], other_key) is None


def test_flow_graph_key_is_direction_independent_for_ipv6():
    forward = make_ipv6_tcp(1)
    reverse = make_ipv6_tcp(2, source="2001:db8::2", destination="2001:db8::1",
                            source_port=443, destination_port=50000)
    first_key, first_direction = tcp_flow_key_for_packet(forward)
    second_key, second_direction = tcp_flow_key_for_packet(reverse)

    assert first_key == second_key
    assert first_direction == 0
    assert second_direction == 1
    assert isinstance(first_key, TCPStreamKey)
    assert first_key.endpoint_a == StreamEndpoint("2001:db8::1", 50000)
