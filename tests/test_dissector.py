from netview.core import (
    PacketRecord,
    dissect_ethernet_frame,
    dissect_packet,
)


DST = bytes.fromhex("aabbccddeeff")
SRC = bytes.fromhex("112233445566")


def make_tcp_segment(payload=b"hello"):
    header = bytearray(20)

    header[0:2] = (12345).to_bytes(2, "big")
    header[2:4] = (443).to_bytes(2, "big")
    header[4:8] = (1000).to_bytes(4, "big")
    header[8:12] = (2000).to_bytes(4, "big")
    header[12] = 0x50
    header[13] = 0x18

    return bytes(header) + payload


def make_udp_segment(payload=b"dns"):
    return (
        (5353).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )


def make_ipv4_packet(payload, protocol, fragment_offset=0):
    header = bytearray(20)

    header[0] = 0x45
    header[2:4] = (20 + len(payload)).to_bytes(2, "big")
    header[6:8] = fragment_offset.to_bytes(2, "big")
    header[8] = 64
    header[9] = protocol
    header[12:16] = bytes([192, 0, 2, 1])
    header[16:20] = bytes([198, 51, 100, 2])

    return bytes(header) + payload


def make_ethernet_frame(ip_packet, ether_type=0x0800):
    return (
        DST
        + SRC
        + ether_type.to_bytes(2, "big")
        + ip_packet
    )


def make_packet(frame, link_type=1):
    return PacketRecord(
        number=1,
        timestamp=1761860000.0,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=link_type,
        data=frame,
    )


def test_dissect_tcp_packet():
    tcp = make_tcp_segment(b"hello")
    ip = make_ipv4_packet(tcp, protocol=6)
    frame = make_ethernet_frame(ip)

    result = dissect_ethernet_frame(frame)

    assert result.protocol == "TCP"
    assert result.protocol_stack == ("Ethernet II", "IPv4", "TCP")

    assert result.ethernet.source_mac == "11:22:33:44:55:66"
    assert result.ipv4.source_ip == "192.0.2.1"

    assert result.tcp.source_port == 12345
    assert result.tcp.destination_port == 443
    assert result.tcp.is_ack
    assert result.tcp.is_psh

    assert result.payload == b"hello"
    assert result.errors == ()


def test_dissect_udp_packet():
    udp = make_udp_segment(b"dns")
    ip = make_ipv4_packet(udp, protocol=17)
    frame = make_ethernet_frame(ip)

    result = dissect_ethernet_frame(frame)

    assert result.protocol == "UDP"
    assert result.protocol_stack == ("Ethernet II", "IPv4", "UDP")

    assert result.udp.source_port == 5353
    assert result.udp.destination_port == 53
    assert result.payload == b"dns"
    assert result.errors == ()


def test_dissect_unknown_ethertype():
    frame = make_ethernet_frame(
        b"\x01\x02\x03\x04",
        ether_type=0x86DD,
    )

    result = dissect_ethernet_frame(frame)

    assert result.protocol == "EtherType 0x86dd"
    assert result.ethernet is not None
    assert result.ipv4 is None
    assert result.payload == b"\x01\x02\x03\x04"


def test_dissect_vlan_frame():
    tcp = make_tcp_segment()
    ip = make_ipv4_packet(tcp, protocol=6)

    frame = (
        DST
        + SRC
        + b"\x81\x00"
        + b"\x00\x64"
        + b"\x08\x00"
        + ip
    )

    result = dissect_ethernet_frame(frame)

    assert result.protocol == "TCP"
    assert result.ethernet.vlan_tags[0].vlan_id == 100
    assert result.tcp.destination_port == 443


def test_dissect_non_initial_fragment():
    tcp = make_tcp_segment()

    ip = make_ipv4_packet(
        tcp,
        protocol=6,
        fragment_offset=1,
    )

    result = dissect_ethernet_frame(make_ethernet_frame(ip))

    assert result.protocol == "IPv4 fragment"
    assert result.ipv4.is_fragment
    assert result.tcp is None
    assert result.payload == tcp


def test_dissect_malformed_ethernet():
    result = dissect_ethernet_frame(b"\x00" * 5)

    assert result.ethernet is None
    assert result.errors
    assert result.protocol == "Unknown"


def test_dissect_malformed_ipv4():
    frame = make_ethernet_frame(b"\x00" * 10)

    result = dissect_ethernet_frame(frame)

    assert result.ethernet is not None
    assert result.ipv4 is None
    assert result.errors[0].startswith("IPv4:")


def test_dissect_malformed_tcp():
    ip = make_ipv4_packet(b"\x00" * 10, protocol=6)
    frame = make_ethernet_frame(ip)

    result = dissect_ethernet_frame(frame)

    assert result.ipv4 is not None
    assert result.tcp is None
    assert result.protocol == "TCP"
    assert result.errors[0].startswith("TCP:")


def test_dissect_packet_unsupported_link_type():
    packet = make_packet(b"\x00" * 20, link_type=101)

    result = dissect_packet(packet)

    assert result.protocol == "Unsupported link type 101"
    assert result.ethernet is None
    assert result.errors
