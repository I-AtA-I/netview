import pytest

from netview.core import (
    ARPParseError,
    IPv6ParseError,
    PacketRecord,
    dissect_ethernet_frame,
    parse_arp_packet,
    parse_ipv6_packet,
    process_packet,
)
from netview.filters import FilterSyntaxError, compile_filter


DST_MAC = bytes.fromhex("ffffffffffff")
SRC_MAC = bytes.fromhex("001122334455")


def ethernet(payload: bytes, ethertype: int) -> bytes:
    return DST_MAC + SRC_MAC + ethertype.to_bytes(2, "big") + payload


def make_arp_request() -> bytes:
    sender_mac = bytes.fromhex("001122334455")
    sender_ip = bytes([192, 0, 2, 10])
    target_mac = b"\x00" * 6
    target_ip = bytes([192, 0, 2, 1])
    arp = (
        b"\x00\x01"  # Ethernet
        + b"\x08\x00"  # IPv4
        + b"\x06\x04"  # address sizes
        + b"\x00\x01"  # request
        + sender_mac
        + sender_ip
        + target_mac
        + target_ip
    )
    return ethernet(arp, 0x0806)


def make_ipv6_packet(payload: bytes, next_header: int, *, extensions: bytes = b"") -> bytes:
    full_payload = extensions + payload
    header = bytearray(40)
    header[0] = 0x60
    header[1] = 0x2A  # traffic class 0x02, start of flow label
    header[2:4] = b"\x12\x34"
    header[4:6] = len(full_payload).to_bytes(2, "big")
    header[6] = next_header
    header[7] = 48
    header[8:24] = bytes.fromhex("20010db8000000000000000000000001")
    header[24:40] = bytes.fromhex("20010db8000000000000000000000002")
    return bytes(header) + full_payload


def make_tcp_segment() -> bytes:
    header = bytearray(20)
    header[0:2] = (12345).to_bytes(2, "big")
    header[2:4] = (443).to_bytes(2, "big")
    header[4:8] = (100).to_bytes(4, "big")
    header[8:12] = (200).to_bytes(4, "big")
    header[12] = 0x50
    header[13] = 0x18
    return bytes(header) + b"hello"


def make_icmp(version: int, message_type: int, code: int = 0) -> bytes:
    return bytes([message_type, code]) + b"\x12\x34" + b"\x00\x07\x00\x09" + b"ping"


def packet_for(frame: bytes):
    return process_packet(PacketRecord(
        number=1,
        timestamp=1.0,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    ))


def test_arp_request_is_decoded():
    frame = make_arp_request()
    result = dissect_ethernet_frame(frame)

    assert result.protocol == "ARP"
    assert result.protocol_stack == ("Ethernet II", "ARP")
    assert result.arp is not None
    assert result.arp.operation == "Request"
    assert result.arp.sender_hardware_address == "00:11:22:33:44:55"
    assert result.arp.sender_protocol_address == "192.0.2.10"
    assert result.arp.target_protocol_address == "192.0.2.1"
    assert result.errors == ()


def test_arp_packet_table_values_and_info():
    packet = packet_for(make_arp_request())

    assert packet.protocol == "ARP"
    assert packet.source == "192.0.2.10"
    assert packet.destination == "192.0.2.1"
    assert packet.info == "Who has 192.0.2.1? Tell 192.0.2.10"


def test_arp_truncated_addresses_are_rejected():
    with pytest.raises(ARPParseError):
        parse_arp_packet(b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 4)


def test_ipv6_tcp_is_decoded():
    frame = ethernet(make_ipv6_packet(make_tcp_segment(), 6), 0x86DD)
    result = dissect_ethernet_frame(frame)

    assert result.protocol == "TCP"
    assert result.protocol_stack == ("Ethernet II", "IPv6", "TCP")
    assert result.ipv6.source_ip == "2001:db8::1"
    assert result.ipv6.destination_ip == "2001:db8::2"
    assert result.ipv6.hop_limit == 48
    assert result.tcp.destination_port == 443
    assert result.payload == b"hello"


def test_ipv6_hop_by_hop_extension_is_skipped():
    tcp = make_tcp_segment()
    # Hop-by-Hop header: next header TCP, extension length 0 => 8 bytes.
    hop_options = b"\x06\x00" + b"\x00" * 6
    ipv6 = make_ipv6_packet(tcp, 0, extensions=hop_options)
    frame = ethernet(ipv6, 0x86DD)

    result = dissect_ethernet_frame(frame)

    assert result.protocol == "TCP"
    assert result.ipv6.upper_layer_protocol == 6
    assert result.ipv6.upper_layer_offset == 48
    assert result.ipv6.extension_headers[0].name == "Hop-by-Hop Options"
    assert result.tcp.destination_port == 443


def test_ipv6_non_initial_fragment_is_not_misparsed_as_tcp():
    tcp = make_tcp_segment()
    fragment = b"\x06\x00\x00\x08\x12\x34\x56\x78"
    ipv6 = make_ipv6_packet(tcp, 44, extensions=fragment)
    result = dissect_ethernet_frame(ethernet(ipv6, 0x86DD))

    assert result.protocol == "IPv6 fragment"
    assert result.ipv6.fragment_offset == 8
    assert result.tcp is None


def test_ipv6_bad_version_is_rejected():
    with pytest.raises(IPv6ParseError):
        parse_ipv6_packet(b"\x40" + b"\x00" * 39)


def test_icmpv4_echo_is_decoded():
    icmp = make_icmp(4, 8)
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    ipv4[2:4] = (20 + len(icmp)).to_bytes(2, "big")
    ipv4[8] = 64
    ipv4[9] = 1
    ipv4[12:16] = bytes([192, 0, 2, 10])
    ipv4[16:20] = bytes([192, 0, 2, 1])
    result = dissect_ethernet_frame(ethernet(bytes(ipv4) + icmp, 0x0800))

    assert result.protocol == "ICMP"
    assert result.icmp.type_name == "Echo Request"
    assert result.icmp.identifier == 7
    assert result.icmp.sequence_number == 9


def test_icmpv6_echo_is_decoded():
    icmp = make_icmp(6, 128)
    frame = ethernet(make_ipv6_packet(icmp, 58), 0x86DD)
    result = dissect_ethernet_frame(frame)

    assert result.protocol == "ICMPv6"
    assert result.icmp.version == 6
    assert result.icmp.type_name == "Echo Request"


def test_known_non_decoded_ethertypes_get_names():
    for ethertype, expected in (
        (0x88CC, "LLDP"),
        (0x888E, "EAPOL"),
        (0x8847, "MPLS"),
        (0x8863, "PPPoE Discovery"),
    ):
        result = dissect_ethernet_frame(ethernet(b"\x00" * 16, ethertype))
        assert result.protocol == expected


def test_display_filters_recognize_new_protocols():
    arp_packet = packet_for(make_arp_request())
    tcp_segment = make_tcp_segment()
    ipv6_packet = packet_for(ethernet(make_ipv6_packet(tcp_segment, 6), 0x86DD))

    assert compile_filter("arp").matches(arp_packet)
    assert not compile_filter("ipv6").matches(arp_packet)
    assert compile_filter("ipv6").matches(ipv6_packet)
    assert compile_filter("ipv6.src == 2001:db8::1").matches(ipv6_packet)
    assert compile_filter("ipv6.hlim == 48").matches(ipv6_packet)
    assert compile_filter("tcp.port == 443").matches(ipv6_packet)
    assert compile_filter("arp.opcode == 1").matches(arp_packet)
    assert compile_filter("arp.src.proto_ipv4 == 192.0.2.10").matches(arp_packet)


def test_invalid_ipv6_filter_address():
    with pytest.raises(FilterSyntaxError):
        compile_filter("ipv6.src == not-an-ip")


def test_arp_reply_info():
    sender_mac = bytes.fromhex("aabbccddeeff")
    sender_ip = bytes([192, 0, 2, 1])
    target_mac = bytes.fromhex("001122334455")
    target_ip = bytes([192, 0, 2, 10])
    arp = (
        b"\x00\x01\x08\x00\x06\x04\x00\x02"
        + sender_mac + sender_ip + target_mac + target_ip
    )
    packet = packet_for(ethernet(arp, 0x0806))

    assert packet.protocol == "ARP"
    assert packet.info == "192.0.2.1 is at aa:bb:cc:dd:ee:ff"


def test_ipv6_udp_is_decoded():
    payload = b"dns"
    udp = (
        (5353).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x00\x00"
        + payload
    )
    result = dissect_ethernet_frame(
        ethernet(make_ipv6_packet(udp, 17), 0x86DD)
    )

    assert result.protocol == "UDP"
    assert result.udp.source_port == 5353
    assert result.udp.destination_port == 53
    assert result.payload == payload


def test_icmpv6_filter_fields():
    packet = packet_for(
        ethernet(make_ipv6_packet(make_icmp(6, 128), 58), 0x86DD)
    )

    assert compile_filter("icmpv6").matches(packet)
    assert compile_filter("icmpv6.type == 128").matches(packet)
    assert not compile_filter("icmp").matches(packet)


def test_icmpv4_filter_fields():
    icmp = make_icmp(4, 8)
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    ipv4[2:4] = (20 + len(icmp)).to_bytes(2, "big")
    ipv4[8] = 64
    ipv4[9] = 1
    ipv4[12:16] = bytes([192, 0, 2, 10])
    ipv4[16:20] = bytes([192, 0, 2, 1])
    packet = packet_for(ethernet(bytes(ipv4) + icmp, 0x0800))

    assert compile_filter("icmp").matches(packet)
    assert compile_filter("icmp.type == 8").matches(packet)
    assert not compile_filter("icmpv6").matches(packet)


def test_ipv6_fragment_filter():
    tcp = make_tcp_segment()
    fragment = b"\x06\x00\x00\x00\x12\x34\x56\x78"
    packet = packet_for(
        ethernet(make_ipv6_packet(tcp, 44, extensions=fragment), 0x86DD)
    )

    assert compile_filter("fragment").matches(packet)
