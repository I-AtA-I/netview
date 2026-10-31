import pytest

from netview.core import PacketRecord, process_packet
from netview.filters import (
    FilterSyntaxError,
    compile_filter,
    iter_filtered_packets,
)


DST = bytes.fromhex("aabbccddeeff")
SRC = bytes.fromhex("112233445566")


def make_processed(protocol="tcp", flags=0x12, number=1):
    if protocol == "tcp":
        transport = bytearray(20)
        transport[0:2] = (12345).to_bytes(2, "big")
        transport[2:4] = (443).to_bytes(2, "big")
        transport[4:8] = (1000).to_bytes(4, "big")
        transport[8:12] = (2000).to_bytes(4, "big")
        transport[12] = 0x50
        transport[13] = flags
        transport = bytes(transport)
        ip_protocol = 6

    elif protocol == "udp":
        payload = b"dns"
        transport = (
            (5353).to_bytes(2, "big")
            + (53).to_bytes(2, "big")
            + (8 + len(payload)).to_bytes(2, "big")
            + b"\x00\x00"
            + payload
        )
        ip_protocol = 17

    else:
        raise ValueError("Unsupported test protocol")

    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = (20 + len(transport)).to_bytes(2, "big")
    ip[8] = 64
    ip[9] = ip_protocol
    ip[12:16] = bytes([192, 0, 2, 1])
    ip[16:20] = bytes([198, 51, 100, 2])

    frame = DST + SRC + b"\x08\x00" + bytes(ip) + transport

    record = PacketRecord(
        number=number,
        timestamp=1234.5,
        captured_length=len(frame),
        original_length=len(frame),
        link_type=1,
        data=frame,
    )

    return process_packet(record)


@pytest.fixture
def tcp_packet():
    return make_processed("tcp")


@pytest.fixture
def udp_packet():
    return make_processed("udp")


def test_empty_filter_matches_all(tcp_packet, udp_packet):
    compiled = compile_filter("")

    assert compiled.matches(tcp_packet)
    assert compiled.matches(udp_packet)


def test_protocol_filters(tcp_packet, udp_packet):
    assert compile_filter("tcp").matches(tcp_packet)
    assert not compile_filter("tcp").matches(udp_packet)

    assert compile_filter("udp").matches(udp_packet)
    assert not compile_filter("udp").matches(tcp_packet)

    assert compile_filter("ip").matches(tcp_packet)
    assert compile_filter("eth").matches(tcp_packet)


def test_ip_address_filter(tcp_packet):
    assert compile_filter(
        "ip.src == 192.0.2.1"
    ).matches(tcp_packet)

    assert compile_filter(
        "ip.dst == 198.51.100.2"
    ).matches(tcp_packet)

    assert not compile_filter(
        "ip.src == 192.0.2.2"
    ).matches(tcp_packet)


def test_tcp_port_filter(tcp_packet):
    assert compile_filter(
        "tcp.srcport == 12345"
    ).matches(tcp_packet)

    assert compile_filter(
        "tcp.dstport == 443"
    ).matches(tcp_packet)

    assert compile_filter(
        "tcp.port == 443"
    ).matches(tcp_packet)


def test_udp_port_filter(udp_packet):
    assert compile_filter(
        "udp.port == 53"
    ).matches(udp_packet)

    assert compile_filter(
        "udp.srcport == 5353"
    ).matches(udp_packet)


def test_ethernet_mac_filter(tcp_packet):
    assert compile_filter(
        "eth.src == 11:22:33:44:55:66"
    ).matches(tcp_packet)


def test_frame_length_filter(tcp_packet):
    assert compile_filter(
        "frame.len > 40"
    ).matches(tcp_packet)


def test_tcp_flags_filter(tcp_packet):
    assert compile_filter(
        "tcp.flags.syn == true"
    ).matches(tcp_packet)

    assert compile_filter(
        "tcp.flags.ack == true"
    ).matches(tcp_packet)

    assert compile_filter(
        "tcp.flags.fin == false"
    ).matches(tcp_packet)


def test_boolean_and(tcp_packet):
    expression = "tcp and ip.src == 192.0.2.1 and tcp.port == 443"

    assert compile_filter(expression).matches(tcp_packet)


def test_boolean_or(tcp_packet, udp_packet):
    expression = "tcp or udp"
    compiled = compile_filter(expression)

    assert compiled.matches(tcp_packet)
    assert compiled.matches(udp_packet)


def test_boolean_precedence(tcp_packet, udp_packet):
    expression = "tcp or udp and ip.src == 203.0.113.1"
    compiled = compile_filter(expression)

    assert compiled.matches(tcp_packet)
    assert not compiled.matches(udp_packet)


def test_parentheses(tcp_packet, udp_packet):
    expression = "(tcp or udp) and ip.src == 192.0.2.1"
    compiled = compile_filter(expression)

    assert compiled.matches(tcp_packet)
    assert compiled.matches(udp_packet)


def test_not_operator(tcp_packet, udp_packet):
    assert compile_filter("not udp").matches(tcp_packet)
    assert not compile_filter("not tcp").matches(tcp_packet)
    assert compile_filter("not tcp").matches(udp_packet)


def test_port_not_equal_checks_both_ports(tcp_packet):
    assert not compile_filter(
        "tcp.port != 443"
    ).matches(tcp_packet)

    assert compile_filter(
        "tcp.port != 80"
    ).matches(tcp_packet)


def test_case_insensitive_keywords(tcp_packet):
    assert compile_filter("TCP AND IP").matches(tcp_packet)


@pytest.mark.parametrize(
    "expression",
    [
        "unknown",
        "tcp.port ==",
        "tcp and",
        "(tcp",
        "tcp or udp)",
        "tcp && udp",
    ],
)
def test_invalid_expressions(expression):
    with pytest.raises(FilterSyntaxError):
        compile_filter(expression)


def test_unknown_field():
    with pytest.raises(FilterSyntaxError):
        compile_filter("ip.unknown == 1")


def test_invalid_ip_value():
    with pytest.raises(FilterSyntaxError):
        compile_filter("ip.src == 999.999.1.1")


def test_invalid_mac_value():
    with pytest.raises(FilterSyntaxError):
        compile_filter("eth.src == 11:22:33:44")


def test_invalid_numeric_value():
    with pytest.raises(FilterSyntaxError):
        compile_filter("tcp.port == abc")


def test_invalid_port_range():
    with pytest.raises(FilterSyntaxError):
        compile_filter("tcp.port == 70000")


def test_invalid_comparison():
    with pytest.raises(FilterSyntaxError):
        compile_filter("ip.src > 192.0.2.1")


def test_iter_filtered_packets(tcp_packet, udp_packet):
    packets = [tcp_packet, udp_packet]
    filtered = list(iter_filtered_packets(packets, "tcp"))

    assert len(filtered) == 1
    assert filtered[0].protocol == "TCP"


def test_compiled_filter_reuse(tcp_packet, udp_packet):
    compiled = compile_filter("tcp.port == 443")

    assert compiled.matches(tcp_packet)
    assert not compiled.matches(udp_packet)

    filtered = list(
        iter_filtered_packets(
            [tcp_packet, udp_packet],
            compiled,
        )
    )

    assert len(filtered) == 1
