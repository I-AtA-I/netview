import pytest

from netview.core import IPv4ParseError, parse_ipv4_packet


def make_packet(
    *,
    version=4,
    ihl=5,
    total_length=None,
    protocol=17,
    flags_fragment=0,
    options=b"",
    payload=b"\xaa\xbb",
):
    header = bytearray([
        (version << 4) | ihl,
        0xBA,
        0x00, 0x00,
        0x12, 0x34,
        (flags_fragment >> 8) & 0xFF,
        flags_fragment & 0xFF,
        64,
        protocol,
        0xAB, 0xCD,
        192, 0, 2, 1,
        198, 51, 100, 2,
    ])

    header.extend(options)

    if total_length is None:
        total_length = len(header) + len(payload)

    header[2:4] = total_length.to_bytes(2, "big")

    return bytes(header) + payload


def test_parse_ipv4_header():
    packet = make_packet()
    header = parse_ipv4_packet(packet)

    assert header.header_length == 20
    assert header.total_length == 22
    assert header.source_ip == "192.0.2.1"
    assert header.destination_ip == "198.51.100.2"
    assert header.ttl == 64
    assert header.protocol == 17
    assert header.identification == 0x1234
    assert header.header_checksum == 0xABCD


def test_parse_dscp_and_ecn():
    header = parse_ipv4_packet(make_packet())

    assert header.dscp == 46
    assert header.ecn == 2


def test_parse_ipv4_options():
    options = b"\x01\x01\x01\x00"

    header = parse_ipv4_packet(
        make_packet(ihl=6, options=options)
    )

    assert header.header_length == 24
    assert header.options == options
    assert header.payload_offset == 24


def test_parse_fragment_flags():
    flags = 0x6003

    header = parse_ipv4_packet(
        make_packet(flags_fragment=flags)
    )

    assert header.dont_fragment is True
    assert header.more_fragments is True
    assert header.fragment_offset == 24
    assert header.is_fragment is True


def test_parse_non_fragmented_packet():
    header = parse_ipv4_packet(make_packet())

    assert header.is_fragment is False
    assert header.dont_fragment is False


def test_truncated_payload_is_accepted():
    packet = make_packet(total_length=100)
    header = parse_ipv4_packet(packet)

    assert header.total_length == 100
    assert header.captured_length == len(packet)
    assert header.captured_payload_length == 2
    assert header.is_truncated is True


def test_trailing_padding_is_not_counted():
    packet = make_packet() + b"\x00" * 20
    header = parse_ipv4_packet(packet)

    assert header.total_length == 22
    assert header.captured_length == 22
    assert header.is_truncated is False


def test_packet_too_short():
    with pytest.raises(IPv4ParseError):
        parse_ipv4_packet(b"\x00" * 19)


def test_invalid_version():
    with pytest.raises(IPv4ParseError):
        parse_ipv4_packet(make_packet(version=6))


def test_invalid_ihl():
    with pytest.raises(IPv4ParseError):
        parse_ipv4_packet(make_packet(ihl=4))


def test_truncated_header_with_options():
    with pytest.raises(IPv4ParseError):
        parse_ipv4_packet(b"\x46" + b"\x00" * 19)


def test_total_length_smaller_than_header():
    with pytest.raises(IPv4ParseError):
        parse_ipv4_packet(
            make_packet(ihl=6, options=b"\x00" * 4, total_length=20)
        )
