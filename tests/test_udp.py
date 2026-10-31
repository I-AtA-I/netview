import pytest

from netview.core import UDPParseError, parse_udp_datagram


def make_datagram(payload=b"\xaa\xbb", length=None):
    if length is None:
        length = 8 + len(payload)

    return (
        (5353).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + (0xABCD).to_bytes(2, "big")
        + payload
    )


def test_parse_udp_header():
    udp = parse_udp_datagram(make_datagram())

    assert udp.source_port == 5353
    assert udp.destination_port == 53
    assert udp.length == 10
    assert udp.checksum == 0xABCD


def test_parse_udp_payload():
    udp = parse_udp_datagram(make_datagram(payload=b"\x11\x22\x33"))

    assert udp.payload_offset == 8
    assert udp.payload_length == 3
    assert udp.captured_payload_length == 3


def test_udp_datagram_too_short():
    with pytest.raises(UDPParseError):
        parse_udp_datagram(b"\x00" * 7)


def test_invalid_udp_length():
    with pytest.raises(UDPParseError):
        parse_udp_datagram(make_datagram(length=7))


def test_truncated_udp_payload():
    udp = parse_udp_datagram(
        make_datagram(payload=b"\xaa", length=100)
    )

    assert udp.length == 100
    assert udp.captured_length == 9
    assert udp.captured_payload_length == 1
    assert udp.is_truncated is True


def test_udp_trailing_padding():
    udp = parse_udp_datagram(
        make_datagram(payload=b"\xaa") + b"\x00" * 10
    )

    assert udp.length == 9
    assert udp.captured_length == 9
    assert udp.is_truncated is False
