import pytest

from netview.core import TCPParseError, parse_tcp_segment


def make_segment(
    *,
    offset=5,
    flags=0x18,
    reserved=0,
    ns=False,
    options=b"",
    payload=b"\xaa\xbb",
):
    header = bytearray(20)

    header[0:2] = (12345).to_bytes(2, "big")
    header[2:4] = (443).to_bytes(2, "big")
    header[4:8] = (1000).to_bytes(4, "big")
    header[8:12] = (2000).to_bytes(4, "big")
    header[12] = (offset << 4) | ((reserved & 0x07) << 1) | int(ns)
    header[13] = flags
    header[14:16] = (4096).to_bytes(2, "big")
    header[16:18] = (0xABCD).to_bytes(2, "big")
    header[18:20] = (10).to_bytes(2, "big")

    return bytes(header) + options + payload


def test_parse_tcp_header():
    tcp = parse_tcp_segment(make_segment())

    assert tcp.source_port == 12345
    assert tcp.destination_port == 443
    assert tcp.sequence_number == 1000
    assert tcp.acknowledgment_number == 2000
    assert tcp.header_length == 20
    assert tcp.window_size == 4096
    assert tcp.checksum == 0xABCD
    assert tcp.urgent_pointer == 10


def test_parse_tcp_flags():
    tcp = parse_tcp_segment(make_segment(flags=0xFF))

    assert tcp.is_cwr
    assert tcp.is_ece
    assert tcp.is_urg
    assert tcp.is_ack
    assert tcp.is_psh
    assert tcp.is_rst
    assert tcp.is_syn
    assert tcp.is_fin

    assert tcp.active_flags == (
        "CWR", "ECE", "URG", "ACK",
        "PSH", "RST", "SYN", "FIN",
    )


def test_parse_tcp_ns_and_reserved():
    tcp = parse_tcp_segment(
        make_segment(reserved=5, ns=True)
    )

    assert tcp.reserved == 5
    assert tcp.ns is True


def test_parse_tcp_options():
    options = b"\x01\x01\x01\x00"

    tcp = parse_tcp_segment(
        make_segment(offset=6, options=options)
    )

    assert tcp.header_length == 24
    assert tcp.options == options
    assert tcp.payload_offset == 24


def test_parse_tcp_payload():
    tcp = parse_tcp_segment(
        make_segment(payload=b"\x11\x22\x33")
    )

    assert tcp.payload_offset == 20
    assert tcp.header_length == 20


def test_tcp_segment_too_short():
    with pytest.raises(TCPParseError):
        parse_tcp_segment(b"\x00" * 19)


def test_invalid_tcp_data_offset():
    with pytest.raises(TCPParseError):
        parse_tcp_segment(make_segment(offset=4))


def test_truncated_tcp_options():
    with pytest.raises(TCPParseError):
        parse_tcp_segment(
            make_segment(
                offset=6,
                options=b"\x01\x02",
                payload=b"",
            )
        )
