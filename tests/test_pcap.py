import struct

import pytest

from netview.capture import PcapReadError, iter_capture_file


FRAME = bytes.fromhex(
    "aabbccddeeff"
    "112233445566"
    "0800"
    "450000160000000040110000"
    "c0000201c6336402"
    "aabb"
)

_CLASSIC_MAGICS = {
    ("<", False): b"\xd4\xc3\xb2\xa1",
    (">", False): b"\xa1\xb2\xc3\xd4",
    ("<", True): b"\x4d\x3c\xb2\xa1",
    (">", True): b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 1
_PCAPNG_PB = 2
_PCAPNG_SPB = 3
_PCAPNG_NRB = 4
_PCAPNG_ISB = 5
_PCAPNG_EPB = 6


def make_classic_pcap(
    packets=(),
    *,
    byte_order="<",
    nano=False,
    link_type=1,
    snaplen=65535,
):
    resolution = 1_000_000_000 if nano else 1_000_000
    output = bytearray(_CLASSIC_MAGICS[(byte_order, nano)])
    output.extend(
        struct.pack(
            f"{byte_order}HHIIII",
            2,
            4,
            0,
            0,
            snaplen,
            link_type,
        )
    )

    for seconds, subseconds, data, original_length in packets:
        output.extend(
            struct.pack(
                f"{byte_order}IIII",
                seconds,
                subseconds,
                len(data),
                original_length,
            )
        )
        output.extend(data)

    return bytes(output), resolution


def pack_pcapng_block(block_type, payload, byte_order="<"):
    assert len(payload) % 4 == 0
    block_length = 12 + len(payload)
    return (
        struct.pack(f"{byte_order}II", block_type, block_length)
        + payload
        + struct.pack(f"{byte_order}I", block_length)
    )


def pack_pcapng_option(code, value, byte_order="<"):
    padding = (-len(value)) % 4
    return (
        struct.pack(f"{byte_order}HH", code, len(value))
        + value
        + (b"\x00" * padding)
    )


def make_pcapng_section(byte_order="<", options=b""):
    payload = (
        struct.pack(f"{byte_order}IHHq", 0x1A2B3C4D, 1, 0, -1)
        + options
    )
    return pack_pcapng_block(_PCAPNG_SHB, payload, byte_order)


def make_pcapng_idb(
    *,
    byte_order="<",
    link_type=1,
    snaplen=65535,
    options=b"",
):
    payload = struct.pack(f"{byte_order}HHI", link_type, 0, snaplen) + options
    return pack_pcapng_block(_PCAPNG_IDB, payload, byte_order)


def make_pcapng_epb(
    data,
    *,
    byte_order="<",
    interface_id=0,
    timestamp_ticks=0,
    original_length=None,
    options=b"",
):
    if original_length is None:
        original_length = len(data)
    high, low = divmod(timestamp_ticks, 0x100000000)
    padded_data = data + (b"\x00" * ((-len(data)) % 4))
    payload = (
        struct.pack(
            f"{byte_order}IIIII",
            interface_id,
            high,
            low,
            len(data),
            original_length,
        )
        + padded_data
        + options
    )
    return pack_pcapng_block(_PCAPNG_EPB, payload, byte_order)


def make_pcapng_spb(data, *, byte_order="<", original_length=None):
    if original_length is None:
        original_length = len(data)
    padded_data = data + (b"\x00" * ((-len(data)) % 4))
    return pack_pcapng_block(
        _PCAPNG_SPB,
        struct.pack(f"{byte_order}I", original_length) + padded_data,
        byte_order,
    )


def make_pcapng_pb(
    data,
    *,
    byte_order="<",
    interface_id=0,
    timestamp_ticks=0,
    original_length=None,
):
    if original_length is None:
        original_length = len(data)
    high, low = divmod(timestamp_ticks, 0x100000000)
    padded_data = data + (b"\x00" * ((-len(data)) % 4))
    payload = (
        struct.pack(f"{byte_order}HHIIII", interface_id, 0, high, low, len(data), original_length)
        + padded_data
    )
    return pack_pcapng_block(_PCAPNG_PB, payload, byte_order)


@pytest.mark.parametrize(
    ("byte_order", "nano", "subseconds"),
    [
        ("<", False, 567890),
        (">", False, 567890),
        ("<", True, 567890123),
        (">", True, 567890123),
    ],
)
def test_read_classic_pcap_all_endianness_and_timestamp_resolutions(
    tmp_path,
    byte_order,
    nano,
    subseconds,
):
    path = tmp_path / "sample.pcap"
    data, resolution = make_classic_pcap(
        [
            (1234, subseconds, FRAME, len(FRAME) + 10),
            (1235, 0, FRAME, len(FRAME)),
        ],
        byte_order=byte_order,
        nano=nano,
        link_type=1,
    )
    path.write_bytes(data)

    packets = list(iter_capture_file(path))

    assert len(packets) == 2
    assert packets[0].number == 1
    assert packets[0].timestamp == pytest.approx(
        1234 + subseconds / resolution
    )
    assert packets[0].captured_length == len(FRAME)
    assert packets[0].original_length == len(FRAME) + 10
    assert packets[0].link_type == 1
    assert packets[0].data == FRAME
    assert packets[1].number == 2
    assert packets[1].timestamp == 1235.0


def test_read_classic_pcap_preserves_full_link_type_field(tmp_path):
    path = tmp_path / "linktype.pcap"
    data, _ = make_classic_pcap(
        [(1, 0, FRAME, len(FRAME))],
        link_type=0x00010001,
    )
    path.write_bytes(data)

    packet = next(iter_capture_file(path))

    assert packet.link_type == 0x00010001


def test_read_empty_classic_pcap(tmp_path):
    path = tmp_path / "empty.pcap"
    data, _ = make_classic_pcap()
    path.write_bytes(data)

    assert list(iter_capture_file(path)) == []


def test_classic_pcap_rejects_invalid_timestamp_fraction(tmp_path):
    path = tmp_path / "invalid-fraction.pcap"
    data, _ = make_classic_pcap(
        [(1, 1_000_000, b"abc", 3)],
    )
    path.write_bytes(data)

    with pytest.raises(PcapReadError, match="timestamp fraction"):
        list(iter_capture_file(path))


def test_classic_pcap_rejects_truncated_global_header(tmp_path):
    path = tmp_path / "truncated-header.pcap"
    path.write_bytes(_CLASSIC_MAGICS[("<", False)] + b"\x00" * 7)

    with pytest.raises(PcapReadError, match="global header"):
        list(iter_capture_file(path))


def test_classic_pcap_rejects_truncated_packet_header(tmp_path):
    path = tmp_path / "truncated-record-header.pcap"
    data, _ = make_classic_pcap()
    path.write_bytes(data + b"\x00" * 8)

    with pytest.raises(PcapReadError, match="PCAP packet header"):
        list(iter_capture_file(path))


def test_classic_pcap_rejects_truncated_packet_data(tmp_path):
    path = tmp_path / "truncated-record-data.pcap"
    data, _ = make_classic_pcap([(1, 0, b"abc", 3)])
    path.write_bytes(data[:-1])

    with pytest.raises(PcapReadError, match="middle of the data"):
        list(iter_capture_file(path))


def test_classic_pcap_rejects_packet_larger_than_snapshot_length(tmp_path):
    path = tmp_path / "oversized-record.pcap"
    data, _ = make_classic_pcap(
        [(1, 0, b"12345", 5)],
        snaplen=4,
    )
    path.write_bytes(data)

    with pytest.raises(PcapReadError, match="snapshot length"):
        list(iter_capture_file(path))


def test_invalid_capture_file(tmp_path):
    path = tmp_path / "invalid.pcap"
    path.write_bytes(b"this is not a capture file")

    with pytest.raises(PcapReadError, match="unknown magic"):
        list(iter_capture_file(path))


def test_missing_capture_file_raises_read_error(tmp_path):
    with pytest.raises(PcapReadError, match="Could not open"):
        list(iter_capture_file(tmp_path / "missing.pcap"))


@pytest.mark.parametrize("byte_order", ["<", ">"])
def test_read_pcapng_enhanced_packet_block(tmp_path, byte_order):
    path = tmp_path / "sample.pcapng"
    capture = (
        make_pcapng_section(byte_order)
        + make_pcapng_idb(byte_order=byte_order, link_type=1)
        + make_pcapng_epb(
            FRAME,
            byte_order=byte_order,
            timestamp_ticks=1_234_567_890,
            original_length=len(FRAME) + 5,
        )
    )
    path.write_bytes(capture)

    packets = list(iter_capture_file(path))

    assert len(packets) == 1
    packet = packets[0]
    assert packet.number == 1
    assert packet.timestamp == pytest.approx(1234.56789)
    assert packet.captured_length == len(FRAME)
    assert packet.original_length == len(FRAME) + 5
    assert packet.link_type == 1
    assert packet.data == FRAME


def test_pcapng_supports_multiple_interfaces_and_timestamp_options(tmp_path):
    path = tmp_path / "interfaces.pcapng"
    interface_options = (
        pack_pcapng_option(9, b"\x8a")
        + pack_pcapng_option(14, struct.pack("<q", 2))
        + pack_pcapng_option(0, b"")
    )
    capture = (
        make_pcapng_section()
        + make_pcapng_idb(link_type=1, snaplen=65535)
        + make_pcapng_idb(
            link_type=101,
            snaplen=0,
            options=interface_options,
        )
        + make_pcapng_epb(
            b"ethernet",
            interface_id=0,
            timestamp_ticks=1_000_000,
        )
        + make_pcapng_epb(
            b"raw-ip",
            interface_id=1,
            timestamp_ticks=512,
        )
    )
    path.write_bytes(capture)

    packets = list(iter_capture_file(path))

    assert [packet.number for packet in packets] == [1, 2]
    assert [packet.link_type for packet in packets] == [1, 101]
    assert packets[0].timestamp == pytest.approx(1.0)
    assert packets[1].timestamp == pytest.approx(2.5)
    assert [packet.data for packet in packets] == [b"ethernet", b"raw-ip"]


def test_pcapng_simple_packet_uses_interface_snaplen_and_has_no_timestamp(tmp_path):
    path = tmp_path / "simple.pcapng"
    data = b"abcdefgh"
    capture = (
        make_pcapng_section()
        + make_pcapng_idb(link_type=1, snaplen=5)
        + make_pcapng_spb(data, original_length=12)
    )
    path.write_bytes(capture)

    packet = next(iter_capture_file(path))

    assert packet.timestamp is None
    assert packet.captured_length == 5
    assert packet.original_length == 12
    assert packet.link_type == 1
    assert packet.data == b"abcde"


def test_pcapng_supports_obsolete_packet_block(tmp_path):
    path = tmp_path / "packet-block.pcapng"
    capture = (
        make_pcapng_section()
        + make_pcapng_idb()
        + make_pcapng_pb(FRAME, timestamp_ticks=2_500_000)
    )
    path.write_bytes(capture)

    packet = next(iter_capture_file(path))

    assert packet.timestamp == pytest.approx(2.5)
    assert packet.data == FRAME


def test_pcapng_skips_unknown_and_metadata_blocks(tmp_path):
    path = tmp_path / "unknown-blocks.pcapng"
    unknown_block = pack_pcapng_block(0x00000BAD, b"\x01\x02\x03\x04")
    name_resolution_block = pack_pcapng_block(_PCAPNG_NRB, b"\x00" * 4)
    interface_stats_block = pack_pcapng_block(_PCAPNG_ISB, b"\x00" * 4)
    capture = (
        make_pcapng_section()
        + name_resolution_block
        + make_pcapng_idb()
        + unknown_block
        + interface_stats_block
        + make_pcapng_epb(FRAME, timestamp_ticks=5_000_000)
    )
    path.write_bytes(capture)

    packet = next(iter_capture_file(path))

    assert packet.number == 1
    assert packet.data == FRAME
    assert packet.timestamp == pytest.approx(5.0)


def test_pcapng_supports_multiple_sections_and_byte_orders(tmp_path):
    path = tmp_path / "multiple-sections.pcapng"
    capture = (
        make_pcapng_section("<")
        + make_pcapng_idb(byte_order="<", link_type=1)
        + make_pcapng_epb(
            b"first",
            byte_order="<",
            timestamp_ticks=1_000_000,
        )
        + make_pcapng_section(">")
        + make_pcapng_idb(byte_order=">", link_type=101)
        + make_pcapng_epb(
            b"second",
            byte_order=">",
            timestamp_ticks=2_000_000,
        )
    )
    path.write_bytes(capture)

    packets = list(iter_capture_file(path))

    assert [packet.number for packet in packets] == [1, 2]
    assert [packet.link_type for packet in packets] == [1, 101]
    assert [packet.data for packet in packets] == [b"first", b"second"]
    assert [packet.timestamp for packet in packets] == pytest.approx([1.0, 2.0])


def test_pcapng_rejects_truncated_section_header(tmp_path):
    path = tmp_path / "truncated-section.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00")

    with pytest.raises(PcapReadError, match="section header"):
        list(iter_capture_file(path))


def test_pcapng_rejects_invalid_byte_order_magic(tmp_path):
    path = tmp_path / "invalid-byte-order.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00" + b"BAD!")

    with pytest.raises(PcapReadError, match="byte-order magic"):
        list(iter_capture_file(path))


def test_pcapng_rejects_mismatched_block_lengths(tmp_path):
    path = tmp_path / "bad-block-length.pcapng"
    capture = bytearray(make_pcapng_section() + make_pcapng_idb())
    capture[-4:] = struct.pack("<I", 0x1234)
    path.write_bytes(capture)

    with pytest.raises(PcapReadError, match="mismatched length fields"):
        list(iter_capture_file(path))


def test_pcapng_rejects_packet_with_unknown_interface(tmp_path):
    path = tmp_path / "unknown-interface.pcapng"
    capture = (
        make_pcapng_section()
        + make_pcapng_epb(FRAME, interface_id=0)
    )
    path.write_bytes(capture)

    with pytest.raises(PcapReadError, match="unknown interface"):
        list(iter_capture_file(path))


def test_pcapng_rejects_malformed_timestamp_resolution_option(tmp_path):
    path = tmp_path / "bad-resolution.pcapng"
    options = (
        pack_pcapng_option(9, b"\x06\x07")
        + pack_pcapng_option(0, b"")
    )
    capture = (
        make_pcapng_section()
        + make_pcapng_idb(options=options)
        + make_pcapng_epb(FRAME)
    )
    path.write_bytes(capture)

    with pytest.raises(PcapReadError, match="timestamp resolution"):
        list(iter_capture_file(path))


def test_pcapng_rejects_simple_packet_before_interface_description(tmp_path):
    path = tmp_path / "simple-without-interface.pcapng"
    path.write_bytes(
        make_pcapng_section()
        + make_pcapng_spb(FRAME)
    )

    with pytest.raises(PcapReadError, match="before an interface"):
        list(iter_capture_file(path))


def test_pcapng_rejects_truncated_enhanced_packet_data(tmp_path):
    path = tmp_path / "truncated-epb.pcapng"
    block = make_pcapng_epb(FRAME)
    capture = (
        make_pcapng_section()
        + make_pcapng_idb()
        + block[:-8]
    )
    path.write_bytes(capture)

    with pytest.raises(PcapReadError):
        list(iter_capture_file(path))
