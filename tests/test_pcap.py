import pytest

from scapy.utils import PcapNgWriter, PcapWriter

from netview.capture import PcapReadError, iter_capture_file


FRAME = bytes.fromhex(
    "aabbccddeeff"
    "112233445566"
    "0800"
    "450000160000000040110000"
    "c0000201c6336402"
    "aabb"
)


@pytest.mark.parametrize(
    ("nano", "subsecond", "expected_timestamp"),
    [
        (False, 567890, 1234.56789),
        (True, 567890123, 1234.567890123),
    ],
)
def test_read_classic_pcap(
    tmp_path,
    nano,
    subsecond,
    expected_timestamp,
):
    path = tmp_path / "sample.pcap"

    with PcapWriter(
        str(path),
        linktype=1,
        nano=nano,
    ) as writer:
        writer.write_header(FRAME)

        writer.write_packet(
            FRAME,
            sec=1234,
            usec=subsecond,
            caplen=len(FRAME),
            wirelen=len(FRAME) + 10,
        )

        writer.write_packet(
            FRAME,
            sec=1235,
            usec=0,
        )

    packets = list(iter_capture_file(path))

    assert len(packets) == 2

    assert packets[0].number == 1
    assert packets[0].timestamp == pytest.approx(expected_timestamp)
    assert packets[0].captured_length == len(FRAME)
    assert packets[0].original_length == len(FRAME) + 10
    assert packets[0].link_type == 1
    assert packets[0].data == FRAME

    assert packets[1].number == 2
    assert packets[1].timestamp == 1235.0


def test_read_pcapng(tmp_path):
    path = tmp_path / "sample.pcapng"

    with PcapNgWriter(str(path)) as writer:
        writer.linktype = 1
        writer.write_header(FRAME)

        writer.write_packet(
            FRAME,
            sec=1234.56789,
            caplen=len(FRAME),
            wirelen=len(FRAME) + 5,
        )

    packets = list(iter_capture_file(path))

    assert len(packets) == 1

    packet = packets[0]

    assert packet.number == 1
    assert packet.timestamp == pytest.approx(1234.56789)
    assert packet.captured_length == len(FRAME)
    assert packet.original_length == len(FRAME) + 5
    assert packet.link_type == 1
    assert packet.data == FRAME


def test_invalid_capture_file(tmp_path):
    path = tmp_path / "invalid.pcap"
    path.write_bytes(b"this is not a capture file")

    with pytest.raises(PcapReadError):
        list(iter_capture_file(path))
