import io
import struct
import pytest

from netview.capture import LiveCaptureError, iter_pcap_stream
from netview.capture.live import _parse_dumpcap_interfaces, list_interfaces


def make_pcap_stream(
    packets,
    *,
    byte_order="<",
    nano=False,
    link_type=1,
    snaplen=65535,
):
    if byte_order == "<" and nano:
        magic = b"\x4d\x3c\xb2\xa1"
    elif byte_order == ">" and nano:
        magic = b"\xa1\xb2\x3c\x4d"
    elif byte_order == "<":
        magic = b"\xd4\xc3\xb2\xa1"
    else:
        magic = b"\xa1\xb2\xc3\xd4"

    output = bytearray(magic)
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

    for seconds, sub_seconds, data, original_length in packets:
        output.extend(
            struct.pack(
                f"{byte_order}IIII",
                seconds,
                sub_seconds,
                len(data),
                original_length,
            )
        )
        output.extend(data)

    return bytes(output)


def test_iter_pcap_stream_little_endian_microseconds():
    stream = make_pcap_stream(
        [(1234, 567890, b"frame-one", 90)],
    )

    packets = list(iter_pcap_stream(io.BytesIO(stream)))

    assert len(packets) == 1
    assert packets[0].number == 1
    assert packets[0].timestamp == pytest.approx(1234.56789)
    assert packets[0].captured_length == 9
    assert packets[0].original_length == 90
    assert packets[0].link_type == 1
    assert packets[0].data == b"frame-one"


def test_iter_pcap_stream_little_endian_nanoseconds():
    stream = make_pcap_stream(
        [(10, 123456789, b"abc", 3)],
        nano=True,
    )

    packet = next(iter_pcap_stream(io.BytesIO(stream)))

    assert packet.timestamp == pytest.approx(10.123456789)


def test_iter_pcap_stream_big_endian():
    stream = make_pcap_stream(
        [(20, 250000, b"abc", 3)],
        byte_order=">",
    )

    packet = next(iter_pcap_stream(io.BytesIO(stream)))

    assert packet.timestamp == pytest.approx(20.25)
    assert packet.data == b"abc"


def test_iter_pcap_stream_multiple_packets():
    stream = make_pcap_stream(
        [
            (1, 0, b"one", 3),
            (2, 500000, b"two-two", 7),
        ],
    )

    packets = list(iter_pcap_stream(io.BytesIO(stream)))

    assert [packet.number for packet in packets] == [1, 2]
    assert [packet.data for packet in packets] == [b"one", b"two-two"]


def test_iter_pcap_stream_rejects_invalid_magic():
    with pytest.raises(LiveCaptureError, match="invalid PCAP"):
        list(iter_pcap_stream(io.BytesIO(b"not-pcap")))


def test_iter_pcap_stream_rejects_truncated_global_header():
    with pytest.raises(LiveCaptureError, match="ended unexpectedly"):
        list(iter_pcap_stream(io.BytesIO(b"\xd4\xc3\xb2\xa1")))


def test_iter_pcap_stream_rejects_truncated_packet():
    stream = make_pcap_stream([(1, 0, b"abc", 3)])[:-1]

    with pytest.raises(LiveCaptureError, match="middle of a record"):
        list(iter_pcap_stream(io.BytesIO(stream)))


def test_parse_dumpcap_interfaces():
    output = """1. enp3s0\n2. wlp2s0 (Wireless interface)\n3. lo (Loopback)\n"""

    assert _parse_dumpcap_interfaces(output) == ["enp3s0", "wlp2s0", "lo"]


def test_list_interfaces_uses_dumpcap(monkeypatch):
    class Result:
        returncode = 0
        stdout = "1. enp3s0\n2. lo (Loopback)\n"
        stderr = ""

    monkeypatch.setattr("netview.capture.live.shutil.which", lambda name: "/usr/bin/dumpcap")
    monkeypatch.setattr(
        "netview.capture.live.subprocess.run",
        lambda *args, **kwargs: Result(),
    )

    assert list_interfaces() == ["enp3s0", "lo"]


def test_list_interfaces_reports_missing_dumpcap(monkeypatch):
    monkeypatch.setattr("netview.capture.live.find_dumpcap", lambda: None)

    with pytest.raises(LiveCaptureError, match="dumpcap was not found"):
        list_interfaces()
