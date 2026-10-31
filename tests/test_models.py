import pytest

from netview.core import PacketRecord


def test_valid_packet_record():
    packet = PacketRecord(
        number=1,
        timestamp=1761860000.0,
        captured_length=14,
        original_length=14,
        link_type=1,
        data=b"\x00" * 14,
    )

    assert packet.number == 1
    assert packet.captured_length == 14
    assert len(packet.data) == 14


def test_captured_length_mismatch():
    with pytest.raises(ValueError):
        PacketRecord(
            number=1,
            timestamp=1761860000.0,
            captured_length=20,
            original_length=20,
            link_type=1,
            data=b"\x00" * 14,
        )


def test_invalid_original_length():
    with pytest.raises(ValueError):
        PacketRecord(
            number=1,
            timestamp=1761860000.0,
            captured_length=14,
            original_length=10,
            link_type=1,
            data=b"\x00" * 14,
        )


def test_packet_number_must_be_positive():
    with pytest.raises(ValueError):
        PacketRecord(
            number=0,
            timestamp=1761860000.0,
            captured_length=14,
            original_length=14,
            link_type=1,
            data=b"\x00" * 14,
        )


def test_packet_without_timestamp():
    packet = PacketRecord(
        number=1,
        timestamp=None,
        captured_length=14,
        original_length=14,
        link_type=1,
        data=b"\x00" * 14,
    )

    assert packet.timestamp is None
