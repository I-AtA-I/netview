import pytest

from netview.core import EthernetParseError, parse_ethernet_frame


DST = bytes.fromhex("aabbccddeeff")
SRC = bytes.fromhex("112233445566")


def make_frame(ether_type=0x0800, payload=b"\x00" * 20):
    return DST + SRC + ether_type.to_bytes(2, "big") + payload


def test_parse_ethernet_header():
    header = parse_ethernet_frame(make_frame())

    assert header.destination_mac == "aa:bb:cc:dd:ee:ff"
    assert header.source_mac == "11:22:33:44:55:66"
    assert header.ether_type == 0x0800
    assert header.payload_offset == 14
    assert header.vlan_tags == ()


def test_parse_vlan_tag():
    tci = (5 << 13) | (1 << 12) | 100

    frame = (
        DST
        + SRC
        + b"\x81\x00"
        + tci.to_bytes(2, "big")
        + b"\x08\x00"
        + b"\x00" * 20
    )

    header = parse_ethernet_frame(frame)

    assert len(header.vlan_tags) == 1
    assert header.vlan_tags[0].priority == 5
    assert header.vlan_tags[0].drop_eligible is True
    assert header.vlan_tags[0].vlan_id == 100
    assert header.ether_type == 0x0800
    assert header.payload_offset == 18


def test_parse_stacked_vlan_tags():
    frame = (
        DST
        + SRC
        + b"\x88\xa8"
        + b"\x00\x0a"
        + b"\x81\x00"
        + b"\x00\x14"
        + b"\x08\x00"
        + b"\x00" * 20
    )

    header = parse_ethernet_frame(frame)

    assert len(header.vlan_tags) == 2
    assert header.vlan_tags[0].vlan_id == 10
    assert header.vlan_tags[1].vlan_id == 20
    assert header.ether_type == 0x0800
    assert header.payload_offset == 22


def test_frame_too_short():
    with pytest.raises(EthernetParseError):
        parse_ethernet_frame(b"\x00" * 13)


def test_truncated_vlan_tag():
    frame = DST + SRC + b"\x81\x00"

    with pytest.raises(EthernetParseError):
        parse_ethernet_frame(frame)


def test_802_3_length_field():
    header = parse_ethernet_frame(make_frame(ether_type=100))

    assert header.type_or_length == 100
    assert header.ether_type is None
