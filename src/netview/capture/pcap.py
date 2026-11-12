from __future__ import annotations

import math
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from netview.core.models import PacketRecord


class PcapReadError(ValueError):
    """Raised when a PCAP or PCAPNG capture cannot be read safely."""


# Magic bytes identify both byte order and timestamp precision.
_CLASSIC_PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER_MAGIC = {
    b"\x4d\x3c\x2b\x1a": "<",
    b"\x1a\x2b\x3c\x4d": ">",
}

_PCAPNG_INTERFACE_DESCRIPTION = 1
_PCAPNG_PACKET = 2  # Obsolete Packet Block, retained for compatibility.
_PCAPNG_SIMPLE_PACKET = 3
_PCAPNG_NAME_RESOLUTION = 4
_PCAPNG_INTERFACE_STATISTICS = 5
_PCAPNG_ENHANCED_PACKET = 6

_PCAPNG_IF_TSRESOL = 9
_PCAPNG_IF_TSOFFSET = 14
_DEFAULT_TIMESTAMP_RESOLUTION = 1_000_000
_MAX_PACKET_SIZE = 64 * 1024 * 1024
_MAX_BLOCK_SIZE = 256 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _Interface:
    link_type: int
    snaplen: int
    timestamp_resolution: int = _DEFAULT_TIMESTAMP_RESOLUTION
    timestamp_offset: int = 0


def _read_exact(
    stream: BinaryIO,
    size: int,
    *,
    allow_clean_eof: bool = False,
    context: str = "capture data",
) -> bytes | None:
    if size < 0:
        raise PcapReadError(f"Invalid negative length while reading {context}")

    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            if not data and allow_clean_eof:
                return None
            if not data:
                raise PcapReadError(
                    f"Capture ended unexpectedly while reading {context}"
                )
            raise PcapReadError(f"Capture ended in the middle of {context}")
        data.extend(chunk)

    return bytes(data)


def _make_packet(
    number: int,
    timestamp: float | None,
    captured_data: bytes,
    original_length: int,
    link_type: int,
) -> PacketRecord:
    try:
        return PacketRecord(
            number=number,
            timestamp=timestamp,
            captured_length=len(captured_data),
            original_length=original_length,
            link_type=link_type,
            data=captured_data,
        )
    except ValueError as exc:
        raise PcapReadError(f"Invalid packet {number}: {exc}") from exc


def _validate_packet_lengths(
    captured_length: int,
    original_length: int,
    *,
    packet_number: int,
) -> None:
    if captured_length > _MAX_PACKET_SIZE:
        raise PcapReadError(
            f"Packet {packet_number} is too large ({captured_length} bytes)"
        )
    if original_length < captured_length:
        raise PcapReadError(
            f"Packet {packet_number} has an original length smaller than "
            "its captured length"
        )


def _iter_classic_pcap(
    stream: BinaryIO,
    magic: bytes,
) -> Iterator[PacketRecord]:
    byte_order, timestamp_resolution = _CLASSIC_PCAP_FORMATS[magic]
    global_header = _read_exact(stream, 20, context="the PCAP global header")
    assert global_header is not None

    major, minor, _timezone, _sigfigs, snaplen, link_type = struct.unpack(
        f"{byte_order}HHIIII",
        global_header,
    )
    if major != 2:
        raise PcapReadError(f"Unsupported PCAP version {major}.{minor}")
    if snaplen == 0:
        raise PcapReadError("Invalid PCAP snapshot length")

    packet_header = struct.Struct(f"{byte_order}IIII")
    packet_number = 0

    while True:
        header = _read_exact(
            stream,
            packet_header.size,
            allow_clean_eof=True,
            context="a PCAP packet header",
        )
        if header is None:
            return

        seconds, subseconds, captured_length, original_length = (
            packet_header.unpack(header)
        )
        packet_number += 1

        if subseconds >= timestamp_resolution:
            raise PcapReadError(
                f"Packet {packet_number} has an invalid timestamp fraction"
            )
        if captured_length > _MAX_PACKET_SIZE:
            raise PcapReadError(
                f"Packet {packet_number} is too large ({captured_length} bytes)"
            )
        if snaplen and captured_length > snaplen:
            raise PcapReadError(
                f"Packet {packet_number} exceeds the PCAP snapshot length"
            )
        _validate_packet_lengths(
            captured_length,
            original_length,
            packet_number=packet_number,
        )

        packet_data = _read_exact(
            stream,
            captured_length,
            context=f"the data for PCAP packet {packet_number}",
        )
        assert packet_data is not None
        timestamp = seconds + subseconds / timestamp_resolution

        yield _make_packet(
            packet_number,
            timestamp,
            packet_data,
            original_length,
            link_type,
        )


def _parse_options(
    data: bytes,
    byte_order: str,
    *,
    context: str,
) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = {}
    offset = 0

    while offset < len(data):
        if len(data) - offset < 4:
            raise PcapReadError(f"Malformed options in {context}")

        code, value_length = struct.unpack_from(
            f"{byte_order}HH",
            data,
            offset,
        )
        offset += 4

        if code == 0:
            if value_length != 0:
                raise PcapReadError(
                    f"Invalid end-of-options marker in {context}"
                )
            if any(data[offset:]):
                raise PcapReadError(
                    f"Unexpected data after end-of-options marker in {context}"
                )
            return options

        padded_length = (value_length + 3) & ~3
        end = offset + padded_length
        if end > len(data):
            raise PcapReadError(f"Truncated option in {context}")

        value = data[offset:offset + value_length]
        options.setdefault(code, []).append(value)
        offset = end

    return options


def _single_option(
    options: dict[int, list[bytes]],
    code: int,
    *,
    context: str,
) -> bytes | None:
    values = options.get(code, [])
    if len(values) > 1:
        raise PcapReadError(f"Duplicate option {code} in {context}")
    return values[0] if values else None


def _interface_from_block(
    payload: bytes,
    byte_order: str,
    *,
    interface_number: int,
) -> _Interface:
    if len(payload) < 8:
        raise PcapReadError("Truncated PCAPNG Interface Description Block")

    link_type, _reserved, snaplen = struct.unpack_from(
        f"{byte_order}HHI",
        payload,
        0,
    )
    context = f"PCAPNG interface {interface_number}"
    options = _parse_options(
        payload[8:],
        byte_order,
        context=context,
    )

    resolution_data = _single_option(
        options,
        _PCAPNG_IF_TSRESOL,
        context=context,
    )
    timestamp_resolution = _DEFAULT_TIMESTAMP_RESOLUTION
    if resolution_data is not None:
        if len(resolution_data) != 1:
            raise PcapReadError(
                f"Invalid timestamp resolution option for {context}"
            )
        resolution_byte = resolution_data[0]
        exponent = resolution_byte & 0x7F
        if resolution_byte & 0x80:
            timestamp_resolution = 2 ** exponent
        else:
            timestamp_resolution = 10 ** exponent

    offset_data = _single_option(
        options,
        _PCAPNG_IF_TSOFFSET,
        context=context,
    )
    timestamp_offset = 0
    if offset_data is not None:
        if len(offset_data) != 8:
            raise PcapReadError(f"Invalid timestamp offset for {context}")
        timestamp_offset = struct.unpack(
            f"{byte_order}q",
            offset_data,
        )[0]

    return _Interface(
        link_type=link_type,
        snaplen=snaplen,
        timestamp_resolution=timestamp_resolution,
        timestamp_offset=timestamp_offset,
    )


def _read_section_header(stream: BinaryIO) -> str:
    header = _read_exact(
        stream,
        8,
        context="the PCAPNG section header",
    )
    assert header is not None

    byte_order = _PCAPNG_BYTE_ORDER_MAGIC.get(header[4:8])
    if byte_order is None:
        raise PcapReadError("Invalid PCAPNG byte-order magic")

    block_length = struct.unpack(f"{byte_order}I", header[:4])[0]
    if (
        block_length < 28
        or block_length > _MAX_BLOCK_SIZE
        or block_length % 4
    ):
        raise PcapReadError("Invalid PCAPNG Section Header Block length")

    remainder = _read_exact(
        stream,
        block_length - 12,
        context="the PCAPNG Section Header Block",
    )
    assert remainder is not None

    trailing_length = struct.unpack(
        f"{byte_order}I",
        remainder[-4:],
    )[0]
    if trailing_length != block_length:
        raise PcapReadError(
            "PCAPNG Section Header Block length fields do not match"
        )

    if len(remainder) < 16:
        raise PcapReadError("Truncated PCAPNG Section Header Block")

    major, minor, section_length = struct.unpack(
        f"{byte_order}HHq",
        remainder[:12],
    )
    if major != 1:
        raise PcapReadError(
            f"Unsupported PCAPNG version {major}.{minor}"
        )
    if section_length < -1:
        raise PcapReadError("Invalid PCAPNG section length")

    _parse_options(
        remainder[12:-4],
        byte_order,
        context="PCAPNG Section Header Block",
    )
    return byte_order


def _read_block(
    stream: BinaryIO,
    byte_order: str,
    block_type_bytes: bytes,
) -> tuple[int, bytes]:
    block_type = struct.unpack(
        f"{byte_order}I",
        block_type_bytes,
    )[0]
    length_bytes = _read_exact(
        stream,
        4,
        context="a PCAPNG block length",
    )
    assert length_bytes is not None

    block_length = struct.unpack(
        f"{byte_order}I",
        length_bytes,
    )[0]
    if (
        block_length < 12
        or block_length > _MAX_BLOCK_SIZE
        or block_length % 4
    ):
        raise PcapReadError(
            f"Invalid PCAPNG block length for block type {block_type}"
        )

    remainder = _read_exact(
        stream,
        block_length - 8,
        context=f"PCAPNG block type {block_type}",
    )
    assert remainder is not None

    trailing_length = struct.unpack(
        f"{byte_order}I",
        remainder[-4:],
    )[0]
    if trailing_length != block_length:
        raise PcapReadError(
            f"PCAPNG block type {block_type} has mismatched length fields"
        )

    return block_type, remainder[:-4]


def _packet_timestamp(
    timestamp_high: int,
    timestamp_low: int,
    interface: _Interface,
) -> float:
    ticks = (timestamp_high << 32) | timestamp_low
    timestamp = (
        ticks / interface.timestamp_resolution
        + interface.timestamp_offset
    )
    if not math.isfinite(timestamp):
        raise PcapReadError("PCAPNG packet timestamp is outside the supported range")
    return timestamp


def _pcapng_packet(
    payload: bytes,
    byte_order: str,
    interfaces: list[_Interface],
    packet_number: int,
    *,
    obsolete_packet_block: bool = False,
) -> PacketRecord:
    if obsolete_packet_block:
        if len(payload) < 20:
            raise PcapReadError("Truncated PCAPNG Packet Block")
        interface_id, _drop_count = struct.unpack_from(
            f"{byte_order}HH",
            payload,
            0,
        )
        timestamp_high, timestamp_low, captured_length, original_length = (
            struct.unpack_from(f"{byte_order}IIII", payload, 4)
        )
        data_offset = 20
        block_name = "Packet Block"
    else:
        if len(payload) < 20:
            raise PcapReadError("Truncated PCAPNG Enhanced Packet Block")
        (
            interface_id,
            timestamp_high,
            timestamp_low,
            captured_length,
            original_length,
        ) = struct.unpack_from(f"{byte_order}IIIII", payload, 0)
        data_offset = 20
        block_name = "Enhanced Packet Block"

    if interface_id >= len(interfaces):
        raise PcapReadError(
            f"{block_name} references unknown interface {interface_id}"
        )

    _validate_packet_lengths(
        captured_length,
        original_length,
        packet_number=packet_number,
    )
    padded_length = (captured_length + 3) & ~3
    data_end = data_offset + padded_length
    if data_end > len(payload):
        raise PcapReadError(
            f"Truncated packet data in PCAPNG {block_name}"
        )

    _parse_options(
        payload[data_end:],
        byte_order,
        context=f"PCAPNG {block_name}",
    )

    interface = interfaces[interface_id]
    if interface.snaplen and captured_length > interface.snaplen:
        raise PcapReadError(
            f"Packet {packet_number} exceeds interface {interface_id} snapshot length"
        )

    packet_data = payload[data_offset:data_offset + captured_length]
    timestamp = _packet_timestamp(
        timestamp_high,
        timestamp_low,
        interface,
    )
    return _make_packet(
        packet_number,
        timestamp,
        packet_data,
        original_length,
        interface.link_type,
    )


def _pcapng_simple_packet(
    payload: bytes,
    byte_order: str,
    interfaces: list[_Interface],
    packet_number: int,
) -> PacketRecord:
    if len(payload) < 4:
        raise PcapReadError("Truncated PCAPNG Simple Packet Block")
    if not interfaces:
        raise PcapReadError(
            "PCAPNG Simple Packet Block appears before an interface description"
        )

    original_length = struct.unpack_from(f"{byte_order}I", payload, 0)[0]
    interface = interfaces[0]
    captured_length = (
        min(original_length, interface.snaplen)
        if interface.snaplen
        else original_length
    )
    _validate_packet_lengths(
        captured_length,
        original_length,
        packet_number=packet_number,
    )

    padded_length = (captured_length + 3) & ~3
    packet_data = payload[4:]
    if len(packet_data) != padded_length:
        raise PcapReadError(
            "Invalid packet data length in PCAPNG Simple Packet Block"
        )

    return _make_packet(
        packet_number,
        None,
        packet_data[:captured_length],
        original_length,
        interface.link_type,
    )


def _iter_pcapng(
    stream: BinaryIO,
    initial_magic: bytes,
) -> Iterator[PacketRecord]:
    if initial_magic != _PCAPNG_SECTION_HEADER:
        raise PcapReadError("Invalid PCAPNG section header")

    byte_order = _read_section_header(stream)
    interfaces: list[_Interface] = []
    packet_number = 0

    while True:
        block_type_bytes = _read_exact(
            stream,
            4,
            allow_clean_eof=True,
            context="a PCAPNG block type",
        )
        if block_type_bytes is None:
            return

        if block_type_bytes == _PCAPNG_SECTION_HEADER:
            byte_order = _read_section_header(stream)
            interfaces = []
            continue

        block_type, payload = _read_block(
            stream,
            byte_order,
            block_type_bytes,
        )

        if block_type == _PCAPNG_INTERFACE_DESCRIPTION:
            interfaces.append(
                _interface_from_block(
                    payload,
                    byte_order,
                    interface_number=len(interfaces),
                )
            )
        elif block_type == _PCAPNG_ENHANCED_PACKET:
            packet_number += 1
            yield _pcapng_packet(
                payload,
                byte_order,
                interfaces,
                packet_number,
            )
        elif block_type == _PCAPNG_PACKET:
            packet_number += 1
            yield _pcapng_packet(
                payload,
                byte_order,
                interfaces,
                packet_number,
                obsolete_packet_block=True,
            )
        elif block_type == _PCAPNG_SIMPLE_PACKET:
            packet_number += 1
            yield _pcapng_simple_packet(
                payload,
                byte_order,
                interfaces,
                packet_number,
            )
        elif block_type in {
            _PCAPNG_NAME_RESOLUTION,
            _PCAPNG_INTERFACE_STATISTICS,
        }:
            # These blocks contain metadata, not captured packet records.
            continue
        else:
            # Unknown block types are safely skipped using their length field.
            continue


def iter_capture_file(path: str | Path) -> Iterator[PacketRecord]:
    """Read classic PCAP or PCAPNG records without third-party parser libraries."""
    source = Path(path)

    try:
        stream = source.open("rb")
    except OSError as exc:
        raise PcapReadError(f"Could not open capture file: {exc}") from exc

    with stream:
        try:
            magic = _read_exact(
                stream,
                4,
                context="the capture file header",
            )
            assert magic is not None

            if magic in _CLASSIC_PCAP_FORMATS:
                yield from _iter_classic_pcap(stream, magic)
            elif magic == _PCAPNG_SECTION_HEADER:
                yield from _iter_pcapng(stream, magic)
            else:
                raise PcapReadError(
                    "Unsupported or invalid capture file (unknown magic bytes)"
                )
        except PcapReadError:
            raise
        except (OSError, OverflowError, struct.error, ZeroDivisionError) as exc:
            raise PcapReadError(f"Error reading capture file: {exc}") from exc
