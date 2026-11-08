from __future__ import annotations

import csv
import struct
from pathlib import Path
from collections.abc import Iterable

from netview.core.models import PacketRecord


def _records(packets: Iterable[object]) -> list[PacketRecord]:
    records = []
    for packet in packets:
        record = getattr(packet, "record", packet)
        if not isinstance(record, PacketRecord):
            raise TypeError("Export expects PacketRecord or ProcessedPacket objects")
        if record.captured_length > 0xFFFFFFFF or record.original_length > 0xFFFFFFFF:
            raise ValueError("Packet length exceeds the capture format limit")
        records.append(record)
    if not records:
        raise ValueError("There are no packets to export")
    return records


def _timestamp_ticks(timestamp: float | None, resolution: int = 1_000_000) -> int:
    if timestamp is None:
        return 0
    if timestamp < 0:
        raise ValueError("Capture formats do not support negative packet timestamps")
    ticks = round(timestamp * resolution)
    if ticks > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Packet timestamp exceeds the capture format limit")
    return ticks


def write_pcap(path: str | Path, packets: Iterable[object]) -> None:
    """Write classic little-endian PCAP. All packets must share one link type."""
    records = _records(packets)
    link_types = {record.link_type for record in records}
    if len(link_types) != 1:
        raise ValueError("Classic PCAP supports one link type; export as PCAPNG instead")
    link_type = next(iter(link_types))
    if not 0 <= link_type <= 0xFFFFFFFF:
        raise ValueError(f"Invalid PCAP link type: {link_type}")

    snaplen = max(1, max(record.captured_length for record in records))
    if snaplen > 0xFFFFFFFF:
        raise ValueError("Capture snap length exceeds the PCAP format limit")

    with Path(path).open("wb") as output:
        output.write(struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,
            2, 4,
            0, 0,
            snaplen,
            link_type,
        ))
        for record in records:
            if record.timestamp is None:
                seconds, microseconds = 0, 0
            else:
                if record.timestamp < 0:
                    raise ValueError("Capture formats do not support negative packet timestamps")
                seconds = int(record.timestamp)
                microseconds = round((record.timestamp - seconds) * 1_000_000)
                if microseconds >= 1_000_000:
                    seconds += 1
                    microseconds -= 1_000_000
                if seconds > 0xFFFFFFFF:
                    raise ValueError("Packet timestamp exceeds the classic PCAP limit")
            output.write(struct.pack(
                "<IIII",
                seconds,
                microseconds,
                record.captured_length,
                record.original_length,
            ))
            output.write(record.data)


def write_pcapng(path: str | Path, packets: Iterable[object]) -> None:
    """Write PCAPNG with one interface description per observed link type."""
    records = _records(packets)
    link_types = list(dict.fromkeys(record.link_type for record in records))
    for link_type in link_types:
        if not 0 <= link_type <= 0xFFFF:
            raise ValueError(f"Invalid PCAPNG link type: {link_type}")

    interface_ids = {link_type: index for index, link_type in enumerate(link_types)}
    with Path(path).open("wb") as output:
        output.write(struct.pack(
            "<IIIHHqI",
            0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28,
        ))

        for link_type in link_types:
            options = struct.pack("<HHB3xHH", 9, 1, 6, 0, 0)
            block_length = 8 + 8 + len(options) + 4
            output.write(struct.pack(
                "<IIHHI", 1, block_length, link_type, 0, 0xFFFFFFFF,
            ))
            output.write(options)
            output.write(struct.pack("<I", block_length))

        for record in records:
            ticks = _timestamp_ticks(record.timestamp)
            timestamp_high, timestamp_low = divmod(ticks, 0x100000000)
            data_padding = (-record.captured_length) % 4
            padded_data = record.data + (b"\x00" * data_padding)
            block_length = 32 + len(padded_data)
            output.write(struct.pack(
                "<IIIIIII",
                6,
                block_length,
                interface_ids[record.link_type],
                timestamp_high,
                timestamp_low,
                record.captured_length,
                record.original_length,
            ))
            output.write(padded_data)
            output.write(struct.pack("<I", block_length))


def write_csv(path: str | Path, packets: Iterable[object]) -> None:
    """Write packet metadata as UTF-8 CSV suitable for spreadsheet imports."""
    processed = list(packets)
    if not processed:
        raise ValueError("There are no packets to export")

    columns = (
        "Number",
        "Timestamp",
        "Source",
        "Destination",
        "Protocol",
        "Length",
        "Captured length",
        "Source port",
        "Destination port",
        "Info",
    )
    with Path(path).open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        for packet in processed:
            record = getattr(packet, "record", packet)
            if not isinstance(record, PacketRecord):
                raise TypeError("CSV export expects PacketRecord or ProcessedPacket objects")
            writer.writerow({
                "Number": packet.number if hasattr(packet, "number") else record.number,
                "Timestamp": "" if record.timestamp is None else format(record.timestamp, ".9f"),
                "Source": getattr(packet, "source", ""),
                "Destination": getattr(packet, "destination", ""),
                "Protocol": getattr(packet, "protocol", ""),
                "Length": record.original_length,
                "Captured length": record.captured_length,
                "Source port": getattr(packet, "source_port", "") or "",
                "Destination port": getattr(packet, "destination_port", "") or "",
                "Info": getattr(packet, "info", ""),
            })


def export_packets(path: str | Path, packets: Iterable[object]) -> None:
    """Export packets according to the destination file extension."""
    destination = Path(path)
    suffix = destination.suffix.lower()
    if suffix in {".pcap", ".cap"}:
        write_pcap(destination, packets)
    elif suffix == ".pcapng":
        write_pcapng(destination, packets)
    elif suffix == ".csv":
        write_csv(destination, packets)
    else:
        raise ValueError("Choose a .pcap, .pcapng or .csv file extension")
