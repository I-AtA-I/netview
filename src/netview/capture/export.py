import csv
import json
import struct
from math import floor
from pathlib import Path
from collections.abc import Iterable

from netview.core.pipeline import ProcessedPacket


class CaptureExportError(ValueError):
    pass


def export_capture(path: str | Path, packets: Iterable[ProcessedPacket]) -> int:
    target = Path(path).expanduser()
    suffix = target.suffix.lower()
    packet_list = list(packets)

    if not packet_list:
        raise CaptureExportError("There are no packets to export")

    if suffix == ".csv":
        _export_csv(target, packet_list)
    elif suffix == ".json":
        _export_json(target, packet_list)
    elif suffix == ".pcap":
        _export_pcap(target, packet_list)
    else:
        raise CaptureExportError("Choose a .pcap, .csv or .json file")

    return len(packet_list)


def _packet_row(packet: ProcessedPacket) -> dict[str, object]:
    record = packet.record
    return {
        "number": record.number,
        "timestamp": record.timestamp,
        "source": packet.source,
        "destination": packet.destination,
        "source_port": packet.source_port,
        "destination_port": packet.destination_port,
        "protocol": packet.protocol,
        "captured_length": record.captured_length,
        "original_length": record.original_length,
        "info": packet.info,
    }


def _export_csv(path: Path, packets: list[ProcessedPacket]) -> None:
    fields = list(_packet_row(packets[0]))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for packet in packets:
            writer.writerow(_packet_row(packet))


def _export_json(path: Path, packets: list[ProcessedPacket]) -> None:
    data = [_packet_row(packet) for packet in packets]
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def _export_pcap(path: Path, packets: list[ProcessedPacket]) -> None:
    link_types = {packet.record.link_type for packet in packets}
    if len(link_types) != 1:
        raise CaptureExportError(
            "Classic PCAP supports one link type per file. "
            "Export this mixed-linktype capture as CSV or JSON."
        )

    link_type = next(iter(link_types))
    max_length = max(packet.record.captured_length for packet in packets)
    snaplen = max(65535, max_length)

    with path.open("wb") as handle:
        # Write a little-endian PCAP file with nanosecond timestamps.
        handle.write(struct.pack(
            "<IHHIIII",
            0xA1B23C4D,
            2,
            4,
            0,
            0,
            snaplen,
            link_type,
        ))

        for packet in packets:
            record = packet.record
            timestamp = record.timestamp or 0.0
            if timestamp < 0:
                raise CaptureExportError(
                    "PCAP cannot store timestamps before the Unix epoch"
                )
            seconds = floor(timestamp)
            nanoseconds = round((timestamp - seconds) * 1_000_000_000)
            if nanoseconds >= 1_000_000_000:
                seconds += 1
                nanoseconds = 0
            if seconds > 0xFFFFFFFF:
                raise CaptureExportError("PCAP timestamp exceeds the format limit")
            handle.write(struct.pack(
                "<IIII",
                seconds,
                nanoseconds,
                record.captured_length,
                record.original_length,
            ))
            handle.write(record.data)
