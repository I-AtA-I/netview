from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .dissector import DissectionResult, dissect_packet
from .models import PacketRecord


@dataclass(frozen=True, slots=True)
class ProcessedPacket:
    record: PacketRecord
    dissection: DissectionResult

    @property
    def number(self) -> int:
        return self.record.number

    @property
    def timestamp(self) -> float | None:
        return self.record.timestamp

    @property
    def length(self) -> int:
        return self.record.original_length

    @property
    def captured_length(self) -> int:
        return self.record.captured_length

    @property
    def protocol(self) -> str:
        return self.dissection.protocol

    @property
    def source(self) -> str:
        if self.dissection.ipv4 is not None:
            return self.dissection.ipv4.source_ip

        if self.dissection.ethernet is not None:
            return self.dissection.ethernet.source_mac

        return "—"

    @property
    def destination(self) -> str:
        if self.dissection.ipv4 is not None:
            return self.dissection.ipv4.destination_ip

        if self.dissection.ethernet is not None:
            return self.dissection.ethernet.destination_mac

        return "—"

    @property
    def source_port(self) -> int | None:
        if self.dissection.tcp is not None:
            return self.dissection.tcp.source_port

        if self.dissection.udp is not None:
            return self.dissection.udp.source_port

        return None

    @property
    def destination_port(self) -> int | None:
        if self.dissection.tcp is not None:
            return self.dissection.tcp.destination_port

        if self.dissection.udp is not None:
            return self.dissection.udp.destination_port

        return None

    @property
    def info(self) -> str:
        dissection = self.dissection

        if dissection.errors:
            return " | ".join(dissection.errors)

        if dissection.tcp is not None:
            tcp = dissection.tcp
            flags = ",".join(tcp.active_flags) or "none"

            return (
                f"{tcp.source_port} → {tcp.destination_port} "
                f"[{flags}] Seq={tcp.sequence_number} "
                f"Ack={tcp.acknowledgment_number}"
            )

        if dissection.udp is not None:
            udp = dissection.udp

            return (
                f"{udp.source_port} → {udp.destination_port} "
                f"Len={udp.payload_length}"
            )

        if dissection.ipv4 is not None:
            ipv4 = dissection.ipv4

            if ipv4.is_fragment:
                return (
                    f"Fragment offset={ipv4.fragment_offset * 8} "
                    f"MF={int(ipv4.more_fragments)}"
                )

            return (
                f"TTL={ipv4.ttl} "
                f"ID=0x{ipv4.identification:04x}"
            )

        if dissection.payload:
            return f"{len(dissection.payload)} bytes"

        return "—"


def process_packet(packet: PacketRecord) -> ProcessedPacket:
    return ProcessedPacket(
        record=packet,
        dissection=dissect_packet(packet),
    )


def iter_processed_packets(
    packets: Iterable[PacketRecord],
) -> Iterator[ProcessedPacket]:
    for packet in packets:
        yield process_packet(packet)
