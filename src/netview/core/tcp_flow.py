from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .pipeline import ProcessedPacket
from .streams import StreamEndpoint, TCPStreamKey, signed_sequence_delta


@dataclass(frozen=True, slots=True)
class TCPFlowEvent:
    packet_number: int
    timestamp: float | None
    elapsed_seconds: float | None
    direction: int
    sequence_number: int
    sequence_offset: int
    acknowledgment_number: int | None
    payload_length: int
    flags: tuple[str, ...]
    possible_overlap: bool
    truncated: bool


@dataclass(frozen=True, slots=True)
class TCPFlowGraph:
    key: TCPStreamKey
    events: tuple[TCPFlowEvent, ...]
    duration_seconds: float | None
    overlap_count: int

    @property
    def packet_count(self) -> int:
        return len(self.events)


def tcp_flow_key_for_packet(
    packet: ProcessedPacket,
) -> tuple[TCPStreamKey, int] | None:
    """Return a direction-independent key for an unfragmented IPv4/IPv6 TCP packet."""
    dissection = packet.dissection
    tcp = dissection.tcp
    if tcp is None:
        return None

    if dissection.ipv4 is not None:
        ip = dissection.ipv4
        if getattr(ip, "is_fragment", False):
            return None
        source_address = getattr(ip, "source_ip", None)
        destination_address = getattr(ip, "destination_ip", None)
    elif dissection.ipv6 is not None:
        ip = dissection.ipv6
        if getattr(ip, "is_fragment", False):
            return None
        source_address = getattr(ip, "source_ip", None)
        destination_address = getattr(ip, "destination_ip", None)
    else:
        return None

    if not source_address or not destination_address:
        return None

    source = StreamEndpoint(source_address, tcp.source_port)
    destination = StreamEndpoint(destination_address, tcp.destination_port)
    if source <= destination:
        return TCPStreamKey(source, destination), 0
    return TCPStreamKey(destination, source), 1


def build_tcp_flow_graph(
    packets: Iterable[ProcessedPacket],
    target_key: TCPStreamKey,
) -> TCPFlowGraph | None:
    """Build a packet-by-packet TCP sequence diagram for one conversation.

    Overlap is a capture-order heuristic: it marks sequence ranges that
    intersect an earlier observed payload range in the same direction.
    """
    raw_events: list[tuple[ProcessedPacket, int, int, int | None, bool, bool]] = []
    base_sequences: list[int | None] = [None, None]
    observed_ranges: list[list[tuple[int, int]]] = [[], []]
    timestamps: list[float] = []

    for packet in packets:
        key_result = tcp_flow_key_for_packet(packet)
        if key_result is None:
            continue
        key, direction = key_result
        if key != target_key:
            continue

        tcp = packet.dissection.tcp
        if tcp is None:
            continue

        data_sequence = (tcp.sequence_number + int(tcp.is_syn)) & 0xFFFFFFFF
        if base_sequences[direction] is None:
            base_sequences[direction] = data_sequence
        sequence_offset = signed_sequence_delta(
            data_sequence,
            int(base_sequences[direction]),
        )

        payload_length = len(packet.dissection.payload)
        possible_overlap = False
        if payload_length:
            end_offset = sequence_offset + payload_length
            possible_overlap = any(
                sequence_offset < previous_end and end_offset > previous_start
                for previous_start, previous_end in observed_ranges[direction]
            )
            observed_ranges[direction].append((sequence_offset, end_offset))

        ip = packet.dissection.ipv4 or packet.dissection.ipv6
        truncated = (
            packet.record.original_length > packet.record.captured_length
            or (ip.is_truncated if ip is not None else False)
        )
        acknowledgment = tcp.acknowledgment_number if tcp.is_ack else None
        raw_events.append((
            packet,
            direction,
            sequence_offset,
            acknowledgment,
            possible_overlap,
            truncated,
        ))
        if packet.timestamp is not None:
            timestamps.append(packet.timestamp)

    if not raw_events:
        return None

    first_timestamp = min(timestamps) if timestamps else None
    last_timestamp = max(timestamps) if timestamps else None
    duration = (
        max(0.0, last_timestamp - first_timestamp)
        if first_timestamp is not None and last_timestamp is not None
        else None
    )

    events = tuple(
        TCPFlowEvent(
            packet_number=packet.number,
            timestamp=packet.timestamp,
            elapsed_seconds=(
                packet.timestamp - first_timestamp
                if packet.timestamp is not None and first_timestamp is not None
                else None
            ),
            direction=direction,
            sequence_number=packet.dissection.tcp.sequence_number,
            sequence_offset=sequence_offset,
            acknowledgment_number=acknowledgment,
            payload_length=len(packet.dissection.payload),
            flags=packet.dissection.tcp.active_flags,
            possible_overlap=possible_overlap,
            truncated=truncated,
        )
        for (
            packet,
            direction,
            sequence_offset,
            acknowledgment,
            possible_overlap,
            truncated,
        ) in raw_events
    )

    return TCPFlowGraph(
        key=target_key,
        events=events,
        duration_seconds=duration,
        overlap_count=sum(event.possible_overlap for event in events),
    )
