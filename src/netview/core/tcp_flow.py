from __future__ import annotations

from bisect import bisect_left
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .pipeline import ProcessedPacket
from .streams import StreamEndpoint, TCPStreamKey, signed_sequence_delta


def _record_sequence_range(
    ranges: list[tuple[int, int]],
    start: int,
    end: int,
) -> bool:
    """Add a sequence range and report whether it overlaps an earlier one."""
    index = bisect_left(ranges, (start, end))
    overlaps = index > 0 and ranges[index - 1][1] > start

    scan = index
    while scan < len(ranges) and ranges[scan][0] < end:
        if ranges[scan][1] > start:
            overlaps = True
        scan += 1

    merge_start = index
    if index > 0 and ranges[index - 1][1] >= start:
        merge_start = index - 1
        start = ranges[merge_start][0]
        end = max(end, ranges[merge_start][1])

    merge_end = merge_start
    while merge_end < len(ranges) and ranges[merge_end][0] <= end:
        end = max(end, ranges[merge_end][1])
        merge_end += 1

    ranges[merge_start:merge_end] = [(start, end)]
    return overlaps


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
    """Get a shared key for both directions of an IPv4/IPv6 TCP connection."""
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
    *,
    should_stop: Callable[[], bool] | None = None,
) -> TCPFlowGraph | None:
    """Build a TCP sequence diagram for one conversation.

    Overlap is a capture-order heuristic: it marks sequence ranges that
    intersect an earlier observed payload range in the same direction.
    """
    raw_events: list[tuple[ProcessedPacket, int, int, int | None, bool, bool]] = []
    base_sequences: list[int | None] = [None, None]
    observed_ranges: list[list[tuple[int, int]]] = [[], []]
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    for packet in packets:
        if should_stop is not None and should_stop():
            return None
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
            possible_overlap = _record_sequence_range(
                observed_ranges[direction],
                sequence_offset,
                end_offset,
            )

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
            if first_timestamp is None or packet.timestamp < first_timestamp:
                first_timestamp = packet.timestamp
            if last_timestamp is None or packet.timestamp > last_timestamp:
                last_timestamp = packet.timestamp

    if not raw_events or (should_stop is not None and should_stop()):
        return None
    duration = (
        max(0.0, last_timestamp - first_timestamp)
        if first_timestamp is not None and last_timestamp is not None
        else None
    )

    events = []
    overlap_count = 0
    for (
        packet,
        direction,
        sequence_offset,
        acknowledgment,
        possible_overlap,
        truncated,
    ) in raw_events:
        if should_stop is not None and should_stop():
            return None
        events.append(TCPFlowEvent(
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
        ))
        overlap_count += int(possible_overlap)

    return TCPFlowGraph(
        key=target_key,
        events=tuple(events),
        duration_seconds=duration,
        overlap_count=overlap_count,
    )
