from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .pipeline import ProcessedPacket

_SEQUENCE_MODULUS = 1 << 32
_SEQUENCE_HALF = 1 << 31


@dataclass(frozen=True, slots=True, order=True)
class StreamEndpoint:
    address: str
    port: int

    def __str__(self) -> str:
        return f"{self.address}:{self.port}"


@dataclass(frozen=True, slots=True)
class TCPStreamKey:
    endpoint_a: StreamEndpoint
    endpoint_b: StreamEndpoint

    def __str__(self) -> str:
        return f"{self.endpoint_a} ↔ {self.endpoint_b}"


@dataclass(frozen=True, slots=True)
class ReassembledChunk:
    sequence_offset: int
    data: bytes


@dataclass(frozen=True, slots=True)
class SequenceGap:
    start_offset: int
    end_offset: int

    @property
    def length(self) -> int:
        return self.end_offset - self.start_offset


@dataclass(frozen=True, slots=True)
class ReassembledDirection:
    chunks: tuple[ReassembledChunk, ...]
    gaps: tuple[SequenceGap, ...]
    packet_count: int
    payload_segment_count: int
    payload_length: int
    overlapping_bytes: int
    truncated_packet_numbers: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class TCPStream:
    stream_id: int
    key: TCPStreamKey
    packet_count: int
    first_timestamp: float | None
    last_timestamp: float | None
    directions: tuple[ReassembledDirection, ReassembledDirection]

    @property
    def payload_length(self) -> int:
        return sum(direction.payload_length for direction in self.directions)


@dataclass(slots=True)
class _Segment:
    sequence_offset: int
    data: bytes
    packet_number: int
    truncated: bool


@dataclass(slots=True)
class _DirectionBuilder:
    base_sequence: int | None = None
    packet_count: int = 0
    segments: list[_Segment] = field(default_factory=list)
    truncated_packet_numbers: list[int] = field(default_factory=list)

    def add_packet(
        self,
        *,
        sequence_number: int,
        syn: bool,
        payload: bytes,
        packet_number: int,
        truncated: bool,
    ) -> None:
        self.packet_count += 1
        data_sequence = (sequence_number + int(syn)) & 0xFFFFFFFF

        if self.base_sequence is None:
            self.base_sequence = data_sequence

        offset = signed_sequence_delta(data_sequence, self.base_sequence)

        if truncated:
            self.truncated_packet_numbers.append(packet_number)

        if payload:
            self.segments.append(
                _Segment(
                    sequence_offset=offset,
                    data=payload,
                    packet_number=packet_number,
                    truncated=truncated,
                )
            )

    def finish(self) -> ReassembledDirection:
        if not self.segments:
            return ReassembledDirection(
                chunks=(),
                gaps=(),
                packet_count=self.packet_count,
                payload_segment_count=0,
                payload_length=0,
                overlapping_bytes=0,
                truncated_packet_numbers=tuple(self.truncated_packet_numbers),
            )

        # Stable sorting preserves capture order for segments with equal offsets.
        segments = sorted(
            self.segments,
            key=lambda segment: segment.sequence_offset,
        )

        chunks: list[ReassembledChunk] = []
        gaps: list[SequenceGap] = []
        current_start = segments[0].sequence_offset
        current_end = current_start + len(segments[0].data)
        current_data = bytearray(segments[0].data)
        overlapping_bytes = 0

        for segment in segments[1:]:
            start = segment.sequence_offset
            end = start + len(segment.data)

            if start > current_end:
                chunks.append(
                    ReassembledChunk(current_start, bytes(current_data))
                )
                gaps.append(SequenceGap(current_end, start))
                current_start = start
                current_end = end
                current_data = bytearray(segment.data)
                continue

            overlap = max(0, min(current_end, end) - start)
            overlapping_bytes += overlap

            if end > current_end:
                uncovered_data = segment.data[current_end - start:]
                current_data.extend(uncovered_data)
                current_end = end

        chunks.append(ReassembledChunk(current_start, bytes(current_data)))
        payload_length = sum(len(chunk.data) for chunk in chunks)

        return ReassembledDirection(
            chunks=tuple(chunks),
            gaps=tuple(gaps),
            packet_count=self.packet_count,
            payload_segment_count=len(self.segments),
            payload_length=payload_length,
            overlapping_bytes=overlapping_bytes,
            truncated_packet_numbers=tuple(self.truncated_packet_numbers),
        )


@dataclass(slots=True)
class _StreamBuilder:
    stream_id: int
    key: TCPStreamKey
    directions: tuple[_DirectionBuilder, _DirectionBuilder] = field(
        default_factory=lambda: (_DirectionBuilder(), _DirectionBuilder())
    )
    packet_count: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    def add(self, packet: ProcessedPacket, direction_index: int) -> None:
        ipv4 = packet.dissection.ipv4
        ipv6 = packet.dissection.ipv6
        tcp = packet.dissection.tcp
        if tcp is None or (ipv4 is None and ipv6 is None):
            return

        payload = packet.dissection.payload
        if ipv4 is not None:
            network_header_length = ipv4.header_length
            network_total_length = ipv4.total_length
        else:
            # upper_layer_offset includes the IPv6 base and extension headers.
            network_header_length = ipv6.upper_layer_offset
            network_total_length = ipv6.total_length
        expected_payload_length = max(
            0,
            network_total_length - network_header_length - tcp.header_length,
        )
        truncated = len(payload) < expected_payload_length

        self.directions[direction_index].add_packet(
            sequence_number=tcp.sequence_number,
            syn=tcp.is_syn,
            payload=payload,
            packet_number=packet.number,
            truncated=truncated,
        )
        self.packet_count += 1

        if packet.timestamp is not None:
            if self.first_timestamp is None:
                self.first_timestamp = packet.timestamp
            self.last_timestamp = packet.timestamp

    def finish(self) -> TCPStream:
        return TCPStream(
            stream_id=self.stream_id,
            key=self.key,
            packet_count=self.packet_count,
            first_timestamp=self.first_timestamp,
            last_timestamp=self.last_timestamp,
            directions=(
                self.directions[0].finish(),
                self.directions[1].finish(),
            ),
        )


def signed_sequence_delta(sequence: int, reference: int) -> int:
    """Return the nearest signed 32-bit distance from reference to sequence."""
    return ((sequence - reference + _SEQUENCE_HALF) % _SEQUENCE_MODULUS) - _SEQUENCE_HALF


def tcp_stream_key_for_packet(packet: ProcessedPacket) -> tuple[TCPStreamKey, int] | None:
    """Return the canonical IPv4/IPv6 TCP conversation key and packet direction."""
    ipv4 = packet.dissection.ipv4
    ipv6 = packet.dissection.ipv6
    tcp = packet.dissection.tcp
    if tcp is None or (ipv4 is None and ipv6 is None):
        return None
    ip = ipv4 or ipv6
    if ip.is_fragment:
        # Wait for IP fragment reassembly before using an incomplete segment.
        return None

    source = StreamEndpoint(ip.source_ip, tcp.source_port)
    destination = StreamEndpoint(ip.destination_ip, tcp.destination_port)

    if source <= destination:
        return TCPStreamKey(source, destination), 0
    return TCPStreamKey(destination, source), 1


def build_tcp_stream(
    packets: Iterable[ProcessedPacket],
    target_key: TCPStreamKey,
) -> TCPStream | None:
    """Build only one selected conversation instead of retaining every flow."""
    seen_keys: set[TCPStreamKey] = set()
    builder: _StreamBuilder | None = None

    for packet in packets:
        key_result = tcp_stream_key_for_packet(packet)
        if key_result is None:
            continue

        key, direction_index = key_result
        if key not in seen_keys:
            stream_id = len(seen_keys)
            seen_keys.add(key)
            if key == target_key:
                builder = _StreamBuilder(stream_id=stream_id, key=key)

        if key == target_key and builder is not None:
            builder.add(packet, direction_index)

    return builder.finish() if builder is not None else None


def build_tcp_streams(packets: Iterable[ProcessedPacket]) -> list[TCPStream]:
    """Group captured IPv4/TCP packets and reassemble each direction's payload.

    Sequence offsets are relative to the first observed sequence position in
    each direction. Missing ranges remain explicit gaps; bytes are never
    invented to fill them. Overlapping bytes are counted and the data from
    the segment with the lowest sequence offset is kept for the overlap.
    """
    builders: dict[TCPStreamKey, _StreamBuilder] = {}

    for packet in packets:
        key_result = tcp_stream_key_for_packet(packet)
        if key_result is None:
            continue

        key, direction_index = key_result
        builder = builders.get(key)

        if builder is None:
            builder = _StreamBuilder(
                stream_id=len(builders),
                key=key,
            )
            builders[key] = builder

        builder.add(packet, direction_index)

    return [builder.finish() for builder in builders.values()]
