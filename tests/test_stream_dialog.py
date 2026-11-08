from netview.core.streams import (
    ReassembledChunk,
    ReassembledDirection,
    SequenceGap,
)
from netview.gui.stream_dialog import TCPStreamDialog


def test_follow_stream_displays_missing_data_before_next_chunk():
    direction = ReassembledDirection(
        chunks=(
            ReassembledChunk(sequence_offset=0, data=b"abc"),
            ReassembledChunk(sequence_offset=6, data=b"ghi"),
        ),
        gaps=(SequenceGap(start_offset=3, end_offset=6),),
        packet_count=2,
        payload_segment_count=2,
        payload_length=6,
        overlapping_bytes=0,
        truncated_packet_numbers=(),
    )

    formatted = TCPStreamDialog._format_direction(direction)

    assert "[MISSING DATA: 3 bytes between sequence offsets 3 and 6.]" in formatted
    assert "sequence gap(s) detected" in formatted
