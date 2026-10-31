from dataclasses import dataclass
import math


@dataclass(frozen=True, slots=True)
class PacketRecord:
    number: int
    timestamp: float | None
    captured_length: int
    original_length: int
    link_type: int
    data: bytes

    def __post_init__(self) -> None:
        if self.number < 1:
            raise ValueError("Packet number must be positive")

        if self.timestamp is not None and not math.isfinite(self.timestamp):
            raise ValueError("Timestamp must be finite")

        if self.captured_length < 0:
            raise ValueError("Captured length cannot be negative")

        if self.captured_length != len(self.data):
            raise ValueError("Captured length does not match data length")

        if self.original_length < self.captured_length:
            raise ValueError("Original length cannot be smaller than captured length")

        if self.link_type < 0:
            raise ValueError("Link type cannot be negative")
