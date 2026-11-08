from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address


class ARPParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ARPHeader:
    hardware_type: int
    protocol_type: int
    hardware_length: int
    protocol_length: int
    opcode: int
    sender_hardware: bytes
    sender_protocol: bytes
    target_hardware: bytes
    target_protocol: bytes

    @property
    def operation(self) -> str:
        return {
            1: "Request",
            2: "Reply",
            3: "Reverse request",
            4: "Reverse reply",
            8: "Inverse request",
            9: "Inverse reply",
        }.get(self.opcode, f"Unknown ({self.opcode})")

    @property
    def hardware_type_name(self) -> str:
        return {
            1: "Ethernet",
            6: "IEEE 802",
            7: "ARCnet",
            15: "Frame Relay",
            32: "InfiniBand",
        }.get(self.hardware_type, f"Unknown ({self.hardware_type})")

    @property
    def protocol_type_name(self) -> str:
        return {
            0x0800: "IPv4",
            0x86DD: "IPv6",
        }.get(self.protocol_type, f"0x{self.protocol_type:04x}")

    @staticmethod
    def _format_hardware_address(value: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in value)

    @staticmethod
    def _format_protocol_address(protocol_type: int, value: bytes) -> str:
        if protocol_type == 0x0800 and len(value) == 4:
            return str(IPv4Address(value))
        if protocol_type == 0x86DD and len(value) == 16:
            return str(IPv6Address(value))
        return value.hex(":") or "(empty)"

    @property
    def sender_hardware_address(self) -> str:
        return self._format_hardware_address(self.sender_hardware)

    @property
    def target_hardware_address(self) -> str:
        return self._format_hardware_address(self.target_hardware)

    @property
    def sender_protocol_address(self) -> str:
        return self._format_protocol_address(
            self.protocol_type, self.sender_protocol
        )

    @property
    def target_protocol_address(self) -> str:
        return self._format_protocol_address(
            self.protocol_type, self.target_protocol
        )


def parse_arp_packet(data: bytes) -> ARPHeader:
    if len(data) < 8:
        raise ARPParseError("ARP packet is shorter than its fixed header")

    hardware_type = int.from_bytes(data[0:2], "big")
    protocol_type = int.from_bytes(data[2:4], "big")
    hardware_length = data[4]
    protocol_length = data[5]
    opcode = int.from_bytes(data[6:8], "big")

    expected_length = 8 + 2 * hardware_length + 2 * protocol_length
    if len(data) < expected_length:
        raise ARPParseError(
            f"Truncated ARP addresses: expected {expected_length} bytes, got {len(data)}"
        )

    offset = 8
    sender_hardware = data[offset:offset + hardware_length]
    offset += hardware_length
    sender_protocol = data[offset:offset + protocol_length]
    offset += protocol_length
    target_hardware = data[offset:offset + hardware_length]
    offset += hardware_length
    target_protocol = data[offset:offset + protocol_length]

    return ARPHeader(
        hardware_type=hardware_type,
        protocol_type=protocol_type,
        hardware_length=hardware_length,
        protocol_length=protocol_length,
        opcode=opcode,
        sender_hardware=sender_hardware,
        sender_protocol=sender_protocol,
        target_hardware=target_hardware,
        target_protocol=target_protocol,
    )
