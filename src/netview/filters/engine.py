import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from netview.core.pipeline import ProcessedPacket


class FilterSyntaxError(ValueError):
    pass


_TOKEN_RE = re.compile(r'\s*(==|!=|>=|<=|[()]|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[<>]|[^\s()=!<>]+)')
_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

_OPERATORS = {"==", "!=", ">", ">=", "<", "<="}

_PROTOCOLS = {
    "eth",
    "ethernet",
    "ip",
    "ipv4",
    "tcp",
    "udp",
    "icmp",
    "vlan",
    "fragment",
    "arp",
    "ipv6",
    "icmpv6",
    "dns",
    "mdns",
    "llmnr",
    "http",
    "tls",
}

_FIELD_KINDS = {
    "frame.number": "number",
    "frame.len": "number",
    "frame.cap_len": "number",
    "ip.src": "ip",
    "ip.dst": "ip",
    "ip.ttl": "number",
    "ip.proto": "number",
    "ipv6.src": "ipv6",
    "ipv6.dst": "ipv6",
    "ipv6.hlim": "number",
    "ipv6.nxt": "number",
    "arp.opcode": "number",
    "arp.hw.type": "number",
    "arp.proto.type": "number",
    "arp.src.hw_mac": "mac",
    "arp.dst.hw_mac": "mac",
    "arp.src.proto_ipv4": "ip",
    "arp.dst.proto_ipv4": "ip",
    "icmp.type": "number",
    "icmp.code": "number",
    "icmpv6.type": "number",
    "icmpv6.code": "number",
    "dns.qry.type": "number",
    "dns.rcode": "number",
    "dns.flags.response": "bool",
    "dns.qry.name": "string",
    "http.host": "string",
    "http.request.method": "string",
    "http.request.uri": "string",
    "http.response.code": "number",
    "tls.sni": "string",
    "tls.handshake.type": "number",
    "tls.record.version": "number",
    "tls.record.content_type": "number",
    "eth.src": "mac",
    "eth.dst": "mac",
    "tcp.srcport": "number",
    "tcp.dstport": "number",
    "tcp.port": "number",
    "udp.srcport": "number",
    "udp.dstport": "number",
    "udp.port": "number",
    "tcp.flags.syn": "bool",
    "tcp.flags.ack": "bool",
    "tcp.flags.fin": "bool",
    "tcp.flags.rst": "bool",
    "tcp.flags.psh": "bool",
    "tcp.flags.urg": "bool",
}


@dataclass(frozen=True, slots=True)
class _Predicate:
    name: str
    operator: str | None = None
    value: int | str | bool | None = None


@dataclass(frozen=True, slots=True)
class _Binary:
    operator: str
    left: object
    right: object


@dataclass(frozen=True, slots=True)
class _Not:
    expression: object


@dataclass(frozen=True, slots=True)
class _Always:
    value: bool


def _tokenize(expression: str) -> list[str]:
    tokens = []
    position = 0

    while position < len(expression):
        if expression[position].isspace():
            position += 1
            continue

        match = _TOKEN_RE.match(expression, position)

        if match is None:
            raise FilterSyntaxError(
                f"Invalid character at position {position}"
            )

        tokens.append(match.group(1))
        position = match.end()

    return tokens


def _parse_value(field: str, raw_value: str):
    kind = _FIELD_KINDS[field]

    if kind == "number":
        try:
            value = (
                int(raw_value, 16)
                if raw_value.lower().startswith("0x")
                else int(raw_value, 10)
            )
        except ValueError as exc:
            raise FilterSyntaxError(
                f"Invalid numeric value: {raw_value}"
            ) from exc

        limits = {
            "frame.number": (1, None),
            "frame.len": (0, None),
            "frame.cap_len": (0, None),
            "ip.ttl": (0, 255),
            "ip.proto": (0, 255),
            "ipv6.hlim": (0, 255),
            "ipv6.nxt": (0, 255),
            "arp.opcode": (0, 65535),
            "arp.hw.type": (0, 65535),
            "arp.proto.type": (0, 65535),
            "icmp.type": (0, 255),
            "icmp.code": (0, 255),
            "icmpv6.type": (0, 255),
            "icmpv6.code": (0, 255),
            "dns.qry.type": (0, 65535),
            "dns.rcode": (0, 15),
            "http.response.code": (100, 599),
            "tls.handshake.type": (0, 255),
            "tls.record.version": (0, 65535),
            "tls.record.content_type": (0, 255),
            "tcp.srcport": (0, 65535),
            "tcp.dstport": (0, 65535),
            "tcp.port": (0, 65535),
            "udp.srcport": (0, 65535),
            "udp.dstport": (0, 65535),
            "udp.port": (0, 65535),
        }

        minimum, maximum = limits[field]

        if value < minimum or (maximum is not None and value > maximum):
            raise FilterSyntaxError(
                f"Value out of range for {field}: {raw_value}"
            )

        return value

    if kind == "ip":
        try:
            return str(IPv4Address(raw_value))
        except ValueError as exc:
            raise FilterSyntaxError(
                f"Invalid IPv4 address: {raw_value}"
            ) from exc

    if kind == "ipv6":
        try:
            return str(IPv6Address(raw_value))
        except ValueError as exc:
            raise FilterSyntaxError(
                f"Invalid IPv6 address: {raw_value}"
            ) from exc

    if kind == "mac":
        if not _MAC_RE.fullmatch(raw_value):
            raise FilterSyntaxError(
                f"Invalid MAC address: {raw_value}"
            )

        return raw_value.lower()

    if kind == "string":
        if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in {"\"", "'"}:
            quote = raw_value[0]
            value = raw_value[1:-1].replace("\\" + quote, quote).replace("\\\\", "\\")
        else:
            value = raw_value
        if not value:
            raise FilterSyntaxError("String filter value cannot be empty")
        return value

    if kind == "bool":
        value = raw_value.lower()

        if value not in {"true", "false"}:
            raise FilterSyntaxError(
                f"Expected true or false, got: {raw_value}"
            )

        return value == "true"

    raise FilterSyntaxError(f"Unsupported field type: {kind}")


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.position = 0

    def _peek(self) -> str | None:
        if self.position >= len(self.tokens):
            return None

        return self.tokens[self.position]

    def _take(self) -> str:
        token = self._peek()

        if token is None:
            raise FilterSyntaxError("Unexpected end of expression")

        self.position += 1
        return token

    def parse(self):
        if not self.tokens:
            return _Always(True)

        result = self._parse_or()

        if self._peek() is not None:
            raise FilterSyntaxError(
                f"Unexpected token: {self._peek()}"
            )

        return result

    def _parse_or(self):
        left = self._parse_and()

        while (token := self._peek()) is not None and token.lower() == "or":
            self._take()
            right = self._parse_and()
            left = _Binary("or", left, right)

        return left

    def _parse_and(self):
        left = self._parse_unary()

        while (token := self._peek()) is not None and token.lower() == "and":
            self._take()
            right = self._parse_unary()
            left = _Binary("and", left, right)

        return left

    def _parse_unary(self):
        token = self._peek()

        if token is not None and token.lower() == "not":
            self._take()
            return _Not(self._parse_unary())

        if token == "(":
            self._take()
            result = self._parse_or()

            if self._take() != ")":
                raise FilterSyntaxError("Expected closing parenthesis")

            return result

        return self._parse_predicate()

    def _parse_predicate(self):
        name = self._take().lower()
        operator = self._peek()

        if operator in _OPERATORS:
            self._take()
            raw_value = self._take()

            if name not in _FIELD_KINDS:
                raise FilterSyntaxError(f"Unknown field: {name}")

            kind = _FIELD_KINDS[name]

            if kind in {"ip", "ipv6", "mac", "bool", "string"} and operator not in {"==", "!="}:
                raise FilterSyntaxError(
                    f"Operator {operator} is not supported for {name}"
                )

            value = _parse_value(name, raw_value)

            return _Predicate(name, operator, value)

        if name not in _PROTOCOLS:
            raise FilterSyntaxError(
                f"Unknown protocol or incomplete predicate: {name}"
            )

        return _Predicate(name)


@dataclass(frozen=True, slots=True)
class CompiledFilter:
    expression: str
    _root: object

    def matches(self, packet: ProcessedPacket) -> bool:
        return _evaluate(self._root, packet)


def compile_filter(expression: str) -> CompiledFilter:
    if not isinstance(expression, str):
        raise TypeError("Filter expression must be a string")

    tokens = _tokenize(expression)
    root = _Parser(tokens).parse()

    return CompiledFilter(expression, root)


def _field_value(field: str, packet: ProcessedPacket):
    record = packet.record
    dissection = packet.dissection

    if field == "frame.number":
        return record.number

    if field == "frame.len":
        return record.original_length

    if field == "frame.cap_len":
        return record.captured_length

    if field == "ip.src":
        return dissection.ipv4.source_ip if dissection.ipv4 else None

    if field == "ip.dst":
        return dissection.ipv4.destination_ip if dissection.ipv4 else None

    if field == "ip.ttl":
        return dissection.ipv4.ttl if dissection.ipv4 else None

    if field == "ip.proto":
        return dissection.ipv4.protocol if dissection.ipv4 else None

    if field == "ipv6.src":
        return dissection.ipv6.source_ip if dissection.ipv6 else None

    if field == "ipv6.dst":
        return dissection.ipv6.destination_ip if dissection.ipv6 else None

    if field == "ipv6.hlim":
        return dissection.ipv6.hop_limit if dissection.ipv6 else None

    if field == "ipv6.nxt":
        return dissection.ipv6.upper_layer_protocol if dissection.ipv6 else None

    if field == "arp.opcode":
        return dissection.arp.opcode if dissection.arp else None

    if field == "arp.hw.type":
        return dissection.arp.hardware_type if dissection.arp else None

    if field == "arp.proto.type":
        return dissection.arp.protocol_type if dissection.arp else None

    if field == "arp.src.hw_mac":
        return dissection.arp.sender_hardware_address if dissection.arp else None

    if field == "arp.dst.hw_mac":
        return dissection.arp.target_hardware_address if dissection.arp else None

    if field == "arp.src.proto_ipv4":
        return dissection.arp.sender_protocol_address if dissection.arp else None

    if field == "arp.dst.proto_ipv4":
        return dissection.arp.target_protocol_address if dissection.arp else None

    if field == "icmp.type":
        return dissection.icmp.type if dissection.icmp and dissection.icmp.version == 4 else None

    if field == "icmp.code":
        return dissection.icmp.code if dissection.icmp and dissection.icmp.version == 4 else None

    if field == "icmpv6.type":
        return dissection.icmp.type if dissection.icmp and dissection.icmp.version == 6 else None

    if field == "icmpv6.code":
        return dissection.icmp.code if dissection.icmp and dissection.icmp.version == 6 else None

    dns = dissection.dns
    if field == "dns.qry.name":
        return dns.query_name if dns else None
    if field == "dns.qry.type":
        return dns.questions[0].qtype if dns and dns.questions else None
    if field == "dns.flags.response":
        return dns.is_response if dns else None
    if field == "dns.rcode":
        return dns.rcode if dns else None

    http = dissection.http
    if field == "http.host":
        return http.host if http else None
    if field == "http.request.method":
        return http.method if http else None
    if field == "http.request.uri":
        return http.target if http else None
    if field == "http.response.code":
        return http.status_code if http else None

    tls = dissection.tls
    if field == "tls.sni":
        return tls.client_hello.server_name if tls and tls.client_hello else None
    if field == "tls.handshake.type":
        return tls.handshake_type if tls else None
    if field == "tls.record.version":
        return tls.legacy_version if tls else None
    if field == "tls.record.content_type":
        return tls.content_type if tls else None

    if field == "eth.src":
        return dissection.ethernet.source_mac if dissection.ethernet else None

    if field == "eth.dst":
        return dissection.ethernet.destination_mac if dissection.ethernet else None

    tcp = dissection.tcp
    udp = dissection.udp

    if field == "tcp.srcport":
        return tcp.source_port if tcp else None

    if field == "tcp.dstport":
        return tcp.destination_port if tcp else None

    if field == "tcp.port":
        return (tcp.source_port, tcp.destination_port) if tcp else None

    if field.startswith("tcp.flags."):
        if tcp is None:
            return None

        flags = {
            "tcp.flags.syn": tcp.is_syn,
            "tcp.flags.ack": tcp.is_ack,
            "tcp.flags.fin": tcp.is_fin,
            "tcp.flags.rst": tcp.is_rst,
            "tcp.flags.psh": tcp.is_psh,
            "tcp.flags.urg": tcp.is_urg,
        }

        return flags[field]

    if field == "udp.srcport":
        return udp.source_port if udp else None

    if field == "udp.dstport":
        return udp.destination_port if udp else None

    if field == "udp.port":
        return (udp.source_port, udp.destination_port) if udp else None

    return None


def _compare(actual, operator: str, expected) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        actual = actual.casefold()
        expected = expected.casefold()

    if operator == "==":
        return actual == expected
    if operator == "!=":
        return actual != expected
    if operator == ">":
        return actual > expected
    if operator == ">=":
        return actual >= expected
    if operator == "<":
        return actual < expected
    if operator == "<=":
        return actual <= expected

    return False


def _protocol_matches(name: str, packet: ProcessedPacket) -> bool:
    dissection = packet.dissection

    if name in {"eth", "ethernet"}:
        return dissection.ethernet is not None

    if name in {"ip", "ipv4"}:
        return dissection.ipv4 is not None

    if name == "ipv6":
        return dissection.ipv6 is not None

    if name == "arp":
        return dissection.arp is not None

    if name == "tcp":
        return dissection.tcp is not None

    if name == "udp":
        return dissection.udp is not None

    if name == "icmp":
        return dissection.icmp is not None and dissection.icmp.version == 4

    if name == "icmpv6":
        return dissection.icmp is not None and dissection.icmp.version == 6

    if name in {"dns", "mdns", "llmnr"}:
        if dissection.dns is None:
            return False
        if name == "mdns":
            return dissection.protocol == "mDNS"
        if name == "llmnr":
            return dissection.protocol == "LLMNR"
        return True

    if name == "http":
        return dissection.http is not None

    if name == "tls":
        return dissection.tls is not None

    if name == "vlan":
        return (
            dissection.ethernet is not None
            and bool(dissection.ethernet.vlan_tags)
        )

    if name == "fragment":
        return (
            (dissection.ipv4 is not None and dissection.ipv4.is_fragment)
            or (dissection.ipv6 is not None and dissection.ipv6.is_fragment)
        )

    return False


def _evaluate(node, packet: ProcessedPacket) -> bool:
    if isinstance(node, _Always):
        return node.value

    if isinstance(node, _Not):
        return not _evaluate(node.expression, packet)

    if isinstance(node, _Binary):
        if node.operator == "and":
            return (
                _evaluate(node.left, packet)
                and _evaluate(node.right, packet)
            )

        return (
            _evaluate(node.left, packet)
            or _evaluate(node.right, packet)
        )

    if isinstance(node, _Predicate):
        if node.operator is None:
            return _protocol_matches(node.name, packet)

        actual = _field_value(node.name, packet)

        if actual is None:
            return False

        if isinstance(actual, tuple):
            if node.operator == "!=":
                return all(
                    _compare(value, "!=", node.value)
                    for value in actual
                )

            return any(
                _compare(value, node.operator, node.value)
                for value in actual
            )

        return _compare(actual, node.operator, node.value)

    return False


def iter_filtered_packets(
    packets: Iterable[ProcessedPacket],
    expression: str | CompiledFilter,
) -> Iterator[ProcessedPacket]:
    compiled = (
        expression
        if isinstance(expression, CompiledFilter)
        else compile_filter(expression)
    )

    for packet in packets:
        if compiled.matches(packet):
            yield packet
