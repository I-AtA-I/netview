import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address

from netview.core.pipeline import ProcessedPacket


class FilterSyntaxError(ValueError):
    pass


_TOKEN_RE = re.compile(r"\s*(==|!=|>=|<=|[()<>]|[^\s()=!<>]+)")
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
}

_FIELD_KINDS = {
    "frame.number": "number",
    "frame.len": "number",
    "frame.cap_len": "number",
    "ip.src": "ip",
    "ip.dst": "ip",
    "ip.ttl": "number",
    "ip.proto": "number",
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

    if kind == "mac":
        if not _MAC_RE.fullmatch(raw_value):
            raise FilterSyntaxError(
                f"Invalid MAC address: {raw_value}"
            )

        return raw_value.lower()

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

            if kind in {"ip", "mac", "bool"} and operator not in {"==", "!="}:
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

    if name == "tcp":
        return dissection.tcp is not None

    if name == "udp":
        return dissection.udp is not None

    if name == "icmp":
        return (
            dissection.ipv4 is not None
            and dissection.ipv4.protocol == 1
        )

    if name == "vlan":
        return (
            dissection.ethernet is not None
            and bool(dissection.ethernet.vlan_tags)
        )

    if name == "fragment":
        return (
            dissection.ipv4 is not None
            and dissection.ipv4.is_fragment
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
