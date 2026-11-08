from dataclasses import dataclass
import re


_REQUEST_LINE_RE = re.compile(
    rb"^([A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}) ([^\s]{1,8192}) (HTTP/1\.[01])$"
)
_RESPONSE_LINE_RE = re.compile(rb"^(HTTP/1\.[01]) ([0-9]{3})(?: (.*))?$")

# Keep credentials out of packet metadata.
_SAFE_HEADERS = {
    "host",
    "content-type",
    "content-length",
    "server",
    "date",
    "connection",
    "transfer-encoding",
    "accept",
    "accept-encoding",
    "accept-language",
}


@dataclass(frozen=True, slots=True)
class HTTPMessage:
    is_request: bool
    version: str
    method: str | None = None
    target: str | None = None
    status_code: int | None = None
    reason: str | None = None
    host: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    server: str | None = None
    connection: str | None = None
    transfer_encoding: str | None = None
    headers_complete: bool = False
    header_count: int = 0

    @property
    def start_line(self) -> str:
        if self.is_request:
            return f"{self.method} {self.target} {self.version}"
        suffix = f" {self.reason}" if self.reason else ""
        return f"{self.version} {self.status_code}{suffix}"


def looks_like_http(data: bytes) -> bool:
    if not data:
        return False
    first_line = data.split(b"\r\n", 1)[0][:9000]
    return bool(_REQUEST_LINE_RE.match(first_line) or _RESPONSE_LINE_RE.match(first_line))


def _clean_header_value(value: bytes) -> str:
    # HTTP/1 headers use ISO-8859-1. Keep displayed values short.
    decoded = value.decode("iso-8859-1", errors="replace").strip()
    return decoded[:512]


def parse_http_message(data: bytes) -> HTTPMessage:
    if not data:
        raise ValueError("Empty HTTP payload")

    separator = data.find(b"\r\n\r\n")
    headers_complete = separator >= 0
    header_block = data[:separator] if headers_complete else data
    lines = header_block.split(b"\r\n")
    if not lines:
        raise ValueError("Missing HTTP start line")

    request_match = _REQUEST_LINE_RE.match(lines[0])
    response_match = _RESPONSE_LINE_RE.match(lines[0])

    if request_match:
        is_request = True
        method = request_match.group(1).decode("ascii")
        target = request_match.group(2).decode("iso-8859-1", errors="replace")[:8192]
        version = request_match.group(3).decode("ascii")
        status_code = None
        reason = None
    elif response_match:
        is_request = False
        method = None
        target = None
        version = response_match.group(1).decode("ascii")
        status_code = int(response_match.group(2))
        reason = (response_match.group(3) or b"").decode("iso-8859-1", errors="replace")[:256]
    else:
        raise ValueError("Payload does not begin with a supported HTTP/1 start line")

    headers: dict[str, str] = {}
    header_count = 0

    for raw_line in lines[1:]:
        if not raw_line:
            continue
        if raw_line[:1] in (b" ", b"\t"):
            # Ignore obsolete folded headers rather than attaching them to another field.
            continue
        if b":" not in raw_line:
            continue
        raw_name, raw_value = raw_line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").strip().lower()
        except UnicodeDecodeError:
            continue
        if not name or not all(ch.isalnum() or ch == "-" for ch in name):
            continue
        header_count += 1
        if name in _SAFE_HEADERS:
            value = _clean_header_value(raw_value)
            if name in headers:
                headers[name] = f"{headers[name]}, {value}"[:512]
            else:
                headers[name] = value

    content_length = None
    if "content-length" in headers:
        try:
            content_length = int(headers["content-length"], 10)
            if content_length < 0:
                content_length = None
        except ValueError:
            content_length = None

    return HTTPMessage(
        is_request=is_request,
        version=version,
        method=method,
        target=target,
        status_code=status_code,
        reason=reason,
        host=headers.get("host"),
        content_type=headers.get("content-type"),
        content_length=content_length,
        server=headers.get("server"),
        connection=headers.get("connection"),
        transfer_encoding=headers.get("transfer-encoding"),
        headers_complete=headers_complete,
        header_count=header_count,
    )
