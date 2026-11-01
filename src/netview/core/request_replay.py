import ipaddress
import socket

from .http import parse_http_message


MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024


class RequestReplayError(ValueError):
    pass


def send_loopback_request(
    host: str,
    port: int,
    request: bytes,
    *,
    timeout: float = 3.0,
) -> bytes:
    target = host.strip().lower()
    if target == "localhost":
        address = "127.0.0.1"
    else:
        try:
            parsed = ipaddress.ip_address(target)
        except ValueError as exc:
            raise RequestReplayError("Only localhost or a loopback IP is allowed") from exc
        if not parsed.is_loopback or "%" in target:
            raise RequestReplayError("Requests are restricted to loopback addresses")
        address = str(parsed)

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise RequestReplayError("Port must be between 1 and 65535")
    if not request or len(request) > MAX_REQUEST_BYTES:
        raise RequestReplayError("Request must be between 1 byte and 64 KiB")

    try:
        message = parse_http_message(request)
    except ValueError as exc:
        raise RequestReplayError(f"Invalid HTTP request: {exc}") from exc
    if not message.is_request:
        raise RequestReplayError("Only HTTP requests can be sent from Request Lab")

    outgoing = request
    if b"\r\n\r\n" in request and b"\r\nconnection:" not in request.lower():
        outgoing = request.replace(
            b"\r\n\r\n",
            b"\r\nConnection: close\r\n\r\n",
            1,
        )

    response = bytearray()
    try:
        with socket.create_connection((address, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(outgoing)
            while len(response) < MAX_RESPONSE_BYTES:
                chunk = connection.recv(min(8192, MAX_RESPONSE_BYTES - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
    except OSError as exc:
        raise RequestReplayError(f"Local request failed: {exc}") from exc

    return bytes(response)
