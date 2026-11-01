# NetView

NetView is a desktop network protocol analyzer built with Python and PySide6. It reads PCAP/PCAPNG captures, dissects supported protocols with its own parser, and provides a Wireshark-inspired packet browsing interface.

## Current features

- Read classic PCAP and PCAPNG capture files.
- Decode Ethernet II, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 headers.
- Dissect DNS over UDP/TCP, including questions and common A, AAAA, name, MX and TXT records.
- Dissect HTTP/1.x request/response start lines and selected non-credential headers.
- Dissect TLS records plus ClientHello/ServerHello metadata such as SNI, ALPN, supported versions and cipher suites.
- Identify common non-decoded Ethernet protocols such as LLDP, EAPOL, MPLS and PPPoE by EtherType.
- Display packet metadata, protocol details and a raw hexadecimal/ASCII view.
- Filter packets with the built-in display-filter language.
- Load capture files in a background thread so the interface stays responsive during import.
- Capture packets live from one manually selected network interface.
- Stop live capture without closing the application; captured packets remain available for filtering and inspection.
- Reassemble IPv4/TCP conversations in both directions, including out-of-order segments, sequence wraparound, overlaps/retransmissions and explicit sequence gaps.
- Keep promiscuous mode disabled by default.
- View capture analytics including protocol distribution, top talkers, conversations and packet timeline.
- Export captures to classic PCAP, CSV or JSON.
- Open captured HTTP requests in a local-only Request Lab, edit the request and inspect the response.
- Drag and drop capture files into the application.

## Requirements

- Python 3.10 or newer
- PySide6 6.12 or newer
- Scapy 2.8 or newer (used for PCAP/PCAPNG file reading)
- `dumpcap` from Wireshark CLI (used for live capture on Linux)

## Setup on Linux

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Run the application:

```bash
netview
```

Or:

```bash
python -m netview
```

Run tests:

```bash
pytest -v
```

## Live capture permissions on Arch Linux

NetView keeps the GUI running as your normal user. Live capture is delegated to `dumpcap`, rather than granting raw-packet privileges to the Python interpreter or running the whole GUI as root.

Install the capture helper:

```bash
sudo pacman -S wireshark-cli
```

Add your account to the `wireshark` group:

```bash
sudo usermod -aG wireshark "$USER"
```

Then fully log out of your desktop session and log back in. Verify the new group membership and that `dumpcap` can list interfaces:

```bash
id -nG
dumpcap -D
```

Start NetView normally, without `sudo`:

```bash
netview
```

NetView invokes `dumpcap` for one manually selected interface and passes packets to its own dissection engine. Promiscuous mode is disabled. The package-managed `dumpcap` permissions are preferable to giving elevated network capabilities to `/usr/bin/python` or the entire GUI application.

## Display filter examples

```text
arp
ipv6
icmp
icmpv6
dns
mdns
llmnr
http
tls
dns.qry.name == example.com
dns.qry.type == 28
http.host == example.com
http.request.method == GET
http.response.code == 200
tls.sni == example.com
tls.handshake.type == 1
tcp
udp
arp.opcode == 1
arp.src.proto_ipv4 == 192.0.2.10
ipv6.src == 2001:db8::1
ip.src == 192.0.2.10
tcp.port == 443
udp.port == 53
tcp.flags.syn == true
frame.len > 1000
tcp and ip.src == 192.0.2.10
tcp or udp
not tcp
(tcp or udp) and ip
```

Supported fields and operators are implemented in `src/netview/filters/engine.py`. The filter engine supports common ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP and TLS predicates. String values can be quoted when they contain spaces or filter operators, for example `http.request.uri == "/search?q=netview"`. IPv6 extension headers supported by the dissection engine are Hop-by-Hop Options, Routing, Fragment, AH, Destination Options, Mobility, HIP and Shim6. IPv6 jumbograms are not implemented.

HTTP Request Lab strips captured Cookie and Authorization headers and only connects to localhost/loopback addresses. Requests are limited to 64 KiB and responses to 256 KiB; it is intended for local service testing, not remote request replay.

Analytics currently summarizes the loaded capture in memory. Classic PCAP export requires all packets to use the same link type; use CSV or JSON for mixed-linktype captures.

## Current scope and limitations

NetView is an early portfolio project, not a replacement for Wireshark. Application dissection is currently packet-based: a DNS message, HTTP/1.x start line and header block, or TLS record/hello must be sufficiently present in the captured packet. Application messages split across multiple TCP segments are not yet reassembled for application decoding, even though a separate Follow TCP Stream view is available. DNS-over-TLS, DNS-over-HTTPS, HTTP/2 and HTTP/3 are not decoded. HTTP parsing deliberately omits credential-bearing Cookie and Authorization headers and does not parse message bodies. TLS support is metadata-only: NetView does not decrypt TLS application data. TLS 1.3 encrypts most handshake messages after ServerHello, and Encrypted ClientHello (ECH) can hide the server name; in those cases SNI may not be available. Checksum validation, IP fragment reassembly and TCP connection-reuse detection remain future work. TCP stream reconstruction currently groups IPv4 conversations by the endpoint/port tuple; reused tuples within one capture can therefore be combined. IPv4-fragmented TCP packets are excluded until IP fragment reassembly is implemented. Sequence gaps are reported only between observed payload segments, because a missing tail cannot be inferred reliably.

Live capture uses `dumpcap` on one interface selected by the user. Promiscuous mode is explicitly disabled. On Linux, `dumpcap` must have the operating-system capture permissions configured; do not run the GUI, IDE, or Python interpreter as root just to bypass a permission error.

Only capture traffic on your own device and networks, or where you have explicit permission to monitor. Captured traffic may contain private information.

The first GUI version loads packets into memory after reading them in batches. It keeps the UI responsive during import, but very large capture files can still consume substantial memory.

## Project layout

```text
src/netview/
├── app.py
├── capture/       # PCAP/PCAPNG reader and live capture helpers
├── core/          # packet models, protocol parsers, dissection pipeline and TCP reassembly
├── filters/       # display-filter parser and evaluator
└── gui/           # PySide6 window, packet table, capture workers and stream viewer

tests/             # parser, pipeline, capture and filter tests
```

## Authorization

Only inspect packet captures that you own or are authorized to analyze. Use live capture only on interfaces and networks you are permitted to monitor.

## Troubleshooting

### `ModuleNotFoundError: No module named 'tests'`

The test suite is a local Python package. Keep `tests/__init__.py` in place when running `pytest` from the repository root:

```bash
pytest -v
```

### Qt reports `Failed to create wl_display`

This means Qt selected its Wayland platform plugin but could not connect to a Wayland display. In an X11 desktop session (for example XFCE), try launching with the XCB platform plugin:

```bash
QT_QPA_PLATFORM=xcb python -m netview
```

Do not set this globally unless you specifically need it; on a working Wayland session, the default platform selection should be allowed.
