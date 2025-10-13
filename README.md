# icmpx

A Python library for building ICMP diagnostics with raw sockets. The current API focuses on reusable building blocks instead of wrapping platform tools, so you can compose pings, probes, and traceroute-like flows directly from Python.

## Features

- Context-managed `Client` that takes care of raw socket setup and teardown
- `probe()` for single TTL measurements, `ping()` for repeated samples, and `traceroute()` for hop discovery
- Rich dataclasses (`EchoResult`, `TracerouteResult`, `ReceivedPacket`, and friends) for post-processing and formatting
- Optional reverse DNS lookup per request
- Clear `RawSocketPermissionError` when the interpreter lacks `CAP_NET_RAW`

## Requirements

- Python 3.14 or newer (see `pyproject.toml`)
- A Linux environment with permission to open ICMP raw sockets

Grant the capability once for your Python interpreter:

```bash
sudo setcap cap_net_raw+ep "$(realpath $(which python))"
```

## Getting Started

Install dependencies with a tool such as `uv`:

```bash
uv sync
```

Then run any of the example scripts:

```bash
uv run examples/ping.py
```

Or explore the traceroute example:

```bash
uv run examples/traceroute.py
```

## Usage Examples

### Basic ping loop

```python
from icmpx import Client

with Client(timeout=1.5) as client:
    results = client.ping("8.8.8.8", count=3)
    for result in results:
        if result.error:
            print(f"{result.request.addr}: {result.error}")
        else:
            print(
                f"reply from {result.reply.received_packet.ip_header.src_addr} "
                f"in {result.reply.rtt:.2f} ms"
            )
```

Each `EchoResult` carries the original request, an `EchoReply` with the measured RTT, and any ICMP errors returned during the exchange.

### Traceroute workflow

```python
from icmpx import Client

with Client(resolve_dns_default=True) as client:
    trace = client.traceroute("1.1.1.1", probes=2)
    for hop in trace.hops:
        addr = hop.addr or "?"
        host = hop.hostname or "?"
        rtts = [
            f"{probe.rtt:.2f} ms" if probe.rtt != float("inf") else "timeout"
            for probe in hop.probes
        ]
        print(f"{hop.ttl:>2}: {addr:<16} {host:<32} {' '.join(rtts)}")
```

`Client.traceroute()` returns a `TracerouteResult` with per-hop metadata, including optional reverse DNS resolution and all collected probe RTTs.

## Example Scripts

- `examples/ping.py` — shortest path to send repeated ICMP echo requests
- `examples/traceroute.py` — hop-by-hop discovery using the library API
- `examples/tui.py` — experimental Textual UI (depends on in-progress modules)

Feel free to copy these scripts as starting points for your own automation or integrate the `Client` directly inside existing services.

## Error Handling

If the interpreter cannot create a raw socket, `Client` raises `RawSocketPermissionError` with guidance on granting `CAP_NET_RAW`. Timeouts surface as `EchoResult.error == "timeout"` while other ICMP responses preserve their numeric type/code so you can present detailed diagnostics.

## Roadmap

- IPv6 probes and traceroutes
- Aggregated multiping support across multiple targets
- asyncio-compatible client implementation
- Additional examples and narrative documentation

Contributions and discussion are welcome — open an issue with your use case or ideas.
