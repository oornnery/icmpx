# icmpx

A Python library for building ICMP diagnostics with raw sockets. The current API focuses on reusable building blocks instead of wrapping platform tools, so you can compose pings, probes, and traceroute-like flows directly from Python.

## Features

- Context-managed `Client` that takes care of raw socket setup and teardown
- `probe()` for single TTL measurements, `ping()` for repeated samples, and `traceroute()` for hop discovery
- Rich dataclasses (`EchoResult`, `TracerouteResult`, `ReceivedPacket`, and friends) for post-processing and formatting
- Optional reverse DNS lookup per request
- Clear `RawSocketPermissionError` when the interpreter lacks `CAP_NET_RAW`

## Requirements

- Python 3.11–3.14 (prefers 3.14 when available; see `pyproject.toml`)
- A Linux environment with permission to open ICMP raw sockets

Grant the capability once for your Python interpreter (the helper works with `uvx` or inside a venv and launches the demo after verifying success):

```bash
uvx icmpx --bootstrap-cap
```

If you cannot use the helper, apply `setcap` manually:

```bash
sudo setcap cap_net_raw+ep "$(realpath $(which python))"
```

## Getting Started

Get the sources and prepare a `uv` environment:

```bash
git clone https://github.com/oornnery/icmpx.git
cd icmpx
uv python install 3.14  # optional; skip if uv cannot fetch it yet
uv venv --python 3.14   # drop --python to let uv pick another 3.11+ runtime
uv sync
uv pip install .
uv run icmpx --bootstrap-cap  # applies CAP_NET_RAW and starts the demo once verified
```

After granting `CAP_NET_RAW`, run any of the examples:

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

### Live MTR loop

```bash
uv run examples/mtr.py 1.1.1.1 -c 10 -i 0.5
```

This script streams probe statistics in a Rich table, updating packet loss and RTT metrics per hop across the configured cycles.

```bash
(icmpx) ➜  icmpx git:(main) ✗ uv run examples/mtr.py 8.8.8.8 -c 100
Found existing alias for "uv run". You should use: "uvr"
                                                                                       MTR to 8.8.8.8
┌─────────┬─────────────────────────────┬──────────────────────────────────────────────────────────────┬──────────┬──────────┬──────────────┬────────────┬───────────┬──────────┬──────────┐
│     Hop │ Address                     │ Hostname                                                     │     Sent │     Recv │       Loss % │       Last │       Avg │     Best │    Worst │
├─────────┼─────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────┼──────────┼──────────────┼────────────┼───────────┼──────────┼──────────┤
│       1 │ 172.19.112.1                │ _gateway                                                     │      100 │      100 │          0.0 │       0.69 │      0.53 │     0.30 │     5.53 │
│       2 │ 192.168.15.1                │ menuvivofibra                                                │      100 │      100 │          0.0 │       3.52 │      5.46 │     3.07 │    37.70 │
│       3 │ 189.97.117.7                │ ip-189-97-117-7.user.vivozap.com.br                          │      100 │      100 │          0.0 │       7.77 │      9.46 │     5.46 │    30.08 │
│       4 │ 201.1.228.105               │ 201-1-228-105.dsl.telesp.net.br                              │      100 │      100 │          0.0 │       9.13 │      9.58 │     4.53 │    28.16 │
│       5 │ 187.100.196.140             │ 187-100-196-140.dsl.telesp.net.br                            │      100 │       72 │         28.0 │      13.78 │     11.10 │     4.97 │    41.67 │
│       6 │ ?                           │                                                              │      100 │        0 │        100.0 │          - │         - │        - │        - │
│       7 │ 72.14.220.222               │                                                              │      100 │      100 │          0.0 │       7.78 │     11.94 │     5.76 │    46.18 │
│       8 │ 172.253.69.243              │                                                              │      100 │      100 │          0.0 │      10.51 │     11.85 │     7.07 │    29.55 │
│       9 │ 108.170.248.215             │                                                              │      100 │      100 │          0.0 │      12.49 │     10.69 │     5.80 │    30.14 │
│      10 │ 8.8.8.8                     │ dns.google                                                   │      100 │      100 │          0.0 │       9.79 │     10.79 │     5.82 │    42.93 │
└─────────┴─────────────────────────────┴──────────────────────────────────────────────────────────────┴──────────┴──────────┴──────────────┴────────────┴───────────┴──────────┴──────────┘
```

### Interactive TUI

Launch the Textual interface to explore multiple diagnostics side by side:

```bash
uv run icmpx
```

Or run it without cloning by using `uvx`:

```bash
uvx icmpx
```

Use `q` (or the terminal window controls) to exit at any time. All views depend on ICMP raw sockets, so make sure `CAP_NET_RAW` is granted before launching the app.

The UI exposes dedicated views for:

- `Ping`: continuous probes with a `Stop` button, a live RTT/loss summary strip, and configurable TTL/timeout.
- `MultiPing`: batched targets with per-host aggregates that remain visible beneath the log of individual replies.
- `Traceroute`: hop discovery with optional reverse DNS lookup and per-probe RTT details once the run completes.
- `MTR`: rolling cycles that refresh hop statistics until stopped, mirroring the behaviour of classic `mtr`.

Tips:

- Switch between views through the left-hand navigation buttons without restarting an active session.
- Validation messages and permission errors surface as notifications at the bottom of the screen.
- When experimenting with rapid probes, increase the timeout if your network drops packets aggressively.

#### TUI preview

![Ping view](docs/ping_tui.png)

![MultiPing view](docs/multiping_tui.png)

![Traceroute view](docs/traceroute_tui.png)

![MTR view](docs/mtr_tui.png)

## Example Scripts

- `examples/ping.py` — shortest path to send repeated ICMP echo requests
- `examples/traceroute.py` — hop-by-hop discovery using the library API
- `icmpx/demo.py` — Textual UI bundling Ping, MultiPing, Traceroute, and MTR views (run it via `uv run icmpx` or `uvx icmpx`)
- `examples/mtr.py` — Rich-powered live table that mimics the `mtr` workflow

Feel free to copy these scripts as starting points for your own automation or integrate the `Client` directly inside existing services.

## Error Handling

If the interpreter cannot create a raw socket, `Client` raises `RawSocketPermissionError` with guidance on granting `CAP_NET_RAW`. Timeouts surface as `EchoResult.error == "timeout"` while other ICMP responses preserve their numeric type/code so you can present detailed diagnostics.

## Roadmap

- IPv6 probes and traceroutes
- Aggregated multiping support across multiple targets
- asyncio-compatible client implementation
- Additional examples and narrative documentation

Contributions and discussion are welcome — open an issue with your use case or ideas.
