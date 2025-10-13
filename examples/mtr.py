"""Minimal MTR clone using icmpx.Client and Rich."""

from __future__ import annotations

import argparse
import math
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box

from icmpx import Client, RawSocketPermissionError


console = Console()


def _format_ms(value: float | None) -> str:
    if value is None or not math.isfinite(value):
        return "-"
    return f"{value:.2f}"


def _build_table(
    host: str,
    resolved: str,
    stats: dict[int, dict[str, Any]],
    cycle: int,
    total_cycles: int,
) -> Table:
    title_suffix = f" ({resolved})" if resolved != host else ""
    caption = f"Cycle {cycle}/{total_cycles}" if cycle else "Collecting…"
    table = Table(
        title=f"MTR to {host}{title_suffix}",
        caption=caption,
        box=box.SQUARE,
        expand=True,
        )
    table.add_column("Hop", justify="right", style="cyan", no_wrap=True)
    table.add_column("Address", style="magenta")
    table.add_column("Hostname", style="green")
    table.add_column("Sent", justify="right", style="yellow")
    table.add_column("Recv", justify="right", style="yellow")
    table.add_column("Loss %", justify="right", style="red")
    table.add_column("Last", justify="right")
    table.add_column("Avg", justify="right")
    table.add_column("Best", justify="right")
    table.add_column("Worst", justify="right")

    for ttl in sorted(stats):
        data = stats[ttl]
        sent = data["sent"]
        recv = data["recv"]
        rtts: list[float] = data["rtts"]
        loss = ((sent - recv) / sent) * 100 if sent else 0.0
        avg = sum(rtts) / len(rtts) if rtts else None
        best = min(rtts) if rtts else None
        worst = max(rtts) if rtts else None

        table.add_row(
            str(ttl),
            data.get("addr") or "?",
            data.get("hostname") or "",
            str(sent),
            str(recv),
            f"{loss:.1f}",
            _format_ms(data.get("last")),
            _format_ms(avg),
            _format_ms(best),
            _format_ms(worst),
        )

    return table


def mtr(
    host: str,
    cycles: int = 5,
    max_hops: int = 30,
    timeout: float = 1.0,
    interval: float = 0.2,
    resolve_dns: bool = True,
) -> None:
    stats: dict[int, dict[str, Any]] = {}
    dns_cache: dict[str, str | None] = {}

    with Client(timeout=timeout, resolve_dns_default=resolve_dns) as client:
        resolved = host
        if not client.valid_ip(host):
            resolved = client.resolve_host(host)

        max_active_ttl = max_hops
        with Live(
            _build_table(host, resolved, stats, 0, cycles),
            console=console,
        ) as live:
            for cycle in range(1, cycles + 1):
                destination_reached = False
                for ttl in range(1, max_active_ttl + 1):
                    entry = stats.setdefault(
                        ttl,
                        {
                            "addr": None,
                            "hostname": None,
                            "sent": 0,
                            "recv": 0,
                            "rtts": [],
                            "last": None,
                        },
                    )

                    entry["sent"] += 1
                    result = client.probe(resolved, ttl=ttl, timeout=timeout)

                    if result.reply.received_packet is not None:
                        pkt = result.reply.received_packet
                        addr = pkt.ip_header.src_addr
                        if entry["addr"] is None:
                            entry["addr"] = addr
                        if resolve_dns:
                            hostname = dns_cache.get(addr)
                            if hostname is None:
                                hostname = client.reverse_dns(addr)
                                dns_cache[addr] = hostname
                            entry["hostname"] = hostname

                        entry["recv"] += 1

                        rtt = result.reply.rtt
                        entry["last"] = rtt if math.isfinite(rtt) else None
                        if math.isfinite(rtt):
                            entry["rtts"].append(rtt)

                        if result.error is None and addr == resolved:
                            destination_reached = True
                    else:
                        entry["last"] = None

                    live.update(_build_table(host, resolved, stats, cycle, cycles))

                    if destination_reached:
                        max_active_ttl = min(max_active_ttl, ttl)
                        break

                    if interval:
                        time.sleep(interval)

                live.update(_build_table(host, resolved, stats, cycle, cycles))
                if destination_reached and interval:
                    time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an interactive MTR loop")
    parser.add_argument("host", nargs="?", default="8.8.8.8", help="target host")
    parser.add_argument("-c", "--cycles", type=int, default=5, help="number of cycles")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="max hop TTL")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="probe timeout")
    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=0.2,
        help="delay between probes in seconds",
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="skip reverse DNS lookups",
    )

    args = parser.parse_args()

    try:
        mtr(
            host=args.host,
            cycles=max(1, args.cycles),
            max_hops=max(1, args.max_hops),
            timeout=max(0.1, args.timeout),
            interval=max(0.0, args.interval),
            resolve_dns=not args.no_dns,
        )
    except RawSocketPermissionError as exc:
        console.print(f"[red]{exc}[/red]")
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    