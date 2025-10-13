"""Interactive Textual TUI for icmpx."""

from __future__ import annotations

import re
import time

from typing import Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Footer,
    Input,
    Label,
    Static,
)

try:  # pragma: no cover - runtime convenience for script usage
    from . import Icmp, traceroute
    from ._mtr import MtrResult
    from ._traceroute import TracerouteResult
except ImportError:  # pragma: no cover - fallback when run directly
    import pathlib
    import sys

    sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
    from icmpx import Icmp, traceroute
    from icmpx._mtr import MtrResult
    from icmpx._traceroute import TracerouteResult


def _reset_table(table: DataTable, columns: tuple[str, ...]) -> None:
    """Clear table contents while ensuring columns remain present."""

    table.clear()
    if not getattr(table, "columns", None):
        table.add_columns(*columns)


class PingView(Vertical):
    """Simple ping form and result table."""

    title = "Ping"
    results = reactive(tuple())

    def compose(self) -> ComposeResult:
        with Vertical(id="ping-form"):
            yield Label(" Target")
            yield Input(placeholder="8.8.8.8", id="ping-target", value="8.8.8.8")
            with Horizontal(id="ping-options"):
                with Vertical():
                    yield Label("TTL")
                    yield Input(placeholder="64", id="ping-ttl", compact=True)
                with Vertical():
                    yield Label("Timeout")
                    yield Input(placeholder="1.0", id="ping-timeout", compact=True)
                with Vertical():
                    yield Label("Count")
                    yield Input(placeholder="10", id="ping-count", compact=True)
            yield Button("Run Ping", id="ping-submit", flat=True)
        table = DataTable(id="ping-table")
        table.add_columns("Target", "Reply IP", "Sequence", "RTT (ms)", "Status")
        yield table

    @on(Button.Pressed, "#ping-submit")
    def run_ping(self) -> None:  # noqa: D401
        target = self.query_one("#ping-target", Input).value
        ttl = self.query_one("#ping-ttl", Input).value or "64"
        timeout = self.query_one("#ping-timeout", Input).value or "1.0"
        count = self.query_one("#ping-count", Input).value or "10"
        if not target:
            self.notify("Please enter a target address.")
            return
        # reset accumulated results so the table starts fresh for each run
        self.results = tuple()
        self.perform_ping(
            target,
            count=int(count),
            ttl=int(ttl),
            timeout=float(timeout),
        )

    @work(thread=True)
    def perform_ping(
        self, target: str, count: int = 10, ttl: int = 64, timeout: float = 1.0
    ) -> None:
        """Perform a series of pings to measure performance."""
        with Icmp() as icmp:
            for _ in range(count):
                result = icmp.ping(target, ttl=ttl, timeout=timeout)
                self.results = (*self.results, result)

    def watch_results(self, old_results: tuple, new_results: tuple) -> None:  # noqa: D401
        table = self.query_one("#ping-table", DataTable)
        if not new_results:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )
            return

        if not old_results:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )

        start = len(old_results)
        if start >= len(new_results):
            return

        for result in new_results[start:]:
            target = getattr(result.sent_packet, "destination", "-")
            if result.response:
                table.add_row(
                    target,
                    result.response.addr,
                    str(result.response.sequence),
                    f"{result.response.rtt:.2f}",
                    "reply",
                )
            elif result.error:
                table.add_row(target, "-", "-", "-", f"error: {result.error}")
            else:
                table.add_row(target, "-", "-", "-", "timeout")

        if new_results:
            table.move_cursor(row=len(new_results) - 1, scroll=True)


class MultiPingView(Vertical):
    """Form for running multiple echo requests across several targets."""

    title = "MultiPing"
    running = reactive(False)
    results = reactive(tuple())

    def __init__(self, *children, **kwargs) -> None:
        super().__init__(*children, **kwargs)
        self._stats: dict[str, dict[str, object]] = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="multiping-form"):
            yield Label(" Targets (comma or space separated)")
            yield Input(
                placeholder="8.8.8.8, 1.1.1.1",
                id="multiping-targets",
                value="8.8.8.8, 1.1.1.1",
            )
            with Horizontal(id="multiping-options"):
                with Vertical():
                    yield Label("Count")
                    yield Input(placeholder="4", id="multiping-count", value="4", compact=True)
                with Vertical():
                    yield Label("Interval (s)")
                    yield Input(
                        placeholder="1.0",
                        id="multiping-interval",
                        value="1.0",
                        compact=True,
                    )
                with Vertical():
                    yield Label("Timeout")
                    yield Input(
                        placeholder="1.0",
                        id="multiping-timeout",
                        compact=True,
                    )
                with Vertical():
                    yield Label("TTL")
                    yield Input(
                        placeholder="64",
                        id="multiping-ttl",
                        value="64",
                        compact=True,
                    )
            yield Button("Run MultiPing", id="multiping-run", flat=True)

        table = DataTable(id="multiping-table")
        table.add_columns(
            "Target",
            "Reply IP",
            "Sequence",
            "RTT (ms)",
            "Status",
        )
        yield table

        self._summary = Static(id="multiping-summary")
        yield self._summary

    @on(Button.Pressed, "#multiping-run")
    def run_multiping(self) -> None:  # noqa: D401
        if self.running:
            if self.app is not None:
                self.app.bell()
            return

        targets_raw = self.query_one("#multiping-targets", Input).value or ""
        targets = [
            part.strip()
            for part in re.split(r"[\s,]+", targets_raw)
            if part.strip()
        ]
        if not targets:
            self.notify("Please provide at least one target.")
            return

        count_value = self.query_one("#multiping-count", Input).value or "4"
        interval_value = self.query_one("#multiping-interval", Input).value or "1.0"
        timeout_value = self.query_one("#multiping-timeout", Input).value
        ttl_value = self.query_one("#multiping-ttl", Input).value or "64"

        self.running = True
        self.results = tuple()
        self._stats = {}
        self._summary.update("")
        table = self.query_one("#multiping-table", DataTable)
        _reset_table(
            table,
            ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
        )

        self.perform_multiping(
            targets,
            count_value,
            interval_value,
            timeout_value,
            ttl_value,
        )

    @work(thread=True)
    def perform_multiping(
        self,
        targets: list[str],
        count_value: str,
        interval_value: str,
        timeout_value: str,
        ttl_value: str,
    ) -> None:
        app = self.app
        if app is None:
            return

        try:
            count = max(1, int(count_value))
            interval = max(0.0, float(interval_value))
            timeout_opt = float(timeout_value) if timeout_value else None
            ttl = max(1, int(ttl_value))

            with Icmp() as icmp:
                for target_index, target in enumerate(targets):
                    for attempt in range(count):
                        result = icmp.ping(
                            target,
                            ttl=ttl,
                            timeout=timeout_opt,
                        )
                        app.call_from_thread(self._record_result, target, result)
                        is_last_probe = (
                            target_index == len(targets) - 1
                            and attempt == count - 1
                        )
                        if interval > 0 and not is_last_probe:
                            time.sleep(interval)
        except Exception as error:  # pragma: no cover - defensive
            app.call_from_thread(self._handle_worker_error, error)
        finally:
            app.call_from_thread(self._finish_worker)

    def _record_result(self, target: str, result: object) -> None:
        self.results = (*self.results, (target, result))
        self._accumulate_stats(target, result)
        self._update_summary()

    def _accumulate_stats(self, target: str, result: object) -> None:
        stats = self._stats.setdefault(
            target,
            {"sent": 0, "received": 0, "rtts": []},
        )
        stats["sent"] += 1
        response = getattr(result, "response", None)
        if response is not None:
            stats["received"] += 1
            stats["rtts"].append(response.rtt)

    def _update_summary(self) -> None:
        if not self._stats:
            self._summary.update("")
            return

        parts: list[str] = []
        for target, stats in self._stats.items():
            sent = stats["sent"]
            received = stats["received"]
            loss = sent - received
            loss_percent = (loss / sent) * 100 if sent else 0.0
            rtts: list[float] = stats["rtts"]
            min_rtt = f"{min(rtts):.2f} ms" if rtts else "n/a"
            avg_rtt = f"{(sum(rtts) / len(rtts)):.2f} ms" if rtts else "n/a"
            max_rtt = f"{max(rtts):.2f} ms" if rtts else "n/a"
            parts.append(
                f"{target}: sent={sent} recv={received} loss={loss_percent:.1f}% min={min_rtt} avg={avg_rtt} max={max_rtt}"
            )

        self._summary.update("\n".join(parts))

    def _handle_worker_error(self, error: Exception) -> None:
        if self.app is not None:
            self.app.bell()
        self.notify(f"Error: {error}")

    def _finish_worker(self) -> None:
        self.running = False

    def watch_results(
        self,
        old_results: tuple,
        new_results: tuple,
    ) -> None:  # noqa: D401
        table = self.query_one("#multiping-table", DataTable)
        if not new_results:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )
            return

        if not old_results:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )

        start = len(old_results)
        if start >= len(new_results):
            return

        for target, result in new_results[start:]:
            dest = target
            sent_packet = getattr(result, "sent_packet", None)
            if sent_packet is not None and getattr(sent_packet, "destination", None):
                dest = sent_packet.destination

            if getattr(result, "response", None) is not None:
                response = result.response
                table.add_row(
                    dest,
                    response.addr,
                    str(response.sequence),
                    f"{response.rtt:.2f}",
                    "reply",
                )
            elif getattr(result, "error", None):
                table.add_row(dest, "-", "-", "-", f"error: {result.error}")
            elif getattr(result, "received_packet", None) is not None:
                icmp_packet = result.received_packet.icmp_packet
                table.add_row(
                    dest,
                    result.received_packet.ip_header.src_addr,
                    str(icmp_packet.sequence),
                    "-",
                    f"type {icmp_packet.type}",
                )
            else:
                table.add_row(dest, "-", "-", "-", "timeout")

        table.move_cursor(row=len(new_results) - 1, scroll=True)


class TracerouteView(Vertical):
    """Form for running traceroute operations."""

    title = "Traceroute"
    running = reactive(False)

    def compose(self) -> ComposeResult:
        with Vertical(id="traceroute-form"):
            yield Label(" Target")
            yield Input(
                placeholder="8.8.8.8",
                id="traceroute-target",
                value="8.8.8.8",
            )
            with Horizontal(id="traceroute-options"):
                with Vertical():
                    yield Label("Max hops")
                    yield Input(
                        placeholder="30",
                        id="traceroute-hops",
                        value="30",
                        compact=True,
                    )
                with Vertical():
                    yield Label("Probes")
                    yield Input(
                        placeholder="3",
                        id="traceroute-probes",
                        value="3",
                        compact=True,
                    )
                with Vertical():
                    yield Label("Timeout")
                    yield Input(
                        placeholder="1.0",
                        id="traceroute-timeout",
                        compact=True,
                    )
            yield Button("Run Traceroute", id="traceroute-run", flat=True)

        table = DataTable(id="traceroute-table")
        table.add_columns("Hop", "Address", "Hostname", "RTTs", "Notes")
        yield table

    @on(Button.Pressed, "#traceroute-run")
    def run_traceroute(self) -> None:  # noqa: D401
        if self.running:
            self.app.bell()
            return

        target = self.query_one("#traceroute-target", Input).value or "8.8.8.8"
        hops_value = self.query_one("#traceroute-hops", Input).value or "30"
        probes_value = self.query_one("#traceroute-probes", Input).value or "3"
        timeout_value = self.query_one("#traceroute-timeout", Input).value

        self.running = True
        table = self.query_one("#traceroute-table", DataTable)
        _reset_table(table, ("Hop", "Address", "Hostname", "RTTs", "Notes"))

        self.perform_traceroute(
            target,
            hops_value,
            probes_value,
            timeout_value,
        )

    @work(thread=True)
    def perform_traceroute(
        self,
        target: str,
        hops_value: str,
        probes_value: str,
        timeout_value: str,
    ) -> None:
        app = self.app
        if app is None:
            return

        try:
            max_hops = max(1, int(hops_value))
            probes = max(1, int(probes_value))
            timeout_opt = float(timeout_value) if timeout_value else None
            with Icmp() as icmp:
                result = traceroute(
                    icmp,
                    target,
                    max_hops=max_hops,
                    probes=probes,
                    timeout=timeout_opt,
                    resolve_dns=True,
                )
        except Exception as error:  # pragma: no cover - defensive
            app.call_from_thread(self._handle_worker_error, error)
        else:
            app.call_from_thread(self.update_result, result)
        finally:
            app.call_from_thread(self._finish_worker)

    def _handle_worker_error(self, error: Exception) -> None:
        if self.app is not None:
            self.app.bell()
        self.notify(f"Error: {error}")

    def _finish_worker(self) -> None:
        self.running = False

    def update_result(self, result: object) -> None:  # noqa: D401
        table = self.query_one("#traceroute-table", DataTable)
        _reset_table(table, ("Hop", "Address", "Hostname", "RTTs", "Notes"))
        if not isinstance(result, TracerouteResult):
            return

        for hop in result.hops:
            addresses = {probe.address for probe in hop.probes if probe.address}
            hostnames = {probe.hostname for probe in hop.probes if probe.hostname}
            address_value = ", ".join(sorted(addresses)) if addresses else "?"
            hostname_value = ", ".join(sorted(hostnames)) if hostnames else "?"

            rtt_parts: list[str] = []
            notes: set[str] = set()
            for probe in hop.probes:
                if probe.rtt is not None:
                    rtt_parts.append(f"{probe.rtt:.2f}")
                else:
                    rtt_parts.append("timeout")
                if probe.reached_destination:
                    notes.add("dest")
                if probe.error:
                    notes.add(f"{probe.error}")

            table.add_row(
                str(hop.ttl),
                address_value,
                hostname_value,
                ", ".join(rtt_parts) if rtt_parts else "-",
                ", ".join(sorted(notes)) if notes else "",
            )

        if result.hops:
            table.move_cursor(row=len(result.hops) - 1, scroll=True)


class MtrView(Vertical):
    """Form for running MTR cycles."""

    title = "MTR"
    running = reactive(False)

    def __init__(self, *children, **kwargs) -> None:
        super().__init__(*children, **kwargs)
        self._should_stop = False
        self._mtr_stats: dict[tuple[str, str], dict[str, object]] = {}
        self._mtr_order: list[tuple[str, str]] = []
        self._resolved_target: Optional[str] = None
        self._cycles = 0

    def compose(self) -> ComposeResult:
        with Vertical(id="mtr-form"):
            yield Label(" Target")
            yield Input(placeholder="8.8.8.8", id="mtr-target", value="8.8.8.8")
            with Horizontal(id="mtr-options"):
                with Vertical():
                    yield Label("Max hops")
                    yield Input(
                        placeholder="30",
                        id="mtr-hops",
                        value="30",
                        compact=True,
                    )
                with Vertical():
                    yield Label("Timeout")
                    yield Input(
                        placeholder="1.0",
                        id="mtr-timeout",
                        compact=True,
                    )
            with Horizontal(id="mtr-actions"):
                yield Button("Run MTR", id="mtr-run", flat=True)
                yield Button("Stop", id="mtr-stop", flat=True, disabled=True)

        table = DataTable(id="mtr-table")
        table.add_columns(
            "Hop",
            "Address",
            "Hostname",
            "Loss%",
            "Sent",
            "Recv",
            "Min",
            "Avg",
            "Max",
        )
        yield table

        self._info = Static("Cycles: 0", id="mtr-info")
        yield self._info

    def _reset_state(self) -> None:
        self._should_stop = False
        self._mtr_stats = {}
        self._mtr_order = []
        self._resolved_target = None
        self._cycles = 0
        self._info.update("Cycles: 0")

    @on(Button.Pressed, "#mtr-run")
    def run_mtr(self) -> None:  # noqa: D401
        if self.running:
            self.app.bell()
            return

        target = self.query_one("#mtr-target", Input).value or "8.8.8.8"
        hops_value = self.query_one("#mtr-hops", Input).value or "30"
        timeout_value = self.query_one("#mtr-timeout", Input).value

        self.running = True
        self._reset_state()
        table = self.query_one("#mtr-table", DataTable)
        _reset_table(
            table,
            (
                "Hop",
                "Address",
                "Hostname",
                "Loss%",
                "Sent",
                "Recv",
                "Min",
                "Avg",
                "Max",
            ),
        )
        run_button = self.query_one("#mtr-run", Button)
        stop_button = self.query_one("#mtr-stop", Button)
        run_button.disabled = True
        stop_button.disabled = False

        self.perform_mtr(
            target,
            hops_value,
            timeout_value,
        )

    @on(Button.Pressed, "#mtr-stop")
    def stop_mtr(self) -> None:  # noqa: D401
        if not self.running:
            if self.app is not None:
                self.app.bell()
            return
        self._should_stop = True

    @work(thread=True)
    def perform_mtr(
        self,
        target: str,
        hops_value: str,
        timeout_value: str,
    ) -> None:
        app = self.app
        if app is None:
            return

        try:
            max_hops = max(1, int(hops_value))
            timeout_opt = float(timeout_value) if timeout_value else None
            with Icmp() as icmp:
                try:
                    resolved = icmp.resolve_destination(target)
                except RuntimeError as error:
                    app.call_from_thread(self._handle_worker_error, error)
                    return

                app.call_from_thread(self._set_resolved_target, resolved)

                dns_cache: dict[str, Optional[str]] = {}

                with icmp.use_timeout(timeout_opt):
                    while not self._should_stop:
                        destination_reached = False
                        for ttl in range(1, max_hops + 1):
                            if self._should_stop:
                                break

                            result = icmp.probe(resolved, ttl=ttl)

                            if result.error:
                                app.call_from_thread(
                                    self._handle_worker_error,
                                    RuntimeError(result.error),
                                )
                                destination_reached = True
                                break

                            address: Optional[str] = None
                            hostname: Optional[str] = None
                            rtt: Optional[float] = None

                            if result.received_packet is not None and result.sent_packet is not None:
                                address = result.received_packet.ip_header.src_addr
                                if address not in dns_cache:
                                    dns_cache[address] = (
                                        icmp.resolve_dns(address) if address else None
                                    )
                                hostname = dns_cache.get(address)

                                if result.response is not None:
                                    rtt = result.response.rtt
                                    if address == resolved:
                                        destination_reached = True
                                else:
                                    rtt = (
                                        result.received_packet.received_at
                                        - result.sent_packet.timestamp
                                    ) * 1000
                            app.call_from_thread(
                                self._register_mtr_sample,
                                ttl,
                                address,
                                hostname,
                                rtt,
                            )

                            if destination_reached:
                                break

                        app.call_from_thread(self._increment_cycle)
                        if self._should_stop:
                            break
                        time.sleep(1.0)

        except Exception as error:  # pragma: no cover - defensive
            app.call_from_thread(self._handle_worker_error, error)
        finally:
            app.call_from_thread(self._finish_worker)

    def _register_mtr_sample(
        self,
        ttl: int,
        address: Optional[str],
        hostname: Optional[str],
        rtt: Optional[float],
    ) -> None:
        addr = address or "?"
        host = hostname or "?"
        key = (addr, host)

        stats = self._mtr_stats.get(key)
        if stats is None:
            stats = {
                "ttls": set(),
                "sent": 0,
                "received": 0,
                "rtt_sum": 0.0,
                "rtt_count": 0,
                "rtt_min": None,
                "rtt_max": None,
            }
            self._mtr_stats[key] = stats
            self._mtr_order.append(key)

        stats["ttls"].add(ttl)
        stats["sent"] += 1
        if rtt is not None:
            stats["received"] += 1
            stats["rtt_sum"] += rtt
            stats["rtt_count"] += 1
            stats["rtt_min"] = rtt if stats["rtt_min"] is None else min(stats["rtt_min"], rtt)
            stats["rtt_max"] = rtt if stats["rtt_max"] is None else max(stats["rtt_max"], rtt)

        self._refresh_mtr_table()

    def _refresh_mtr_table(self) -> None:
        table = self.query_one("#mtr-table", DataTable)
        _reset_table(
            table,
            (
                "Hop",
                "Address",
                "Hostname",
                "Loss%",
                "Sent",
                "Recv",
                "Min",
                "Avg",
                "Max",
            ),
        )

        rows: list[tuple[str, str, str, float, int, int, Optional[float], Optional[float], Optional[float]]] = []
        for key in self._mtr_order:
            stats = self._mtr_stats[key]
            ttls = sorted(stats["ttls"])
            if not ttls:
                hop_label = "-"
            elif len(ttls) == 1:
                hop_label = str(ttls[0])
            else:
                hop_label = f"{ttls[0]}-{ttls[-1]}"

            sent = stats["sent"]
            received = stats["received"]
            loss_percent = ((sent - received) / sent) * 100 if sent else 0.0
            rtt_count = stats["rtt_count"]
            rtt_avg = stats["rtt_sum"] / rtt_count if rtt_count else None
            rtt_min = stats["rtt_min"]
            rtt_max = stats["rtt_max"]

            rows.append(
                (
                    hop_label,
                    key[0],
                    key[1],
                    loss_percent,
                    sent,
                    received,
                    rtt_min,
                    rtt_avg,
                    rtt_max,
                )
            )

        for hop_label, address, hostname, loss_percent, sent, received, rtt_min, rtt_avg, rtt_max in rows:
            table.add_row(
                hop_label,
                address,
                hostname,
                f"{loss_percent:.1f}",
                str(sent),
                str(received),
                f"{rtt_min:.2f}" if rtt_min is not None else "-",
                f"{rtt_avg:.2f}" if rtt_avg is not None else "-",
                f"{rtt_max:.2f}" if rtt_max is not None else "-",
            )

        if rows:
            table.move_cursor(row=len(rows) - 1, scroll=True)

    def _increment_cycle(self) -> None:
        self._cycles += 1
        resolved = f" ({self._resolved_target})" if self._resolved_target else ""
        self._info.update(f"Cycles: {self._cycles}{resolved}")

    def _set_resolved_target(self, resolved: str) -> None:
        self._resolved_target = resolved
        self._info.update(f"Cycles: {self._cycles} ({resolved})")

    def _handle_worker_error(self, error: Exception) -> None:
        if self.app is not None:
            self.app.bell()
        self.notify(f"Error: {error}")
        self._should_stop = True

    def _finish_worker(self) -> None:
        self.running = False
        run_button = self.query_one("#mtr-run", Button)
        stop_button = self.query_one("#mtr-stop", Button)
        run_button.disabled = False
        stop_button.disabled = True
        self._should_stop = False

    def update_result(self, result: object) -> None:  # noqa: D401
        if not isinstance(result, MtrResult):
            return

        self._reset_state()
        for hop in result.hops:
            address = hop.address or "?"
            hostname = hop.hostname or "?"
            key = (address, hostname)
            stats = self._mtr_stats.get(key)
            if stats is None:
                stats = {
                    "ttls": set(),
                    "sent": 0,
                    "received": 0,
                    "rtt_sum": 0.0,
                    "rtt_count": 0,
                    "rtt_min": None,
                    "rtt_max": None,
                }
                self._mtr_stats[key] = stats
                self._mtr_order.append(key)

            stats["ttls"].add(hop.ttl)
            stats["sent"] += hop.sent
            stats["received"] += hop.received

            if hop.rtt_min is not None:
                stats["rtt_min"] = (
                    hop.rtt_min
                    if stats["rtt_min"] is None
                    else min(stats["rtt_min"], hop.rtt_min)
                )
            if hop.rtt_max is not None:
                stats["rtt_max"] = (
                    hop.rtt_max
                    if stats["rtt_max"] is None
                    else max(stats["rtt_max"], hop.rtt_max)
                )
            if hop.rtt_avg is not None and hop.received:
                stats["rtt_sum"] += hop.rtt_avg * hop.received
                stats["rtt_count"] += hop.received

        self._cycles = result.cycles
        self._resolved_target = result.resolved
        self._refresh_mtr_table()
        self._info.update(f"Cycles: {self._cycles} ({self._resolved_target})")


class IcmpxApp(App):
    """Main Textual application hosting the icmpx tools."""

    CSS_PATH = "style.tcss"

    BINDINGS = [
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(id="main-container"):
            with Vertical(id="nav-container"):
                yield Button("Ping", id="ping", classes="nav-button", flat=True)
                yield Button(
                    "MultiPing", id="multiping", classes="nav-button", flat=True
                )
                yield Button(
                    "Traceroute", id="traceroute", classes="nav-button", flat=True
                )
                yield Button("MTR", id="mtr", classes="nav-button", flat=True)
            with ContentSwitcher(initial="ping", id="content-container"):
                yield PingView(id="ping")
                yield MultiPingView(id="multiping")
                yield TracerouteView(id="traceroute")
                yield MtrView(id="mtr")
        yield Footer()

    @on(Button.Pressed, ".nav-button")
    def on_nav_selected(self, event: Button.Pressed) -> None:  # noqa: D401
        view_id = event.button.id or "ping"
        self.query_one(ContentSwitcher).current = view_id


if __name__ == "__main__":
    app = IcmpxApp()
    app.run()
