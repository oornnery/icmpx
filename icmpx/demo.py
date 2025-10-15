"""Interactive Textual TUI for icmpx using the Client API."""

from __future__ import annotations

import math
import re
import time
from pathlib import Path
from typing import Any, Optional

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

from icmpx import Client, EchoResult, RawSocketPermissionError, TracerouteResult


ICMP_ECHO_REPLY = 0

__all__ = ["IcmpxApp", "run"]


def _format_ms(value: float | None) -> str:
    if value is None or not math.isfinite(value):
        return "-"
    return f"{value:.2f}"


def _reset_table(table: DataTable, columns: tuple[str, ...]) -> None:
    table.clear()
    if not getattr(table, "columns", None):
        table.add_columns(*columns)


class PingView(Vertical):
    """Simple ping form and result table."""

    title = "Ping"
    results = reactive(tuple())
    running = reactive(False)

    def __init__(self, *children: Any, **kwargs: Any) -> None:
        super().__init__(*children, **kwargs)
        self._should_stop = False
        self._stats = {"sent": 0, "recv": 0, "rtts": []}
        self._summary_widget: Optional[Static] = None

    def compose(self) -> ComposeResult:
        with Vertical(id="ping-form"):
            yield Label(" Target")
            yield Input(placeholder="8.8.8.8", id="ping-target", value="8.8.8.8")
            with Horizontal(id="ping-options"):
                with Vertical():
                    yield Label("Interval (s)")
                    yield Input(
                        placeholder="1.0",
                        id="ping-interval",
                        value="0.2",
                        compact=True,
                    )
                with Vertical():
                    yield Label("TTL")
                    yield Input(placeholder="64", id="ping-ttl", compact=True)
                with Vertical():
                    yield Label("Timeout")
                    yield Input(placeholder="1.0", id="ping-timeout", compact=True)
            with Horizontal(id="ping-actions"):
                yield Button("Run", id="ping-submit", flat=True)
                yield Button("Stop", id="ping-stop", flat=True, disabled=True)
        with Vertical(id="ping-results"):
            table = DataTable(id="ping-table")
            table.add_columns("Target", "Reply IP", "Sequence", "RTT (ms)", "Status")
            yield table
            self._summary_widget = Static(self._format_summary(), id="ping-summary")
            yield self._summary_widget

    @on(Button.Pressed, "#ping-submit")
    def run_ping(self) -> None:  # noqa: D401
        if self.running:
            if self.app is not None:
                self.app.bell()
            return

        interval = self.query_one("#ping-interval", Input).value or "1.0"
        target = self.query_one("#ping-target", Input).value
        ttl_value = self.query_one("#ping-ttl", Input).value or "64"
        timeout_value = self.query_one("#ping-timeout", Input).value or "1.0"

        if not target:
            self.notify("Please enter a target address.")
            return

        try:
            interval = max(0.0, float(interval))
            ttl = max(1, int(ttl_value))
            timeout = max(0.1, float(timeout_value))
        except ValueError:
            self.notify("Invalid numeric value.")
            return

        self.results = tuple()
        self._reset_stats()
        self._update_summary()

        self.running = True
        self._should_stop = False
        run_button = self.query_one("#ping-submit", Button)
        stop_button = self.query_one("#ping-stop", Button)
        run_button.disabled = True
        stop_button.disabled = False

        self.perform_ping(target, interval=interval, ttl=ttl, timeout=timeout)

    @on(Button.Pressed, "#ping-stop")
    def stop_ping(self) -> None:  # noqa: D401
        if not self.running:
            if self.app is not None:
                self.app.bell()
            return
        self._should_stop = True

    @work(thread=True)
    def perform_ping(
        self,
        target: str,
        interval: float = 0.2,
        timeout: float = 1.0,
        ttl: int = 64,
    ) -> None:
        app = self.app
        if app is None:
            return

        try:
            with Client(timeout=timeout, default_ttl=ttl) as client:
                while not self._should_stop:
                    result = client.probe(target, ttl=ttl, timeout=timeout)
                    app.call_from_thread(self._append_result, result)
                    if self._should_stop:
                        break
                    time.sleep(interval)
        except RawSocketPermissionError as exc:
            app.call_from_thread(self._show_error, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            app.call_from_thread(self._show_error, str(exc))
        finally:
            if app is not None:
                app.call_from_thread(self._finish_worker)

    def _append_result(self, result: EchoResult) -> None:
        self._stats["sent"] += 1
        reply_packet = result.reply.received_packet
        rtt_value = result.reply.rtt
        if (
            result.error is None
            and reply_packet
            and rtt_value is not None
            and math.isfinite(rtt_value)
        ):
            self._stats["recv"] += 1
            self._stats["rtts"].append(rtt_value)
        self.results = (*self.results, result)
        self._update_summary()

    def _show_error(self, message: str) -> None:
        if self.app is not None:
            self.app.bell()
        self.notify(message)

    def watch_results(self, old: tuple, new: tuple) -> None:  # noqa: D401
        table = self.query_one("#ping-table", DataTable)
        if not new:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )
            return

        if not old:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )

        start = len(old)
        for result in new[start:]:
            request = result.request
            reply_packet = result.reply.received_packet
            target = request.addr
            if reply_packet is not None:
                reply_ip = reply_packet.ip_header.src_addr
                sequence = str(reply_packet.icmp_packet.sequence)
                rtt_display = _format_ms(result.reply.rtt)
                status = "reply" if result.error is None else result.error
            else:
                reply_ip = "-"
                sequence = "-"
                rtt_display = "-"
                status = result.error or "timeout"

            table.add_row(target, reply_ip, sequence, rtt_display, status)

        if new:
            table.move_cursor(row=len(new) - 1, scroll=True)

    def _finish_worker(self) -> None:
        self.running = False
        self._should_stop = False
        run_button = self.query_one("#ping-submit", Button)
        stop_button = self.query_one("#ping-stop", Button)
        run_button.disabled = False
        stop_button.disabled = True

    def _reset_stats(self) -> None:
        self._stats = {"sent": 0, "recv": 0, "rtts": []}

    def _format_summary(self) -> str:
        sent = self._stats["sent"]
        recv = self._stats["recv"]
        loss = ((sent - recv) / sent) * 100 if sent else 0.0
        rtts = self._stats["rtts"]
        if rtts:
            min_rtt = f"{min(rtts):.2f} ms"
            avg_rtt = f"{(sum(rtts) / len(rtts)):.2f} ms"
            max_rtt = f"{max(rtts):.2f} ms"
        else:
            min_rtt = avg_rtt = max_rtt = "n/a"
        return f"sent={sent} recv={recv} loss={loss:.1f}% min={min_rtt} avg={avg_rtt} max={max_rtt}"

    def _update_summary(self) -> None:
        if self._summary_widget is None:
            return
        self._summary_widget.update(self._format_summary())


class MultiPingView(Vertical):
    """Form for running multiple echo requests across several targets."""

    title = "MultiPing"
    running = reactive(False)
    results = reactive(tuple())

    def __init__(self, *children: Any, **kwargs: Any) -> None:
        super().__init__(*children, **kwargs)
        self._stats: dict[str, dict[str, Any]] = {}

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
                    yield Label("Interval (s)")
                    yield Input(
                        placeholder="1.0",
                        id="multiping-interval",
                        value="0.2",
                        compact=True,
                    )
                with Vertical():
                    yield Label("Timeout")
                    yield Input(
                        placeholder="1.0",
                        id="multiping-timeout",
                        value="1.0",
                        compact=True,
                    )
                with Vertical():
                    yield Label("TTL")
                    yield Input(
                        placeholder="64", id="multiping-ttl", value="64", compact=True
                    )
            with Horizontal(id="multiping-actions"):
                yield Button("Run", id="multiping-submit", flat=True)
                yield Button("Stop", id="multiping-stop", flat=True, disabled=True)
        with Vertical(id="multiping-results"):
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

    @on(Button.Pressed, "#multiping-submit")
    def run_multiping(self) -> None:  # noqa: D401
        if self.running:
            if self.app is not None:
                self.app.bell()
            return

        targets_raw = self.query_one("#multiping-targets", Input).value or ""
        targets = [
            part.strip() for part in re.split(r"[\s,]+", targets_raw) if part.strip()
        ]
        if not targets:
            self.notify("Please provide at least one target.")
            return

        interval_value = self.query_one("#multiping-interval", Input).value or "1.0"
        timeout_value = self.query_one("#multiping-timeout", Input).value or "1.0"
        ttl_value = self.query_one("#multiping-ttl", Input).value or "64"

        try:
            interval = max(0.0, float(interval_value))
            timeout = max(0.1, float(timeout_value))
            ttl = max(1, int(ttl_value))
        except ValueError:
            self.notify("Invalid numeric value.")
            return

        self.running = True
        self._should_stop = False
        self.results = tuple()
        run_button = self.query_one("#multiping-submit", Button)
        stop_button = self.query_one("#multiping-stop", Button)
        run_button.disabled = True
        stop_button.disabled = False

        self._stats = {}
        self._summary.update("")
        table = self.query_one("#multiping-table", DataTable)
        _reset_table(
            table,
            ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
        )

        self.perform_multiping(targets, interval, timeout, ttl)


    @on(Button.Pressed, "#multiping-stop")
    def stop_ping(self) -> None:  # noqa: D401
        if not self.running:
            if self.app is not None:
                self.app.bell()
            return
        self._should_stop = True

    @work(thread=True)
    def perform_multiping(
        self,
        targets: list[str],
        interval: float = 0.2,
        timeout: float = 1.0,
        ttl: int = 64,
    ) -> None:
        app = self.app
        if app is None:
            return

        try:
            with Client(timeout=timeout, default_ttl=ttl) as client:
                while not self._should_stop:
                    for target_index, target in enumerate(targets):
                        result = client.probe(target, ttl=ttl, timeout=timeout)
                        app.call_from_thread(self._record_result, target, result)
                        if self._should_stop:
                            break
                        if interval > 0:
                            time.sleep(interval)
        except RawSocketPermissionError as exc:
            app.call_from_thread(self._handle_worker_error, exc)
        except Exception as exc:  # pragma: no cover - defensive
            app.call_from_thread(self._handle_worker_error, exc)
        finally:
            app.call_from_thread(self._finish_worker)

    def _record_result(self, target: str, result: EchoResult) -> None:
        self.results = (*self.results, (target, result))
        self._accumulate_stats(target, result)
        self._update_summary()

    def _accumulate_stats(self, target: str, result: EchoResult) -> None:
        stats = self._stats.setdefault(target, {"sent": 0, "received": 0, "rtts": []})
        stats["sent"] += 1
        reply_packet = result.reply.received_packet
        if result.error is None and reply_packet and math.isfinite(result.reply.rtt):
            stats["received"] += 1
            stats["rtts"].append(result.reply.rtt)

    def _update_summary(self) -> None:
        if not self._stats:
            self._summary.update("")
            return

        lines: list[str] = []
        for target, stats in self._stats.items():
            sent = stats["sent"]
            received = stats["received"]
            loss_percent = ((sent - received) / sent) * 100 if sent else 0.0
            rtts: list[float] = stats["rtts"]
            min_rtt = f"{min(rtts):.2f} ms" if rtts else "n/a"
            avg_rtt = f"{(sum(rtts) / len(rtts)):.2f} ms" if rtts else "n/a"
            max_rtt = f"{max(rtts):.2f} ms" if rtts else "n/a"
            lines.append(
                f"{target}: sent={sent} recv={received} loss={loss_percent:.1f}% min={min_rtt} avg={avg_rtt} max={max_rtt}"
            )

        self._summary.update("\n".join(lines))

    def _handle_worker_error(self, error: Exception) -> None:
        if self.app is not None:
            self.app.bell()
        self.notify(f"Error: {error}")

    def _finish_worker(self) -> None:
        self.running = False
        self._should_stop = False
        run_button = self.query_one("#multiping-submit", Button)
        stop_button = self.query_one("#multiping-stop", Button)
        run_button.disabled = False
        stop_button.disabled = True

    def watch_results(self, old: tuple, new: tuple) -> None:  # noqa: D401
        table = self.query_one("#multiping-table", DataTable)
        if not new:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )
            return

        if not old:
            _reset_table(
                table,
                ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
            )

        start = len(old)
        for target, result in new[start:]:
            reply_packet = result.reply.received_packet
            reply_ip = reply_packet.ip_header.src_addr if reply_packet else "-"
            sequence = str(reply_packet.icmp_packet.sequence) if reply_packet else "-"
            rtt_display = _format_ms(result.reply.rtt if reply_packet else None)
            status = "reply" if reply_packet else (result.error or "timeout")
            table.add_row(target, reply_ip, sequence, rtt_display, status)

        table.move_cursor(row=len(new) - 1, scroll=True)


class TracerouteView(Vertical):
    """Form for running traceroute operations."""

    title = "Traceroute"
    running = reactive(False)

    def compose(self) -> ComposeResult:
        with Vertical(id="traceroute-form"):
            yield Label(" Target")
            yield Input(placeholder="8.8.8.8", id="traceroute-target", value="8.8.8.8")
            with Horizontal(id="traceroute-options"):
                with Vertical():
                    yield Label("Max hops")
                    yield Input(
                        placeholder="30", id="traceroute-hops", value="30", compact=True
                    )
                with Vertical():
                    yield Label("Probes")
                    yield Input(
                        placeholder="3", id="traceroute-probes", value="3", compact=True
                    )
                with Vertical():
                    yield Label("Timeout")
                    yield Input(
                        placeholder="1.0",
                        id="traceroute-timeout",
                        value="1.0",
                        compact=True,
                    )
            yield Button("Run", id="traceroute-submit", flat=True)

        table = DataTable(id="traceroute-table")
        table.add_columns("Hop", "Address", "Hostname", "RTTs", "Notes")
        yield table

    @on(Button.Pressed, "#traceroute-submit")
    def run_traceroute(self) -> None:  # noqa: D401
        if self.running:
            self.app.bell()
            return

        target = self.query_one("#traceroute-target", Input).value or "8.8.8.8"
        hops_value = self.query_one("#traceroute-hops", Input).value or "30"
        probes_value = self.query_one("#traceroute-probes", Input).value or "3"
        timeout_value = self.query_one("#traceroute-timeout", Input).value or "1.0"

        try:
            max_hops = max(1, int(hops_value))
            probes = max(1, int(probes_value))
            timeout = max(0.1, float(timeout_value))
        except ValueError:
            self.notify("Invalid numeric value.")
            return

        self.running = True
        table = self.query_one("#traceroute-table", DataTable)
        _reset_table(table, ("Hop", "Address", "Hostname", "RTTs", "Notes"))
        self.perform_traceroute(target, max_hops, probes, timeout)

    @work(thread=True)
    def perform_traceroute(
        self,
        target: str,
        max_hops: int,
        probes: int,
        timeout: float,
    ) -> None:
        app = self.app
        if app is None:
            return

        try:
            with Client(timeout=timeout, resolve_dns_default=True) as client:
                result = client.traceroute(
                    target,
                    max_hops=max_hops,
                    probes=probes,
                    timeout=timeout,
                    resolve_dns=True,
                )
        except RawSocketPermissionError as exc:
            app.call_from_thread(self._handle_worker_error, exc)
        except Exception as exc:  # pragma: no cover - defensive
            app.call_from_thread(self._handle_worker_error, exc)
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
            address_value = hop.addr or "?"
            hostname_value = hop.hostname or "?"

            rtt_parts: list[str] = []
            notes: set[str] = set()
            for probe in hop.probes:
                if probe.received_packet is None:
                    rtt_parts.append("timeout")
                else:
                    rtt_parts.append(_format_ms(probe.rtt))
                    pkt = probe.received_packet.icmp_packet
                    if pkt.type != ICMP_ECHO_REPLY:
                        notes.add(f"type={pkt.type} code={pkt.code}")

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

    def __init__(self, *children: Any, **kwargs: Any) -> None:
        super().__init__(*children, **kwargs)
        self._should_stop = False
        self._stats: dict[int, dict[str, Any]] = {}
        self._resolved_target: Optional[str] = None
        self._cycles = 0

    def compose(self) -> ComposeResult:
        with Vertical(id="mtr-form"):
            yield Label(" Target")
            yield Input(placeholder="8.8.8.8", id="mtr-target", value="8.8.8.8")
            with Horizontal(id="mtr-options"):
                with Vertical():
                    yield Label("Interval (s)")
                    yield Input(
                        placeholder="1.0",
                        id="mtr-interval",
                        value="0.2",
                        compact=True,
                    )
                with Vertical():
                    yield Label("Max hops")
                    yield Input(
                        placeholder="30", id="mtr-hops", value="30", compact=True
                    )
                with Vertical():
                    yield Label("Timeout")
                    yield Input(
                        placeholder="1.0", id="mtr-timeout", value="1.0", compact=True
                    )
            with Horizontal(id="mtr-actions"):
                yield Button("Run", id="mtr-submit", flat=True)
                yield Button("Stop", id="mtr-stop", flat=True, disabled=True)
        with Vertical(id="mtr-results"):
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

            self._info = Static("Cycles: 0", id="mtr-summary")
            yield self._info

    def _reset_state(self) -> None:
        self._should_stop = False
        self._stats = {}
        self._resolved_target = None
        self._cycles = 0
        self._info.update("Cycles: 0")

    @on(Button.Pressed, "#mtr-submit")
    def run_mtr(self) -> None:  # noqa: D401
        if self.running:
            self.app.bell()
            return

        interval_value = self.query_one("#mtr-interval", Input).value or "1.0"
        target = self.query_one("#mtr-target", Input).value or "8.8.8.8"
        hops_value = self.query_one("#mtr-hops", Input).value or "30"
        timeout_value = self.query_one("#mtr-timeout", Input).value or "1.0"

        try:
            interval = max(0.0, float(interval_value))
            max_hops = max(1, int(hops_value))
            timeout = max(0.1, float(timeout_value))
        except ValueError:
            self.notify("Invalid numeric value.")
            return

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
        run_button = self.query_one("#mtr-submit", Button)
        stop_button = self.query_one("#mtr-stop", Button)
        run_button.disabled = True
        stop_button.disabled = False

        self.perform_mtr(target=target, max_hops=max_hops, timeout=timeout, interval=interval)

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
        max_hops: int = 30,
        timeout: float = 1.0,
        interval: float = 0.2,
    ) -> None:
        app = self.app
        if app is None:
            return

        try:
            with Client(timeout=timeout, resolve_dns_default=True) as client:
                resolved = (
                    target if client.valid_ip(target) else client.resolve_host(target)
                )
                app.call_from_thread(self._set_resolved_target, resolved)

                dns_cache: dict[str, Optional[str]] = {}
                active_hops = max_hops

                while not self._should_stop:
                    destination_reached = False
                    for ttl in range(1, active_hops + 1):
                        if self._should_stop:
                            break

                        result = client.probe(resolved, ttl=ttl, timeout=timeout)
                        reply_packet = result.reply.received_packet

                        addr: Optional[str] = None
                        host: Optional[str] = None
                        rtt: Optional[float] = None

                        if reply_packet is not None:
                            addr = reply_packet.ip_header.src_addr
                            if addr not in dns_cache:
                                dns_cache[addr] = client.reverse_dns(addr)
                            host = dns_cache.get(addr)

                            rtt = (
                                result.reply.rtt
                                if math.isfinite(result.reply.rtt)
                                else None
                            )
                            if result.error is None and addr == resolved:
                                destination_reached = True
                        elif result.error not in (None, "timeout"):
                            app.call_from_thread(
                                self._handle_worker_error, RuntimeError(result.error)
                            )
                            destination_reached = True

                        app.call_from_thread(
                            self._register_sample, ttl, addr, host, rtt
                        )

                        if destination_reached:
                            active_hops = min(active_hops, ttl)
                            break

                    app.call_from_thread(self._increment_cycle)
                    if self._should_stop:
                        break
                    time.sleep(interval)

        except RawSocketPermissionError as exc:
            app.call_from_thread(self._handle_worker_error, exc)
        except Exception as exc:  # pragma: no cover - defensive
            app.call_from_thread(self._handle_worker_error, exc)
        finally:
            app.call_from_thread(self._finish_worker)

    def _register_sample(
        self,
        ttl: int,
        address: Optional[str],
        hostname: Optional[str],
        rtt: Optional[float],
    ) -> None:
        entry = self._stats.setdefault(
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
        if address and entry["addr"] is None:
            entry["addr"] = address
        if hostname and entry["hostname"] is None:
            entry["hostname"] = hostname

        entry["last"] = rtt
        if rtt is not None:
            entry["recv"] += 1
            entry["rtts"].append(rtt)

        self._refresh_table()

    def _refresh_table(self) -> None:
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

        for ttl in sorted(self._stats):
            data = self._stats[ttl]
            sent = data["sent"]
            recv = data["recv"]
            rtts: list[float] = data["rtts"]
            loss_percent = ((sent - recv) / sent) * 100 if sent else 0.0
            min_rtt = min(rtts) if rtts else None
            avg_rtt = (sum(rtts) / len(rtts)) if rtts else None
            max_rtt = max(rtts) if rtts else None

            table.add_row(
                str(ttl),
                data.get("addr") or "?",
                data.get("hostname") or "",
                f"{loss_percent:.1f}",
                str(sent),
                str(recv),
                _format_ms(min_rtt),
                _format_ms(avg_rtt),
                _format_ms(max_rtt),
            )

        if self._stats:
            table.move_cursor(row=len(self._stats) - 1, scroll=True)

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
        run_button = self.query_one("#mtr-submit", Button)
        stop_button = self.query_one("#mtr-stop", Button)
        run_button.disabled = False
        stop_button.disabled = True
        self._should_stop = False


class IcmpxApp(App):
    """Main Textual application hosting the icmpx tools."""

    CSS_PATH = Path(__file__).with_name("style.tcss")

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


def run() -> None:
    """Launch the icmpx Textual UI."""

    app = IcmpxApp()
    app.run()


if __name__ == "__main__":
    run()
