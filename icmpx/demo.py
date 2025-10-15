"""Interactive Textual TUI for icmpx using the AsyncClient API."""

from __future__ import annotations

import asyncio
import math
import re
import secrets
from collections import Counter
from pathlib import Path
from typing import Any, Optional
from threading import get_ident

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

from icmpx import AsyncClient, EchoResult, RawSocketPermissionError, TracerouteResult


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


def _new_identifier() -> int:
    return secrets.randbelow(0x10000)


class PingView(Vertical):
    """Simple ping form and result table."""

    FOCUS = "#ping-target"
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
                    yield Label("TTL")
                    yield Input(placeholder="64", id="ping-ttl", compact=True)
                with Vertical():
                    yield Label("Timeout")
                    yield Input(placeholder="1.0", id="ping-timeout", compact=True)
                with Vertical():
                    yield Label("Interval (s)")
                    yield Input(
                        placeholder="0.2",
                        id="ping-interval",
                        value="0.2",
                        compact=True,
                    )
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

        target = self.query_one("#ping-target", Input).value
        ttl_value = self.query_one("#ping-ttl", Input).value or "64"
        timeout_value = self.query_one("#ping-timeout", Input).value or "1.0"
        interval_value = self.query_one("#ping-interval", Input).value or "0.2"

        if not target:
            self.notify("Please enter a target address.")
            return

        try:
            ttl = max(1, int(ttl_value))
            timeout = max(0.1, float(timeout_value))
            interval = max(0.0, float(interval_value))
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

        self.perform_ping(target, ttl=ttl, timeout=timeout, interval=interval)

    @on(Button.Pressed, "#ping-stop")
    def stop_ping(self) -> None:  # noqa: D401
        if not self.running:
            if self.app is not None:
                self.app.bell()
            return
        self._should_stop = True

    @work(exclusive=True)
    async def perform_ping(
        self,
        target: str,
        ttl: int = 64,
        timeout: float = 1.0,
        interval: float = 0.2,
    ) -> None:
        try:
            async with AsyncClient(
                timeout=timeout,
                default_ttl=ttl,
                identifier=_new_identifier(),
            ) as client:
                while not self._should_stop:
                    result = await client.probe(target, ttl=ttl, timeout=timeout)
                    self._append_result(result)
                    if self._should_stop:
                        break
                    await asyncio.sleep(interval)
        except RawSocketPermissionError as exc:
            self._show_error(str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            self._show_error(str(exc))
        finally:
            self._finish_worker()

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
        self._should_stop = False

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
                        placeholder="0.2",
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
                yield Button("Run", id="multiping-run", flat=True)
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

    @on(Button.Pressed, "#multiping-run")
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

        interval_value = self.query_one("#multiping-interval", Input).value or "0.2"
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
        self._stats = {}
        self._summary.update("")
        table = self.query_one("#multiping-table", DataTable)
        _reset_table(
            table,
            ("Target", "Reply IP", "Sequence", "RTT (ms)", "Status"),
        )
        run_button = self.query_one("#multiping-run", Button)
        stop_button = self.query_one("#multiping-stop", Button)
        run_button.disabled = True
        stop_button.disabled = False

        self.perform_multiping(targets, interval, timeout, ttl)

    @work(exclusive=True)
    async def perform_multiping(
        self,
        targets: list[str],
        interval: float,
        timeout: float,
        ttl: int,
    ) -> None:
        app = self.app

        def dispatch(callback, *args: Any) -> None:
            if app is not None and getattr(app, "_thread_id", None) != get_ident():
                app.call_from_thread(callback, *args)
            else:
                callback(*args)

        clients: dict[str, AsyncClient] = {}
        try:
            # Keep a dedicated AsyncClient per target so ICMP sequence numbers increment.
            for target in targets:
                try:
                    client = AsyncClient(
                        timeout=timeout,
                        default_ttl=ttl,
                        identifier=_new_identifier(),
                    )
                    await client.__aenter__()
                except RawSocketPermissionError as exc:
                    dispatch(self._handle_worker_error, exc)
                    self._should_stop = True
                    return
                except Exception as exc:  # pragma: no cover - defensive
                    dispatch(self._handle_worker_error, exc)
                    self._should_stop = True
                    return
                clients[target] = client

            while not self._should_stop:
                probes = await asyncio.gather(
                    *[
                        self._probe_once(clients[target], target, ttl, timeout)
                        for target in targets
                    ],
                    return_exceptions=True,
                )

                for target, outcome in zip(targets, probes):
                    if isinstance(outcome, RawSocketPermissionError):
                        dispatch(self._handle_worker_error, outcome)
                        self._should_stop = True
                        continue
                    if isinstance(outcome, Exception):
                        dispatch(self._handle_worker_error, outcome)
                        continue

                    dispatch(self._record_result, target, outcome)

                if self._should_stop:
                    break
                if interval > 0:
                    await asyncio.sleep(interval)
        finally:
            await asyncio.gather(
                *[
                    client.__aexit__(None, None, None)
                    for client in clients.values()
                ],
                return_exceptions=True,
            )
            dispatch(self._finish_worker)

    async def _probe_once(
        self,
        client: AsyncClient,
        target: str,
        ttl: int,
        timeout: float,
    ) -> EchoResult:
        return await client.probe(target, ttl=ttl, timeout=timeout)

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
        run_button = self.query_one("#multiping-run", Button)
        stop_button = self.query_one("#multiping-stop", Button)
        run_button.disabled = False
        stop_button.disabled = True

    @on(Button.Pressed, "#multiping-stop")
    def stop_multiping(self) -> None:  # noqa: D401
        if not self.running:
            if self.app is not None:
                self.app.bell()
            return
        self._should_stop = True

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
            yield Button("Run", id="traceroute-run", flat=True)

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

    @work(exclusive=True)
    async def perform_traceroute(
        self,
        target: str,
        max_hops: int,
        probes: int,
        timeout: float,
    ) -> None:
        try:
            async with AsyncClient(
                timeout=timeout,
                resolve_dns_default=True,
                identifier=_new_identifier(),
            ) as client:
                result = await client.traceroute(
                    target,
                    max_hops=max_hops,
                    probes=probes,
                    timeout=timeout,
                    resolve_dns=True,
                )
        except RawSocketPermissionError as exc:
            self._handle_worker_error(exc)
        except Exception as exc:  # pragma: no cover - defensive
            self._handle_worker_error(exc)
        else:
            self.update_result(result)
        finally:
            self._finish_worker()

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
            rtt_parts: list[str] = []
            notes: set[str] = set()
            addresses: list[str] = []
            for probe in hop.probes:
                if probe.received_packet is None:
                    rtt_parts.append("timeout")
                else:
                    reply_packet = probe.received_packet
                    rtt_parts.append(_format_ms(probe.rtt))
                    addresses.append(reply_packet.ip_header.src_addr)
                    pkt = reply_packet.icmp_packet
                    if pkt.type != ICMP_ECHO_REPLY:
                        notes.add(f"type={pkt.type} code={pkt.code}")

            address_value = "?"
            if addresses:
                unique_addresses = list(dict.fromkeys(addresses))
                address_value = ", ".join(unique_addresses)

            hostname_value = hop.hostname or "?"

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
        self._hop_ttls: list[int] = []
        self._route_info: dict[int, dict[str, Optional[str]]] = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="mtr-form"):
            yield Label(" Target")
            yield Input(placeholder="8.8.8.8", id="mtr-target", value="8.8.8.8")
            with Horizontal(id="mtr-options"):
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
                with Vertical():
                    yield Label("Interval (s)")
                    yield Input(
                        placeholder="0.2",
                        id="mtr-interval",
                        value="0.2",
                        compact=True,
                    )
            with Horizontal(id="mtr-actions"):
                yield Button("Run", id="mtr-run", flat=True)
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
        self._hop_ttls = []
        self._route_info = {}

    @on(Button.Pressed, "#mtr-run")
    def run_mtr(self) -> None:  # noqa: D401
        if self.running:
            self.app.bell()
            return

        target = self.query_one("#mtr-target", Input).value or "8.8.8.8"
        hops_value = self.query_one("#mtr-hops", Input).value or "30"
        timeout_value = self.query_one("#mtr-timeout", Input).value or "1.0"
        interval_value = self.query_one("#mtr-interval", Input).value or "0.2"

        try:
            max_hops = max(1, int(hops_value))
            timeout = max(0.1, float(timeout_value))
            interval = max(0.0, float(interval_value))
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
        run_button = self.query_one("#mtr-run", Button)
        stop_button = self.query_one("#mtr-stop", Button)
        run_button.disabled = True
        stop_button.disabled = False

        self.perform_mtr(target, max_hops, timeout, interval)

    @on(Button.Pressed, "#mtr-stop")
    def stop_mtr(self) -> None:  # noqa: D401
        if not self.running:
            if self.app is not None:
                self.app.bell()
            return
        self._should_stop = True

    @work(exclusive=True)
    async def perform_mtr(
        self,
        target: str,
        max_hops: int,
        timeout: float,
        interval: float,
    ) -> None:
        app = self.app

        def dispatch(callback, *args: Any) -> None:
            if app is not None and getattr(app, "_thread_id", None) != get_ident():
                app.call_from_thread(callback, *args)
            else:
                callback(*args)

        dns_cache: dict[str, Optional[str]] = {}
        ttl_clients: dict[int, AsyncClient] = {}
        hop_clients: dict[int, AsyncClient] = {}
        try:
            try:
                route = await self._discover_route(target, max_hops, timeout)
            except Exception as exc:  # pragma: no cover - defensive
                dispatch(self._handle_worker_error, exc)
                return

            resolved = route.resolved or target
            dispatch(self._set_resolved_target, resolved)
            self._initialize_route(route)
            for hop in route.hops:
                if hop.addr:
                    dns_cache.setdefault(hop.addr, hop.hostname)

            for ttl in self._hop_ttls:
                info = self._route_info.get(ttl, {})
                addr = info.get("addr")
                if not addr:
                    continue
                try:
                    client = AsyncClient(
                        timeout=timeout,
                        resolve_dns_default=False,
                        identifier=_new_identifier(),
                    )
                    await client.__aenter__()
                except RawSocketPermissionError as exc:
                    dispatch(self._handle_worker_error, exc)
                    self._should_stop = True
                    return
                hop_clients[ttl] = client

            while not self._should_stop:
                order = list(self._hop_ttls) if self._hop_ttls else list(range(1, max_hops + 1))
                if not order:
                    break

                tasks = []
                for ttl in order:
                    info = self._route_info.get(ttl, {})
                    addr = info.get("addr")
                    if addr and ttl in hop_clients:
                        tasks.append(
                            self._ping_hop_once(
                                hop_clients[ttl],
                                ttl,
                                addr,
                                timeout,
                                dns_cache,
                            )
                        )
                    else:
                        tasks.append(
                            self._probe_ttl_once(
                                ttl_clients,
                                resolved,
                                ttl,
                                timeout,
                                dns_cache,
                            )
                        )

                probes = await asyncio.gather(*tasks, return_exceptions=True)

                reached_ttl: Optional[int] = None
                for ttl_value, outcome in zip(order, probes):
                    if isinstance(outcome, RawSocketPermissionError):
                        dispatch(self._handle_worker_error, outcome)
                        self._should_stop = True
                        break
                    if isinstance(outcome, Exception):
                        dispatch(self._handle_worker_error, outcome)
                        continue

                    if ttl_value not in self._hop_ttls:
                        self._hop_ttls.append(ttl_value)
                        self._hop_ttls.sort()

                    ttl_value, result, addr, host = outcome
                    if addr:
                        info = self._route_info.setdefault(ttl_value, {})
                        if info.get("addr") is None:
                            info["addr"] = addr
                        if host and info.get("hostname") is None:
                            info["hostname"] = host
                        dns_cache.setdefault(addr, host)
                        if ttl_value not in hop_clients:
                            try:
                                client = AsyncClient(
                                    timeout=timeout,
                                    resolve_dns_default=False,
                                    identifier=_new_identifier(),
                                )
                                await client.__aenter__()
                            except RawSocketPermissionError as exc:
                                dispatch(self._handle_worker_error, exc)
                                self._should_stop = True
                                break
                            hop_clients[ttl_value] = client

                    rtt_ms = result.reply.rtt
                    rtt_value = (
                        rtt_ms if rtt_ms is not None and math.isfinite(rtt_ms) else None
                    )

                    error = result.error
                    expected_error = False
                    if isinstance(error, str):
                        if error.startswith("time_exceeded"):
                            expected_error = True
                        elif error.startswith("dest_unreachable") or error.startswith(
                            "destination_unreachable"
                        ):
                            expected_error = True

                    if error not in (None, "timeout") and not expected_error:
                        dispatch(self._handle_worker_error, RuntimeError(error))
                        continue

                    dispatch(self._register_sample, ttl_value, addr, host, rtt_value)

                    if addr == resolved and error is None:
                        reached_ttl = (
                            ttl_value
                            if reached_ttl is None
                            else min(reached_ttl, ttl_value)
                        )

                if self._should_stop:
                    break

                if reached_ttl is not None:
                    limit = reached_ttl
                    stale_ttls = [ttl for ttl in list(ttl_clients) if ttl > limit]
                    if stale_ttls:
                        stale_clients = [ttl_clients.pop(ttl) for ttl in stale_ttls]
                        await asyncio.gather(
                            *[
                                client.__aexit__(None, None, None)
                                for client in stale_clients
                            ],
                            return_exceptions=True,
                        )
                    stale_direct = [ttl for ttl in list(hop_clients) if ttl > limit]
                    if stale_direct:
                        direct_clients = [hop_clients.pop(ttl) for ttl in stale_direct]
                        await asyncio.gather(
                            *[
                                client.__aexit__(None, None, None)
                                for client in direct_clients
                            ],
                            return_exceptions=True,
                        )
                    self._hop_ttls = [ttl for ttl in self._hop_ttls if ttl <= limit]
                    dispatch(self._truncate_hops, limit)

                dispatch(self._increment_cycle)
                if self._should_stop:
                    break
                if interval > 0:
                    await asyncio.sleep(interval)
        finally:
            if hop_clients:
                await asyncio.gather(
                    *[
                        client.__aexit__(None, None, None)
                        for client in list(hop_clients.values())
                    ],
                    return_exceptions=True,
                )
            if ttl_clients:
                await asyncio.gather(
                    *[
                        client.__aexit__(None, None, None)
                        for client in list(ttl_clients.values())
                    ],
                    return_exceptions=True,
                )
            dispatch(self._finish_worker)

    async def _discover_route(
        self,
        target: str,
        max_hops: int,
        timeout: float,
    ) -> TracerouteResult:
        async with AsyncClient(
            timeout=timeout,
            resolve_dns_default=True,
            identifier=_new_identifier(),
        ) as client:
            return await client.traceroute(
                target,
                max_hops=max_hops,
                probes=1,
                timeout=timeout,
                resolve_dns=True,
            )

    def _initialize_route(self, route: TracerouteResult) -> None:
        self._hop_ttls = []
        for hop in route.hops:
            ttl = hop.ttl
            self._hop_ttls.append(ttl)
            info = self._route_info.setdefault(ttl, {})
            if hop.addr:
                info.setdefault("addr", hop.addr)
            if hop.hostname:
                info.setdefault("hostname", hop.hostname)
            entry = self._stats.setdefault(
                ttl,
                {
                    "addr": None,
                    "hostname": None,
                    "addr_counts": Counter(),
                    "hostname_counts": Counter(),
                    "sent": 0,
                    "recv": 0,
                    "rtts": [],
                    "last": None,
                },
            )
            if hop.addr:
                entry["addr"] = hop.addr
            if hop.hostname:
                entry["hostname"] = hop.hostname
        self._hop_ttls.sort()

    async def _ping_hop_once(
        self,
        client: AsyncClient,
        ttl: int,
        address: str,
        timeout: float,
        dns_cache: dict[str, Optional[str]],
    ) -> tuple[int, EchoResult, Optional[str], Optional[str]]:
        result = await client.probe(
            address,
            timeout=timeout,
            resolve_dns=False,
        )
        host = dns_cache.get(address)
        if host is None and result.reply.received_packet is not None:
            host = await client.reverse_dns(address)
            dns_cache[address] = host
        return ttl, result, address, host

    async def _probe_ttl_once(
        self,
        clients: dict[int, AsyncClient],
        resolved: str,
        ttl: int,
        timeout: float,
        dns_cache: dict[str, Optional[str]],
    ) -> tuple[int, EchoResult, Optional[str], Optional[str]]:
        client = clients.get(ttl)
        if client is None:
            client = AsyncClient(
                timeout=timeout,
                default_ttl=ttl,
                resolve_dns_default=False,
                identifier=_new_identifier(),
            )
            await client.__aenter__()
            clients[ttl] = client

        result = await client.probe(
            resolved,
            ttl=ttl,
            timeout=timeout,
            resolve_dns=False,
        )
        reply_packet = result.reply.received_packet
        addr: Optional[str] = None
        host: Optional[str] = None
        if reply_packet is not None:
            addr = reply_packet.ip_header.src_addr
            if addr in dns_cache:
                host = dns_cache[addr]
            else:
                host = await client.reverse_dns(addr)
                dns_cache[addr] = host
        return ttl, result, addr, host

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
                "addr_counts": Counter(),
                "hostname_counts": Counter(),
                "sent": 0,
                "recv": 0,
                "rtts": [],
                "last": None,
            },
        )

        entry["sent"] += 1
        addr_counts: Counter[str] = entry["addr_counts"]
        host_counts: Counter[str] = entry["hostname_counts"]

        if address:
            addr_counts[address] += 1
        if hostname:
            host_counts[hostname] += 1

        if addr_counts:
            entry["addr"] = addr_counts.most_common(1)[0][0]
        elif address:
            entry["addr"] = address

        if host_counts:
            entry["hostname"] = host_counts.most_common(1)[0][0]
        elif hostname:
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

            addr_counts = data.get("addr_counts")
            if isinstance(addr_counts, Counter) and addr_counts:
                addr_list = [addr for addr, _ in addr_counts.most_common()]
                addr_display = ", ".join(addr_list)
            else:
                addr_display = data.get("addr") or "?"

            host_counts = data.get("hostname_counts")
            if isinstance(host_counts, Counter) and host_counts:
                host_list = [host for host, _ in host_counts.most_common() if host]
                hostname_display = ", ".join(host_list)
            else:
                hostname_display = data.get("hostname") or ""

            table.add_row(
                str(ttl),
                addr_display,
                hostname_display,
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

    def _truncate_hops(self, limit: int) -> None:
        removed = [ttl for ttl in self._stats if ttl > limit]
        if not removed:
            return
        for ttl in removed:
            del self._stats[ttl]
            self._route_info.pop(ttl, None)
        if self._hop_ttls:
            self._hop_ttls = [ttl for ttl in self._hop_ttls if ttl <= limit]
        self._refresh_table()

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
