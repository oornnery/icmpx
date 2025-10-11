"""Interactive Textual TUI for icmpx."""

from __future__ import annotations

from typing import Callable, Optional

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Input,
    Label,
    Static,
    Footer,
)
from textual.worker import Worker

try:  # pragma: no cover - runtime convenience for script usage
    from . import Icmp, mtr, multiping, traceroute
    from ._mtr import MtrResult
    from ._multiping import MultiPingResult
    from ._traceroute import TracerouteResult
except ImportError:  # pragma: no cover - fallback when run directly
    import pathlib
    import sys

    sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
    from icmpx import Icmp, mtr, multiping, traceroute
    from icmpx._mtr import MtrResult
    from icmpx._multiping import MultiPingResult
    from icmpx._traceroute import TracerouteResult


def _reset_table(table: DataTable, columns: tuple[str, ...]) -> None:
    """Clear table contents while ensuring columns remain present."""

    table.clear()
    if not getattr(table, "columns", None):
        table.add_columns(*columns)


class BaseToolView(VerticalScroll):
    """Base view with helpers for running network tasks."""

    title: str = ""

    def __init__(self, *, view_id: str) -> None:
        super().__init__(id=view_id)
        self._worker: Optional[Worker] = None

    def _start_worker(self, func: Callable[[], object]) -> None:
        if self._worker and not self._worker.is_finished:
            self.app.bell()
            return

        app = self.app
        if app is None:
            raise RuntimeError("App is not available for worker execution")

        def task_wrapper() -> None:
            try:
                result = func()
            except Exception as error:  # pragma: no cover - defensive handling
                app.call_from_thread(self._handle_worker_error, error)
            else:
                app.call_from_thread(self.update_result, result)
            finally:
                app.call_from_thread(self._clear_worker)

        self._worker = self.run_worker(
            task_wrapper,
            thread=True,
            exclusive=True,
            name=f"worker-{self.id or 'tool'}",
        )

    def _handle_worker_error(self, error: Exception) -> None:
        self.app.bell()
        self.app.notify(f"Error: {error}")

    def _clear_worker(self) -> None:
        self._worker = None

    def update_result(self, result: object) -> None:  # pragma: no cover - overridden
        """Populate the UI with a finished result."""


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


class MultiPingView(BaseToolView):
    """Form for running multiple echo requests."""

    title = "MultiPing"

    def compose(self) -> ComposeResult:
        yield Label("Target host or IP")
        yield Input(placeholder="8.8.8.8", id="multiping-target", value="8.8.8.8")
        yield Label("Count")
        yield Input(placeholder="4", id="multiping-count", value="4")
        yield Label("Interval (seconds)")
        yield Input(placeholder="1.0", id="multiping-interval", value="1.0")
        yield Label("Timeout (seconds, optional)")
        yield Input(placeholder="1.0", id="multiping-timeout")
        yield Button("Run MultiPing", id="multiping-run")
        table = DataTable(id="multiping-table")
        table.add_columns("Seq", "Status", "RTT (ms)")
        yield table
        self._summary = Static(id="multiping-summary")
        yield self._summary

    @on(Button.Pressed, "#multiping-run")
    def run_multiping(self) -> None:  # noqa: D401
        target = self.query_one("#multiping-target", Input).value or "8.8.8.8"
        count_value = self.query_one("#multiping-count", Input).value or "4"
        interval_value = self.query_one("#multiping-interval", Input).value or "1.0"
        timeout_value = self.query_one("#multiping-timeout", Input).value

        def _task() -> MultiPingResult:
            count = max(1, int(count_value))
            interval = max(0.0, float(interval_value))
            timeout_opt = float(timeout_value) if timeout_value else None
            with Icmp() as icmp:
                return multiping(
                    icmp,
                    target,
                    count=count,
                    interval=interval,
                    timeout=timeout_opt,
                )

        self._start_worker(_task)

    def update_result(self, result: object) -> None:  # noqa: D401
        table = self.query_one("#multiping-table", DataTable)
        _reset_table(table, ("Seq", "Status", "RTT (ms)"))
        if not isinstance(result, MultiPingResult):
            return

        for response in result.responses:
            if response.response is not None:
                status = "reply"
                rtt_value = f"{response.response.rtt:.2f}"
                seq = str(response.response.sequence)
            elif response.error:
                status = f"error ({response.error})"
                rtt_value = "-"
                seq = "-"
            else:
                status = "timeout"
                rtt_value = "-"
                seq = "-"
            table.add_row(seq, status, rtt_value)

        stats = result.stats
        summary_lines = [
            f"Sent: {stats.sent}",
            f"Received: {stats.received}",
            f"Loss: {stats.loss_percent:.1f}%",
            f"Min: {stats.rtt_min:.2f} ms" if stats.rtt_min is not None else "Min: n/a",
            f"Avg: {stats.rtt_avg:.2f} ms" if stats.rtt_avg is not None else "Avg: n/a",
            f"Max: {stats.rtt_max:.2f} ms" if stats.rtt_max is not None else "Max: n/a",
        ]
        self._summary.update(" | ".join(summary_lines))


class TracerouteView(BaseToolView):
    """Form for running traceroute operations."""

    title = "Traceroute"

    def compose(self) -> ComposeResult:
        yield Label("Target host or IP")
        yield Input(placeholder="8.8.8.8", id="traceroute-target", value="8.8.8.8")
        yield Label("Max hops")
        yield Input(placeholder="30", id="traceroute-hops", value="30")
        yield Label("Probes per hop")
        yield Input(placeholder="3", id="traceroute-probes", value="3")
        yield Label("Timeout (seconds, optional)")
        yield Input(placeholder="1.0", id="traceroute-timeout")
        yield Button("Run Traceroute", id="traceroute-run")
        table = DataTable(id="traceroute-table")
        table.add_columns("Hop", "Address", "Hostname", "RTTs", "Notes")
        yield table

    @on(Button.Pressed, "#traceroute-run")
    def run_traceroute(self) -> None:  # noqa: D401
        target = self.query_one("#traceroute-target", Input).value or "8.8.8.8"
        hops_value = self.query_one("#traceroute-hops", Input).value or "30"
        probes_value = self.query_one("#traceroute-probes", Input).value or "3"
        timeout_value = self.query_one("#traceroute-timeout", Input).value

        def _task() -> TracerouteResult:
            max_hops = max(1, int(hops_value))
            probes = max(1, int(probes_value))
            timeout_opt = float(timeout_value) if timeout_value else None
            with Icmp() as icmp:
                return traceroute(
                    icmp,
                    target,
                    max_hops=max_hops,
                    probes=probes,
                    timeout=timeout_opt,
                    resolve_dns=True,
                )

        self._start_worker(_task)

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


class MtrView(BaseToolView):
    """Form for running MTR cycles."""

    title = "MTR"

    def compose(self) -> ComposeResult:
        yield Label("Target host or IP")
        yield Input(placeholder="8.8.8.8", id="mtr-target", value="8.8.8.8")
        yield Label("Max hops")
        yield Input(placeholder="30", id="mtr-hops", value="30")
        yield Label("Cycles")
        yield Input(placeholder="5", id="mtr-cycles", value="5")
        yield Label("Timeout (seconds, optional)")
        yield Input(placeholder="1.0", id="mtr-timeout")
        yield Button("Run MTR", id="mtr-run")
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

    @on(Button.Pressed, "#mtr-run")
    def run_mtr(self) -> None:  # noqa: D401
        target = self.query_one("#mtr-target", Input).value or "8.8.8.8"
        hops_value = self.query_one("#mtr-hops", Input).value or "30"
        cycles_value = self.query_one("#mtr-cycles", Input).value or "5"
        timeout_value = self.query_one("#mtr-timeout", Input).value

        def _task() -> MtrResult:
            max_hops = max(1, int(hops_value))
            cycles = max(1, int(cycles_value))
            timeout_opt = float(timeout_value) if timeout_value else None
            with Icmp() as icmp:
                return mtr(
                    icmp,
                    target,
                    max_hops=max_hops,
                    cycles=cycles,
                    timeout=timeout_opt,
                    resolve_dns=True,
                )

        self._start_worker(_task)

    def update_result(self, result: object) -> None:  # noqa: D401
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
        if not isinstance(result, MtrResult):
            return

        for hop in result.hops:
            table.add_row(
                str(hop.ttl),
                hop.address or "?",
                hop.hostname or "?",
                f"{hop.loss_percent:.1f}" if hop.loss_percent is not None else "?",
                str(hop.sent),
                str(hop.received),
                f"{hop.rtt_min:.2f}" if hop.rtt_min is not None else "-",
                f"{hop.rtt_avg:.2f}" if hop.rtt_avg is not None else "-",
                f"{hop.rtt_max:.2f}" if hop.rtt_max is not None else "-",
            )


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
                yield MultiPingView(view_id="multiping")
                yield TracerouteView(view_id="traceroute")
                yield MtrView(view_id="mtr")
        yield Footer()

    @on(Button.Pressed, ".nav-button")
    def on_nav_selected(self, event: Button.Pressed) -> None:  # noqa: D401
        view_id = event.button.id or "ping"
        self.query_one(ContentSwitcher).current = view_id


if __name__ == "__main__":
    app = IcmpxApp()
    app.run()
