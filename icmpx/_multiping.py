"""Multiping helper functionality."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from ._icmp import EchoResult, Icmp, logger


@dataclass
class EchoStats:
    sent: int
    received: int
    lost: int
    loss_percent: float
    rtt_min: Optional[float]
    rtt_avg: Optional[float]
    rtt_max: Optional[float]


@dataclass
class MultiPingResult:
    target: str
    resolved: str
    responses: list[EchoResult]
    stats: EchoStats

    def __str__(self) -> str:
        lines = [
            f"Multiping to {self.target} ({self.resolved}):",
            f"  Packets: Sent = {self.stats.sent}, Received = {self.stats.received}, Lost = {self.stats.lost} ({self.stats.loss_percent:.1f}% loss)",
        ]
        if (
            self.stats.rtt_min is not None
            and self.stats.rtt_avg is not None
            and self.stats.rtt_max is not None
        ):
            lines.append(
                "Approximate round trip times in milli-seconds:\n"
                f"  Minimum = {self.stats.rtt_min:.2f} ms, "
                f"Average = {self.stats.rtt_avg:.2f} ms, "
                f"Maximum = {self.stats.rtt_max:.2f} ms"
            )
        else:
            lines.append("No round trip time data available.")
        return "\n".join(lines) + "\n"

    def __rich__(self) -> str:  # pragma: no cover - rich display helper
        return self.__str__()


def multiping(
    icmp: Icmp,
    dest_addr: str,
    *,
    count: int = 4,
    interval: float = 1.0,
    timeout: Optional[float] = None,
) -> MultiPingResult:
    """Execute multiple probes using an existing :class:`Icmp` instance."""
    try:
        resolved = icmp.resolve_destination(dest_addr)
    except RuntimeError as exc:
        logger.error(str(exc))
        stats = EchoStats(
            sent=0,
            received=0,
            lost=0,
            loss_percent=0.0,
            rtt_min=None,
            rtt_avg=None,
            rtt_max=None,
        )
        error_result = EchoResult(
            response=None,
            sent_packet=None,
            received_packet=None,
            error=str(exc),
        )
        return MultiPingResult(
            target=dest_addr,
            resolved=dest_addr,
            responses=[error_result],
            stats=stats,
        )

    responses: list[EchoResult] = []

    with icmp.use_timeout(timeout):
        logger.info("Starting multiping to %s (%d probes)", resolved, count)
        for idx in range(count):
            logger.debug("Sending ping %d/%d to %s", idx + 1, count, resolved)
            result = icmp.probe(resolved)
            responses.append(result)
            if result.response is not None:
                logger.info(
                    "Ping %d: reply from %s in %.2f ms",
                    idx + 1,
                    result.response.addr,
                    result.response.rtt,
                )
            elif result.received_packet is not None:
                logger.warning(
                    "Ping %d: received ICMP type %d",
                    idx + 1,
                    result.received_packet.icmp_packet.type,
                )
            elif result.error:
                logger.error("Ping %d: error %s", idx + 1, result.error)
            else:
                logger.warning("Ping %d: timed out", idx + 1)
            if interval > 0 and idx < count - 1:
                time.sleep(interval)

    rtts = [result.response.rtt for result in responses if result.response is not None]
    sent = len(responses)
    received = len(rtts)
    lost = sent - received
    loss_percent = (lost / sent) * 100 if sent else 0.0

    stats = EchoStats(
        sent=sent,
        received=received,
        lost=lost,
        loss_percent=loss_percent,
        rtt_min=min(rtts) if rtts else None,
        rtt_avg=(sum(rtts) / len(rtts)) if rtts else None,
        rtt_max=max(rtts) if rtts else None,
    )

    logger.info(
        "Multiping stats -> sent: %d received: %d loss: %.1f%% min/avg/max: %s/%s/%s",
        stats.sent,
        stats.received,
        stats.loss_percent,
        f"{stats.rtt_min:.2f} ms" if stats.rtt_min is not None else "n/a",
        f"{stats.rtt_avg:.2f} ms" if stats.rtt_avg is not None else "n/a",
        f"{stats.rtt_max:.2f} ms" if stats.rtt_max is not None else "n/a",
    )

    return MultiPingResult(
        target=dest_addr,
        resolved=resolved,
        responses=responses,
        stats=stats,
    )
