"""MTR helper functionality."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ._icmp import EchoResult, Icmp, logger


@dataclass
class MtrHop:
    ttl: int
    address: Optional[str]
    hostname: Optional[str]
    sent: int
    received: int
    loss_percent: float
    rtt_min: Optional[float]
    rtt_avg: Optional[float]
    rtt_max: Optional[float]
    samples: list[Optional[float]]


@dataclass
class MtrResult:
    target: str
    resolved: str
    cycles: int
    hops: list[MtrHop]

    def __str__(self) -> str:
        lines = [f"MTR to {self.target} ({self.resolved}), {self.cycles} cycles"]
        header = (
            f"{'Hop':<4}"
            f" {'Address':<20}"
            f" {'Hostname':<40}"
            f" {'Loss%':>6}"
            f" {'Sent':>5}"
            f" {'Recv':>5}"
            f" {'Min':>8}"
            f" {'Avg':>8}"
            f" {'Max':>8}"
        )
        lines.append(header)
        for hop in self.hops:
            addr = hop.address if hop.address else "?"
            hostname = hop.hostname if hop.hostname else "?"
            loss = f"{hop.loss_percent:.1f}" if hop.loss_percent is not None else "?"
            sent = f"{hop.sent}" if hop.sent is not None else "?"
            received = f"{hop.received}" if hop.received is not None else "?"
            rtt_min = f"{hop.rtt_min:.2f}" if hop.rtt_min is not None else "?"
            rtt_avg = f"{hop.rtt_avg:.2f}" if hop.rtt_avg is not None else "?"
            rtt_max = f"{hop.rtt_max:.2f}" if hop.rtt_max is not None else "?"
            lines.append(
                f"{hop.ttl:<4}"
                f" {addr:<20}"
                f" {hostname:<40}"
                f" {loss:>6}"
                f" {sent:>5}"
                f" {received:>5}"
                f" {rtt_min:>8}"
                f" {rtt_avg:>8}"
                f" {rtt_max:>8}"
            )
        return "\n".join(lines) + "\n"

    def __rich__(self) -> str:  # pragma: no cover - rich display helper
        return self.__str__()


def mtr(
    icmp: Icmp,
    dest_addr: str,
    *,
    max_hops: int = 30,
    cycles: int = 5,
    timeout: Optional[float] = None,
    resolve_dns: bool = False,
) -> MtrResult:
    """Run an MTR session using an existing :class:`Icmp` instance."""
    try:
        resolved = icmp.resolve_destination(dest_addr)
    except RuntimeError as exc:
        logger.error(str(exc))
        return MtrResult(target=dest_addr, resolved=dest_addr, cycles=cycles, hops=[])

    samples: dict[int, list[Optional[float]]] = {
        ttl: [] for ttl in range(1, max_hops + 1)
    }
    addresses: dict[int, Optional[str]] = {ttl: None for ttl in range(1, max_hops + 1)}
    hostnames: dict[int, Optional[str]] = {ttl: None for ttl in range(1, max_hops + 1)}

    with icmp.use_timeout(timeout):
        logger.info(
            "Starting MTR to %s (%s) cycles=%d max_hops=%d",
            dest_addr,
            resolved,
            cycles,
            max_hops,
        )
        for cycle in range(1, cycles + 1):
            logger.info("Cycle %d", cycle)
            destination_reached = False
            for ttl in range(1, max_hops + 1):
                result: EchoResult = icmp.probe(resolved, ttl=ttl)

                if result.error:
                    logger.error("  ttl %d: %s", ttl, result.error)
                    samples[ttl].append(None)
                    destination_reached = True
                    break

                received = result.received_packet
                sent_packet = result.sent_packet

                if received is not None and sent_packet is not None:
                    addr = received.ip_header.src_addr
                    if addresses[ttl] is None:
                        addresses[ttl] = addr
                        if resolve_dns and addr:
                            hostnames[ttl] = icmp.resolve_dns(addr)
                    if result.response is not None:
                        rtt = result.response.rtt
                    else:
                        rtt = (received.received_at - sent_packet.timestamp) * 1000
                    samples[ttl].append(rtt)

                    logger.info("  ttl %d: %s rtt=%.2f ms", ttl, addr or "?", rtt)
                    if result.response is not None and addr == resolved:
                        destination_reached = True
                else:
                    samples[ttl].append(None)
                    logger.warning("  ttl %d: timeout", ttl)

                if destination_reached:
                    logger.info("Destination reached during cycle %d", cycle)
                    break

    hops: list[MtrHop] = []
    for ttl, rtt_samples in samples.items():
        if not rtt_samples:
            continue
        sent = len(rtt_samples)
        received = len([r for r in rtt_samples if r is not None])
        loss_percent = ((sent - received) / sent) * 100 if sent else 0.0
        valid_rtts = [r for r in rtt_samples if r is not None]
        rtt_min = min(valid_rtts) if valid_rtts else None
        rtt_max = max(valid_rtts) if valid_rtts else None
        rtt_avg = (sum(valid_rtts) / len(valid_rtts)) if valid_rtts else None

        hops.append(
            MtrHop(
                ttl=ttl,
                address=addresses[ttl],
                hostname=hostnames[ttl],
                sent=sent,
                received=received,
                loss_percent=loss_percent,
                rtt_min=rtt_min,
                rtt_avg=rtt_avg,
                rtt_max=rtt_max,
                samples=rtt_samples,
            )
        )
    return MtrResult(target=dest_addr, resolved=resolved, cycles=cycles, hops=hops)
