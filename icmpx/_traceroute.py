"""Traceroute helper functionality."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ._icmp import EchoResult, Icmp, ReceivedPacket, logger


@dataclass
class TracerouteProbe:
    ttl: int
    probe: int
    rtt: Optional[float]
    address: Optional[str]
    hostname: Optional[str]
    received: Optional[ReceivedPacket]
    error: Optional[str]
    reached_destination: bool


@dataclass
class TracerouteHop:
    ttl: int
    probes: list[TracerouteProbe]


@dataclass
class TracerouteResult:
    target: str
    resolved: str
    probes_per_hop: int
    hops: list[TracerouteHop]

    def __str__(self) -> str:
        lines = [
            f"Traceroute to {self.target} ({self.resolved}), {self.probes_per_hop} probes per hop"
        ]
        header = f"{'Hop':<4} {'Address':<20} {'Hostname':<40} {'Probe Times (ms)':>20}"
        lines.append(header)

        for hop in self.hops:
            address = "?"
            hostname = "?"
            for probe in hop.probes:
                if probe.address:
                    address = probe.address
                    if probe.hostname:
                        hostname = probe.hostname
                    break
            if hostname == "?":
                for probe in hop.probes:
                    if probe.hostname:
                        hostname = probe.hostname
                        break

            values: list[str] = []
            for idx in range(self.probes_per_hop):
                if idx < len(hop.probes):
                    probe = hop.probes[idx]
                    if probe.rtt is not None:
                        values.append(f"{probe.rtt:.2f} ms")
                    elif probe.error:
                        values.append(f"* {probe.error}")
                    else:
                        values.append("*")
                else:
                    values.append("-")

            line = f"{hop.ttl:<4} {address:<20} {hostname:<40}" + "".join(
                f" {value:>12}" for value in values
            )
            lines.append(line)
        return "\n".join(lines) + "\n"

    def __rich__(self) -> str:  # pragma: no cover - rich display helper
        return self.__str__()


def traceroute(
    icmp: Icmp,
    dest_addr: str,
    *,
    max_hops: int = 30,
    probes: int = 3,
    timeout: Optional[float] = None,
    resolve_dns: bool = False,
) -> TracerouteResult:
    """Run traceroute using an existing :class:`Icmp` instance."""
    try:
        resolved = icmp.resolve_destination(dest_addr)
    except RuntimeError as exc:
        logger.error(str(exc))
        return TracerouteResult(
            target=dest_addr,
            resolved=dest_addr,
            probes_per_hop=probes,
            hops=[],
        )

    hops: list[TracerouteHop] = []

    with icmp.use_timeout(timeout):
        reached = False
        logger.info(
            "Starting traceroute to %s (%s) max_hops=%d probes=%d",
            dest_addr,
            resolved,
            max_hops,
            probes,
        )
        for ttl in range(1, max_hops + 1):
            probe_entries: list[TracerouteProbe] = []
            logger.info("TTL %d", ttl)
            for probe_idx in range(1, probes + 1):
                result: EchoResult = icmp.probe(resolved, ttl=ttl)

                if result.error:
                    logger.error("  probe %d: %s", probe_idx, result.error)
                    probe_entries.append(
                        TracerouteProbe(
                            ttl=ttl,
                            probe=probe_idx,
                            rtt=None,
                            address=None,
                            hostname=None,
                            received=None,
                            error=result.error,
                            reached_destination=False,
                        )
                    )
                    reached = True
                    break

                received = result.received_packet
                sent_packet = result.sent_packet
                response = result.response

                if received is None:
                    logger.warning("  probe %d: timeout", probe_idx)
                    probe_entries.append(
                        TracerouteProbe(
                            ttl=ttl,
                            probe=probe_idx,
                            rtt=None,
                            address=None,
                            hostname=None,
                            received=None,
                            error="timeout",
                            reached_destination=False,
                        )
                    )
                    continue

                if sent_packet is None:
                    logger.error("  probe %d: missing sent packet data", probe_idx)
                    probe_entries.append(
                        TracerouteProbe(
                            ttl=ttl,
                            probe=probe_idx,
                            rtt=None,
                            address=None,
                            hostname=None,
                            received=received,
                            error="missing sent packet",
                            reached_destination=False,
                        )
                    )
                    continue

                addr = received.ip_header.src_addr
                hostname = icmp.resolve_dns(addr) if resolve_dns and addr else None

                if response is not None:
                    rtt = response.rtt
                else:
                    rtt = (received.received_at - sent_packet.timestamp) * 1000

                error_message = None
                if received.icmp_packet.type == icmp.ICMP_DEST_UNREACHABLE:
                    error_message = (
                        f"dest unreachable (code {received.icmp_packet.code})"
                    )

                reached_destination = response is not None and addr == resolved
                log_msg = f"  probe {probe_idx}: {addr}"
                if hostname:
                    log_msg += f" ({hostname})"
                log_msg += f" rtt={rtt:.2f} ms"
                if error_message:
                    log_msg += f" [{error_message}]"
                logger.info(log_msg)
                probe_entries.append(
                    TracerouteProbe(
                        ttl=ttl,
                        probe=probe_idx,
                        rtt=rtt,
                        address=addr,
                        hostname=hostname,
                        received=received,
                        error=error_message,
                        reached_destination=reached_destination,
                    )
                )

                if reached_destination:
                    reached = True
            hops.append(TracerouteHop(ttl=ttl, probes=probe_entries))
            if reached:
                logger.info("Destination reached at TTL %d", ttl)
                break
        if not reached:
            logger.warning("Traceroute finished without reaching destination")

    return TracerouteResult(
        target=dest_addr,
        resolved=resolved,
        probes_per_hop=probes,
        hops=hops,
    )
