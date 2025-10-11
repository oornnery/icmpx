from __future__ import annotations

import logging
import os
import select
import socket
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACHABLE = 3


# ------------- Logger configuravel
console = Console()
FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET",
    format=FORMAT,
    datefmt="[%X]",
    handlers=[
        RichHandler(
            console=console,
            rich_tracebacks=True,
            markup=True,
            show_time=False,
        )
    ],
)
logger = logging.getLogger("rich")


@dataclass
class IcmpPacket:
    type: int
    code: int
    checksum: int
    id: int
    sequence: int
    data: bytes


@dataclass
class IpHeader:
    version: int
    ihl: int
    tos: int
    total_length: int
    id: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_addr: str
    dest_addr: str


@dataclass
class EchoResponse:
    rtt: float
    addr: str
    sequence: int


@dataclass
class SentPacket:
    icmp_packet: IcmpPacket
    raw: bytes
    timestamp: float
    destination: str
    ttl: int


@dataclass
class ReceivedPacket:
    ip_header: IpHeader
    icmp_packet: IcmpPacket
    raw: bytes
    received_at: float


@dataclass
class EchoResult:
    response: Optional[EchoResponse]
    sent_packet: Optional[SentPacket]
    received_packet: Optional[ReceivedPacket]
    error: Optional[str]

    def __str__(self) -> str:
        if self.error:
            return f"Error: {self.error}\n"
        if self.response:
            return f"Reply from {self.response.addr}: time={self.response.rtt:.2f} ms (seq={self.response.sequence})\n"
        return "Request timed out.\n"

    def __rich__(self) -> str:
        return self.__str__()


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
                f"Approximate round trip times in milli-seconds:\n  Minimum = {self.stats.rtt_min:.2f} ms, Average = {self.stats.rtt_avg:.2f} ms, Maximum = {self.stats.rtt_max:.2f} ms"
            )
        else:
            lines.append("No round trip time data available.")
        return "\n".join(lines) + "\n"

    def __rich__(self) -> str:
        return self.__str__()


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

    def __rich__(self) -> str:
        return self.__str__()


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

    def __rich__(self) -> str:
        return self.__str__()


class RawSocketPermissionError(PermissionError):
    """Raised when raw socket creation fails due to missing privileges."""


class Icmp:
    ICMP_ECHO_REQUEST = ICMP_ECHO_REQUEST
    ICMP_ECHO_REPLY = ICMP_ECHO_REPLY
    ICMP_TIME_EXCEEDED = ICMP_TIME_EXCEEDED

    @staticmethod
    def _valid_ip(host: str) -> bool:
        try:
            socket.inet_aton(host)
            return True
        except OSError:
            return False

    @staticmethod
    def _resolve_host(host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except OSError as exc:
            message = f"Resolve error {host}"
            logger.error(message)
            raise RuntimeError(message) from exc

    @staticmethod
    def _resolve_dns(addr: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(addr)[0]
        except OSError:
            return None

    @contextmanager
    def _use_timeout(self, timeout: Optional[float]):
        if timeout is None:
            yield
            return

        previous = self.timeout
        self.timeout = timeout
        if self._sock is not None:
            self._sock.settimeout(timeout)
        try:
            yield
        finally:
            self.timeout = previous
            if self._sock is not None:
                self._sock.settimeout(previous)

    def _resolve_destination(self, dest_addr: str) -> str:
        if self._valid_ip(dest_addr):
            return dest_addr
        return self._resolve_host(dest_addr)

    def __init__(self, timeout: float = 1.0, default_ttl: int = 64):
        self.timeout = timeout
        self.default_ttl = default_ttl
        self.seq_number = 0
        self.identifier = os.getpid() & 0xFFFF
        self._sock: Optional[socket.socket] = None

    @property
    def sock(self) -> socket.socket:
        if self._sock is None:
            try:
                self._sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_RAW,
                    socket.getprotobyname("icmp"),
                )
            except PermissionError as exc:
                message = (
                    "Raw socket requires elevated privileges. Use sudo or grant "
                    "CAP_NET_RAW to the Python interpreter."
                )
                raise RawSocketPermissionError(message) from exc
            self._sock.settimeout(self.timeout)
        return self._sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "Icmp":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _parser_icmp_packet(self, pkt: bytes, received_at: float) -> ReceivedPacket:
        if len(pkt) < 20:
            raise ValueError("Packet shorter than minimum IP header length (20 bytes).")

        iph = struct.unpack("!BBHHHBBH4s4s", pkt[:20])
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        if len(pkt) < iph_length + 8:
            raise ValueError(
                "Packet shorter than IP header + ICMP header (IHL + 8 bytes)."
            )

        tos = iph[1]
        total_length = iph[2]
        identifier = iph[3]
        flags_fragment = iph[4]
        flags = flags_fragment >> 13
        fragment_offset = flags_fragment & 0x1FFF
        ttl = iph[5]
        protocol = iph[6]
        checksum = iph[7]
        src_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])

        icmp_header = pkt[iph_length : iph_length + 8]
        icmph = struct.unpack("!BBHHH", icmp_header)
        data = pkt[iph_length + 8 :]

        ip_hdr = IpHeader(
            version=version,
            ihl=ihl,
            tos=tos,
            total_length=total_length,
            id=identifier,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            src_addr=src_addr,
            dest_addr=dest_addr,
        )
        icmp_pkt = IcmpPacket(
            type=icmph[0],
            code=icmph[1],
            checksum=icmph[2],
            id=icmph[3],
            sequence=icmph[4],
            data=data,
        )
        return ReceivedPacket(
            ip_header=ip_hdr, icmp_packet=icmp_pkt, raw=pkt, received_at=received_at
        )

    def _icmp_checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return (~total) & 0xFFFF

    def _build_icmp_packet(self, sequence: int) -> tuple[bytes, IcmpPacket, float]:
        timestamp = time.time()
        header = struct.pack(
            "!BBHHH", self.ICMP_ECHO_REQUEST, 0, 0, self.identifier, sequence
        )
        data = struct.pack("d", timestamp)
        checksum = self._icmp_checksum(header + data)
        header = struct.pack(
            "!BBHHH", self.ICMP_ECHO_REQUEST, 0, checksum, self.identifier, sequence
        )
        packet_bytes = header + data
        icmp_pkt = IcmpPacket(
            type=self.ICMP_ECHO_REQUEST,
            code=0,
            checksum=checksum,
            id=self.identifier,
            sequence=sequence,
            data=data,
        )
        return packet_bytes, icmp_pkt, timestamp

    def _matches_probe(
        self, identifier: int, sequence: int, icmp_pkt: IcmpPacket
    ) -> bool:
        if icmp_pkt.type == ICMP_ECHO_REPLY:
            return icmp_pkt.id == identifier and icmp_pkt.sequence == sequence

        if (
            icmp_pkt.type in {ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACHABLE}
            and len(icmp_pkt.data) >= 28
        ):
            try:
                _, _, _, inner_id, inner_seq = struct.unpack(
                    "!BBHHH", icmp_pkt.data[20:28]
                )
            except struct.error:
                return False
            return inner_id == identifier and inner_seq == sequence

        return False

    def _send_echo_request(
        self, dest_addr: str, ttl: Optional[int] = None
    ) -> SentPacket:
        self.seq_number += 1
        packet_bytes, icmp_pkt, timestamp = self._build_icmp_packet(self.seq_number)
        ttl_value = ttl if ttl is not None else self.default_ttl
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl_value)
        self.sock.sendto(packet_bytes, (dest_addr, 1))
        return SentPacket(
            icmp_packet=icmp_pkt,
            raw=packet_bytes,
            timestamp=timestamp,
            destination=dest_addr,
            ttl=ttl_value,
        )

    def _receive_probe(
        self,
        expected_sequence: int,
        sent_timestamp: float,
        *,
        allow_extended_types: bool,
    ) -> tuple[Optional[EchoResponse], Optional[ReceivedPacket]]:
        deadline = time.time() + self.timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None, None

            ready = select.select([self.sock], [], [], remaining)
            if not ready[0]:
                return None, None

            recv_time = time.time()
            pkt, _ = self.sock.recvfrom(1024)
            try:
                received = self._parser_icmp_packet(pkt, recv_time)
            except ValueError as err:
                logger.debug(f"Discarding malformed packet: {err}")
                continue

            if not self._matches_probe(
                self.identifier, expected_sequence, received.icmp_packet
            ):
                continue

            if received.icmp_packet.type == ICMP_ECHO_REPLY:
                rtt = (received.received_at - sent_timestamp) * 1000
                response = EchoResponse(
                    rtt=rtt,
                    addr=received.ip_header.src_addr,
                    sequence=received.icmp_packet.sequence,
                )
                return response, received

            if allow_extended_types and received.icmp_packet.type in {
                ICMP_TIME_EXCEEDED,
                ICMP_DEST_UNREACHABLE,
            }:
                return None, received

    def _receive_echo_reply(
        self, expected_sequence: int, sent_timestamp: float
    ) -> tuple[Optional[EchoResponse], Optional[ReceivedPacket]]:
        return self._receive_probe(
            expected_sequence, sent_timestamp, allow_extended_types=False
        )

    def probe(
        self,
        dest_addr: str,
        ttl: Optional[int] = None,
    ) -> EchoResult:
        sent_packet: Optional[SentPacket] = None
        try:
            sent_packet = self._send_echo_request(dest_addr, ttl=ttl)
            response, received_packet = self._receive_probe(
                expected_sequence=sent_packet.icmp_packet.sequence,
                sent_timestamp=sent_packet.timestamp,
                allow_extended_types=True,
            )
            return EchoResult(
                response=response,
                sent_packet=sent_packet,
                received_packet=received_packet,
                error=None,
            )
        except RawSocketPermissionError as exc:
            logger.error(str(exc))
            return EchoResult(
                response=None,
                sent_packet=sent_packet,
                received_packet=None,
                error=str(exc),
            )
        except Exception as exc:  # pragma: no cover - safeguard for unexpected failures
            logger.error(f"Probe error: {exc}")
            return EchoResult(
                response=None,
                sent_packet=sent_packet,
                received_packet=None,
                error=str(exc),
            )

    def echo(self, dest_addr: str, ttl: Optional[int] = None) -> EchoResult:
        return self.probe(dest_addr, ttl=ttl)

    def ping(
        self,
        dest_addr: str,
        *,
        ttl: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> EchoResult:
        try:
            resolved = self._resolve_destination(dest_addr)
        except RuntimeError as exc:
            logger.error(str(exc))
            return EchoResult(
                response=None,
                sent_packet=None,
                received_packet=None,
                error=str(exc),
            )
        ttl_value = ttl if ttl is not None else self.default_ttl
        logger.info("Ping %s (ttl=%s)", resolved, ttl_value)

        with self._use_timeout(timeout):
            result = self.probe(resolved, ttl=ttl_value)

        if result.response is not None:
            logger.info(
                "Reply from %s: time=%.2f ms (seq=%d)",
                result.response.addr,
                result.response.rtt,
                result.response.sequence,
            )
        elif result.received_packet is not None:
            logger.warning(
                "Received ICMP type %d code %d",
                result.received_packet.icmp_packet.type,
                result.received_packet.icmp_packet.code,
            )
        elif result.error:
            logger.error("Ping error: %s", result.error)
        else:
            logger.warning("Ping timeout")

        return result

    def multiping(
        self,
        dest_addr: str,
        *,
        count: int = 4,
        interval: float = 1.0,
        timeout: Optional[float] = None,
    ) -> MultiPingResult:
        try:
            resolved = self._resolve_destination(dest_addr)
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

        with self._use_timeout(timeout):
            logger.info(f"Starting multiping to {resolved} ({count} probes)")
            for idx in range(count):
                logger.debug(f"Sending ping {idx + 1}/{count} to {resolved}")
                result = self.probe(resolved)
                responses.append(result)
                if result.response is not None:
                    logger.info(
                        f"Ping {idx + 1}: reply from {result.response.addr} in {result.response.rtt:.2f} ms"
                    )
                elif result.received_packet is not None:
                    logger.warning(
                        f"Ping {idx + 1}: received ICMP type {result.received_packet.icmp_packet.type}"
                    )
                elif result.error:
                    logger.error(f"Ping {idx + 1}: error {result.error}")
                else:
                    logger.warning(f"Ping {idx + 1}: timed out")
                if interval > 0 and idx < count - 1:
                    time.sleep(interval)

        rtts = [
            result.response.rtt for result in responses if result.response is not None
        ]
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
            target=dest_addr, resolved=resolved, responses=responses, stats=stats
        )

    def traceroute(
        self,
        dest_addr: str,
        *,
        max_hops: int = 30,
        probes: int = 3,
        timeout: Optional[float] = None,
        resolve_dns: bool = False,
    ) -> TracerouteResult:
        try:
            resolved = self._resolve_destination(dest_addr)
        except RuntimeError as exc:
            logger.error(str(exc))
            return TracerouteResult(
                target=dest_addr, resolved=dest_addr, probes_per_hop=probes, hops=[]
            )
        hops: list[TracerouteHop] = []

        with self._use_timeout(timeout):
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
                    result = self.probe(resolved, ttl=ttl)

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
                    hostname = self._resolve_dns(addr) if resolve_dns and addr else None

                    if response is not None:
                        rtt = response.rtt
                    else:
                        rtt = (received.received_at - sent_packet.timestamp) * 1000

                    error_message = None
                    if received.icmp_packet.type == ICMP_DEST_UNREACHABLE:
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
            target=dest_addr, resolved=resolved, probes_per_hop=probes, hops=hops
        )

    def mtr(
        self,
        dest_addr: str,
        *,
        max_hops: int = 30,
        cycles: int = 5,
        timeout: Optional[float] = None,
        resolve_dns: bool = False,
    ) -> MtrResult:
        try:
            resolved = self._resolve_destination(dest_addr)
        except RuntimeError as exc:
            logger.error(str(exc))
            return MtrResult(
                target=dest_addr, resolved=dest_addr, cycles=cycles, hops=[]
            )
        samples: dict[int, list[Optional[float]]] = {
            ttl: [] for ttl in range(1, max_hops + 1)
        }
        addresses: dict[int, Optional[str]] = {
            ttl: None for ttl in range(1, max_hops + 1)
        }
        hostnames: dict[int, Optional[str]] = {
            ttl: None for ttl in range(1, max_hops + 1)
        }

        with self._use_timeout(timeout):
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
                    result = self.probe(resolved, ttl=ttl)

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
                                hostnames[ttl] = self._resolve_dns(addr)
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
