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


class RawSocketPermissionError(PermissionError):
    """Raised when raw socket creation fails due to missing privileges."""


class Icmp:
    ICMP_ECHO_REQUEST = ICMP_ECHO_REQUEST
    ICMP_ECHO_REPLY = ICMP_ECHO_REPLY
    ICMP_TIME_EXCEEDED = ICMP_TIME_EXCEEDED
    ICMP_DEST_UNREACHABLE = ICMP_DEST_UNREACHABLE

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
    def resolve_dns(addr: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(addr)[0]
        except OSError:
            return None

    @contextmanager
    def use_timeout(self, timeout: Optional[float]):
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

    def resolve_destination(self, dest_addr: str) -> str:
        if self._valid_ip(dest_addr):
            return dest_addr
        return self._resolve_host(dest_addr)


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

    def ping(
        self,
        dest_addr: str,
        *,
        ttl: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> EchoResult:
        try:
            resolved = self.resolve_destination(dest_addr)
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

        with self.use_timeout(timeout):
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
