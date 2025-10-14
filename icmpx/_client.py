from __future__ import annotations

import logging
import os
import select
import socket
import struct
import time
from contextlib import contextmanager

from ._models import (
    EchoReply,
    EchoRequest,
    EchoResult,
    ICMPPacket,
    IPHeader,
    ReceivedPacket,
    SentPacket,
    TracerouteEntry,
    TracerouteResult,
)

from ._exceptions import RawSocketPermissionError

# ICMP types
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_SOURCE_QUENCH = 4  # Obsoleto, mas reservado
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
ICMP_PARAMETER_PROBLEM = 12
ICMP_TIMESTAMP_REQUEST = 13
ICMP_TIMESTAMP_REPLY = 14

logger = logging.getLogger("icmpx")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class Client:
    def __init__(
        self,
        bind_addr: str | None = None,
        timeout: float = 1.0,
        default_ttl: int = 64,
        resolve_dns_default: bool = False,
    ) -> None:
        self.bind_addr = bind_addr
        self.timeout = timeout
        self.default_ttl = default_ttl
        self.resolve_dns_default = resolve_dns_default
        self._sock: socket.socket | None = None
        self._identifier = os.getpid() & 0xFFFF
        self._next_sequence = 0

    def __enter__(self) -> Client:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    # ------------- Utilitários DNS/IP -------------

    @staticmethod
    def valid_ip(addr: str) -> bool:
        try:
            socket.inet_aton(addr)
            return True
        except OSError:
            return False

    @staticmethod
    def resolve_host(host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror as exc:
            raise RuntimeError(f"Não foi possível resolver host: {host}") from exc

    @staticmethod
    def reverse_dns(addr: str) -> str | None:
        try:
            return socket.gethostbyaddr(addr)[0]
        except socket.herror:
            return None

    # ------------- Contextos de socket -------------

    def _create_socket(self) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            if self.bind_addr:
                sock.bind((self.bind_addr, 0))
            return sock
        except PermissionError as exc:
            msg = (
                "Raw socket requires elevated privileges. Use sudo or grant "
                "CAP_NET_RAW to the Python interpreter."
            )
            raise RawSocketPermissionError(msg) from exc

    @contextmanager
    def use_socket(self) -> socket.socket:
        if self._sock is None:
            self._sock = self._create_socket()
        try:
            yield self._sock
        finally:
            if self._sock:
                self._sock.close()
            self._sock = None

    # ------------- Checksum -------------

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return (~total) & 0xFFFF

    # ------------- Construção e parsing -------------

    def _build_echo_request(
        self, seq: int, payload: bytes | None
    ) -> tuple[bytes, ICMPPacket]:
        # payload inclui timestamp (8 bytes) + carga extra (opcional)
        send_ts = time.monotonic()
        ts_bytes = struct.pack("!d", send_ts)
        body = ts_bytes + (payload or b"")
        header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, self._identifier, seq)
        csum = self._checksum(header + body)
        header = struct.pack(
            "!BBHHH", ICMP_ECHO_REQUEST, 0, csum, self._identifier, seq
        )
        packet_bytes = header + body
        icmp = ICMPPacket(
            id=self._identifier,
            type=ICMP_ECHO_REQUEST,
            code=0,
            checksum=csum,
            sequence=seq,
            payload=payload or b"",
        )
        return packet_bytes, icmp

    def _parse_ip_icmp(self, raw: bytes, received_at: float) -> ReceivedPacket:
        if len(raw) < 20:
            raise ValueError("Datagrama menor que o cabeçalho mínimo de IP (20 bytes).")
        iph = struct.unpack("!BBHHHBBH4s4s", raw[:20])
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0x0F
        ip_header_len = ihl * 4
        if version != 4 or ihl < 5:
            raise ValueError("Cabeçalho IP inválido (versão ou IHL).")
        if len(raw) < ip_header_len + 8:
            raise ValueError("Datagrama menor que IP(IHL) + cabeçalho ICMP (8 bytes).")
        tos = iph[1]
        total_length = iph[2]
        ip_id = iph[3]
        flags_fragment = iph[4]
        flags = flags_fragment >> 13
        fragment_offset = flags_fragment & 0x1FFF
        ttl = iph[5]
        protocol = iph[6]
        ip_checksum = iph[7]
        src_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])

        # Limitar ICMP ao total_length quando possível
        icmp_end = total_length if 0 < total_length <= len(raw) else len(raw)
        icmp_segment = raw[ip_header_len:icmp_end]
        if len(icmp_segment) < 8:
            raise ValueError("Segmento ICMP menor que 8 bytes.")

        icmp_header = icmp_segment[:8]
        icmp_payload = icmp_segment[8:]
        t, c, recv_csum, pid, seq = struct.unpack("!BBHHH", icmp_header)

        # Validar checksum ICMP (recalcular com campo checksum zerado)
        zeroed = struct.pack("!BBHHH", t, c, 0, pid, seq) + icmp_payload
        calc = self._checksum(zeroed)
        if calc != recv_csum:
            raise ValueError("Checksum ICMP inválido.")

        ip = IPHeader(
            id=ip_id,
            version=version,
            ihl=ihl,
            tos=tos,
            total_length=total_length,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=ip_checksum,
            src_addr=src_addr,
            dest_addr=dest_addr,
        )
        icmp = ICMPPacket(
            id=pid,
            type=t,
            code=c,
            checksum=recv_csum,
            sequence=seq,
            payload=icmp_payload,
        )
        return ReceivedPacket(
            ip_header=ip, icmp_packet=icmp, raw=raw, received_at=received_at
        )

    @staticmethod
    def _extract_inner_echo_id_seq(icmp_payload: bytes) -> tuple[int, int] | None:
        # Em mensagens de erro, o payload contém: cabeçalho IP original (IHL variável)
        # seguido dos 8 bytes iniciais do datagrama original (cabeçalho ICMP Echo).
        if len(icmp_payload) < 28:  # 20 (IP min) + 8 (ICMP min)
            return None
        # Primeiro byte do IP interno
        inner_vihl = icmp_payload[0]
        inner_ihl = inner_vihl & 0x0F
        inner_ip_len = inner_ihl * 4
        if inner_ip_len < 20 or len(icmp_payload) < inner_ip_len + 8:
            return None
        inner_icmp_hdr = icmp_payload[inner_ip_len : inner_ip_len + 8]
        try:
            inner_type, _, _, inner_id, inner_seq = struct.unpack(
                "!BBHHH", inner_icmp_hdr
            )
        except struct.error:
            return None
        if inner_type != ICMP_ECHO_REQUEST:
            return None
        return inner_id, inner_seq

    def _match_probe(self, ident: int, seq: int, pkt: ICMPPacket) -> bool:
        if pkt.type == ICMP_ECHO_REPLY and pkt.id == ident and pkt.sequence == seq:
            return True
        if pkt.type in (
            ICMP_TIME_EXCEEDED,
            ICMP_DEST_UNREACHABLE,
            ICMP_PARAMETER_PROBLEM,
            ICMP_REDIRECT,
        ):
            inner = self._extract_inner_echo_id_seq(pkt.payload)
            return inner == (ident, seq)
        return False

    # ------------- Envio/Recepção -------------

    def _send(self, addr: str, ttl: int, payload: bytes | None) -> SentPacket:
        if self._sock is None:
            raise RuntimeError("Socket não inicializado. Use 'use_socket' primeiro.")
        self._next_sequence = (self._next_sequence + 1) & 0xFFFF
        raw_bytes, icmp = self._build_echo_request(self._next_sequence, payload)
        # TTL
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        # Timestamp já está em payload; também registrar no SentPacket
        ts = time.monotonic()
        self._sock.sendto(raw_bytes, (addr, 0))
        return SentPacket(packet=icmp, raw=raw_bytes, timestamp=ts, addr=addr, ttl=ttl)

    def _receive(self, ident: int, seq: int, timeout: float) -> ReceivedPacket | None:
        if self._sock is None:
            raise RuntimeError("Socket não inicializado. Use 'use_socket' primeiro.")
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([self._sock], [], [], remaining)
            if not ready:
                return None
            recv_at = time.monotonic()
            raw, _ = self._sock.recvfrom(65535)
            try:
                pkt = self._parse_ip_icmp(raw, recv_at)
            except ValueError as exc:
                logger.debug(f"Descartando pacote inválido: {exc}")
                continue
            if self._match_probe(ident, seq, pkt.icmp_packet):
                return pkt

    # ------------- Alto nível: probe/ping/traceroute -------------

    def probe(
        self,
        target: str,
        ttl: int | None = None,
        timeout: float | None = None,
        payload_size: int = 0,
        resolve_dns: bool | None = None,
    ) -> EchoResult:
        addr = target if self.valid_ip(target) else self.resolve_host(target)
        do_dns = self.resolve_dns_default if resolve_dns is None else resolve_dns
        ttl_val = ttl or self.default_ttl
        timeout_val = timeout if timeout is not None else self.timeout
        payload = b"\x00" * max(0, payload_size)

        with self.use_socket():
            sent = self._send(addr, ttl_val, payload)
            rcv = self._receive(self._identifier, sent.packet.sequence, timeout_val)
        hostname = self.reverse_dns(addr) if do_dns else None
        request = EchoRequest(
            addr=addr, hostname=hostname, ttl=ttl_val, sent_packet=sent
        )

        if rcv is None:
            return EchoResult(
                request=request,
                reply=EchoReply(rtt=float("inf"), received_packet=None),
                error="timeout",
            )

        # Calcular RTT em ms usando monotonic
        rtt_ms = (rcv.received_at - sent.timestamp) * 1000.0

        error_str: str | None = None
        t = rcv.icmp_packet.type
        c = rcv.icmp_packet.code
        if t == ICMP_ECHO_REPLY:
            error_str = None
        elif t == ICMP_TIME_EXCEEDED:
            error_str = f"time_exceeded(code={c})"
        elif t == ICMP_DEST_UNREACHABLE:
            error_str = f"dest_unreachable(code={c})"
        elif t == ICMP_PARAMETER_PROBLEM:
            error_str = f"parameter_problem(code={c})"
        elif t == ICMP_REDIRECT:
            error_str = f"redirect(code={c})"
        else:
            error_str = f"icmp_type_{t}_code_{c}"

        return EchoResult(
            request=request,
            reply=EchoReply(rtt=rtt_ms, received_packet=rcv),
            error=error_str,
        )

    def ping(
        self,
        target: str,
        count: int = 4,
        interval: float = 1.0,
        timeout: float | None = None,
        size: int = 0,
        resolve_dns: bool | None = None,
    ) -> list[EchoResult]:
        addr = target if self.valid_ip(target) else self.resolve_host(target)
        do_dns = self.resolve_dns_default if resolve_dns is None else resolve_dns
        timeout_val = timeout if timeout is not None else self.timeout
        results: list[EchoResult] = []

        with self.use_socket():
            for i in range(count):
                start = time.monotonic()
                sent = self._send(addr, self.default_ttl, b"\x00" * max(0, size))
                rcv = self._receive(self._identifier, sent.packet.sequence, timeout_val)
                hostname = self.reverse_dns(addr) if do_dns else None
                request = EchoRequest(
                    addr=addr, hostname=hostname, ttl=self.default_ttl, sent_packet=sent
                )
                if rcv is None:
                    results.append(
                        EchoResult(
                            request=request,
                            reply=EchoReply(rtt=float("inf"), received_packet=None),
                            error="timeout",
                        )
                    )
                else:
                    rtt_ms = (rcv.received_at - sent.timestamp) * 1000.0
                    t = rcv.icmp_packet.type
                    c = rcv.icmp_packet.code
                    if t == ICMP_ECHO_REPLY:
                        err = None
                    elif t == ICMP_TIME_EXCEEDED:
                        err = f"time_exceeded(code={c})"
                    elif t == ICMP_DEST_UNREACHABLE:
                        err = f"dest_unreachable(code={c})"
                    else:
                        err = f"icmp_type_{t}_code_{c}"
                    results.append(
                        EchoResult(
                            request=request,
                            reply=EchoReply(rtt=rtt_ms, received_packet=rcv),
                            error=err,
                        )
                    )
                # Respeitar o intervalo entre envios
                elapsed = time.monotonic() - start
                sleep_left = interval - elapsed
                if sleep_left > 0 and i != count - 1:
                    time.sleep(sleep_left)
        return results

    def traceroute(
        self,
        target: str,
        max_hops: int = 30,
        probes: int = 3,
        timeout: float | None = None,
        resolve_dns: bool | None = None,
        size: int = 0,
    ) -> TracerouteResult:
        resolved = target if self.valid_ip(target) else self.resolve_host(target)
        do_dns = self.resolve_dns_default if resolve_dns is None else resolve_dns
        timeout_val = timeout if timeout is not None else self.timeout

        hops: list[TracerouteEntry] = []
        reached = False

        with self.use_socket():
            for ttl in range(1, max_hops + 1):
                per_hop_replies: list[EchoReply] = []
                hop_addr: str | None = None
                hop_host: str | None = None

                for _ in range(probes):
                    sent = self._send(resolved, ttl, b"\x00" * max(0, size))
                    rcv = self._receive(
                        self._identifier, sent.packet.sequence, timeout_val
                    )
                    if rcv is None:
                        per_hop_replies.append(
                            EchoReply(rtt=float("inf"), received_packet=None)
                        )
                        continue

                    rtt_ms = (rcv.received_at - sent.timestamp) * 1000.0
                    per_hop_replies.append(EchoReply(rtt=rtt_ms, received_packet=rcv))
                    # Fixar endereço do roteador deste hop
                    if hop_addr is None:
                        hop_addr = rcv.ip_header.src_addr
                        hop_host = self.reverse_dns(hop_addr) if do_dns else None
                    # Verificar se destino foi alcançado
                    if (
                        rcv.icmp_packet.type == ICMP_ECHO_REPLY
                        and rcv.ip_header.src_addr == resolved
                    ):
                        reached = True

                hops.append(
                    TracerouteEntry(
                        ttl=ttl,
                        probes=per_hop_replies,
                        addr=hop_addr,
                        hostname=hop_host,
                    )
                )
                if reached:
                    break

        return TracerouteResult(target=target, resolved=resolved, hops=hops)


class AsyncClient(Client):
    # Placeholder para futura implementação assíncrona
    pass
