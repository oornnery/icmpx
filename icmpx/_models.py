from dataclasses import dataclass


@dataclass
class ICMPPacket:
    id: int
    type: int
    code: int
    checksum: int
    sequence: int
    payload: bytes


@dataclass
class IPHeader:
    id: int
    version: int
    ihl: int
    tos: int
    total_length: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_addr: str
    dest_addr: str


@dataclass
class SentPacket:
    packet: ICMPPacket
    raw: bytes
    timestamp: float  # monotonic
    addr: str
    ttl: int


@dataclass
class ReceivedPacket:
    ip_header: IPHeader
    icmp_packet: ICMPPacket
    raw: bytes
    received_at: float  # monotonic


@dataclass
class EchoRequest:
    addr: str
    hostname: str | None
    ttl: int
    sent_packet: SentPacket


@dataclass
class EchoReply:
    rtt: float  # em ms
    received_packet: ReceivedPacket | None


@dataclass
class EchoResult:
    request: EchoRequest
    reply: EchoReply
    error: str | None

    def __str__(self) -> str:
        if self.error:
            return f"EchoResult(to={self.request.addr}, error={self.error})"
        elif self.reply.received_packet is None:
            return f"EchoResult(to={self.request.addr}, timeout)"
        else:
            rcv = self.reply.received_packet
            return (
                f"EchoResult(to={self.request.addr}, from={rcv.ip_header.src_addr}, "
                f"rtt={self.reply.rtt:.2f} ms, type={rcv.icmp_packet.type}, code={rcv.icmp_packet.code})"
            )


@dataclass
class TracerouteEntry:
    ttl: int
    probes: list[EchoReply]
    addr: str | None
    hostname: str | None


@dataclass
class TracerouteResult:
    target: str
    resolved: str
    hops: list[TracerouteEntry]

    def __str__(self) -> str:
        lines = [
            f"Traceroute to {self.target} ({self.resolved}), {len(self.hops)} hops"
        ]
        header = f"{'Hop':<4} {'Address':<20} {'Hostname':<40} {'Probe Times (ms)':>20}"
        lines.append(header)

        for hop in self.hops:
            address = hop.addr or "?"
            hostname = hop.hostname or "?"
            values: list[str] = []
            for probe in hop.probes:
                if probe.rtt != float("inf"):
                    values.append(f"{probe.rtt:.2f} ms")
                elif probe.received_packet is None:
                    values.append("*")
                else:
                    t = probe.received_packet.icmp_packet.type
                    c = probe.received_packet.icmp_packet.code
                    values.append(f"icmp_{t}_code_{c}")
            while len(values) < 3:
                values.append("*")
            lines.append(
                f"{hop.ttl:<4} {address:<20} {hostname:<40} {' '.join(values):>20}"
            )

        return "\n".join(lines) + "\n"
