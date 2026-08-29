"""
TCP Finite State Machine (RFC 793) and Round-Trip Time (RTT) Estimation (RFC 6298).
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import Optional, List, Dict
from netsphere.protocols.l4.tcp import TCPHeader, TCPFlags


class TCPState(enum.Enum):
    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RCVD = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"


class RTTTracker:
    """
    Jacobson / Karels Algorithm for RTT & Retransmission Timeout (RTO) Estimation (RFC 6298):
    SRTT = (1 - alpha) * SRTT + alpha * R' (alpha = 1/8)
    RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'| (beta = 1/4)
    RTO = SRTT + max(G, 4 * RTTVAR)
    """
    def __init__(self, initial_rto: float = 1.0, min_rto: float = 0.2, max_rto: float = 60.0):
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.rto: float = initial_rto
        self.min_rto = min_rto
        self.max_rto = max_rto
        self.alpha = 0.125
        self.beta = 0.25

    def update(self, measured_rtt: float) -> None:
        if self.srtt is None:
            # First measurement
            self.srtt = measured_rtt
            self.rttvar = measured_rtt / 2.0
            self.rto = self.srtt + max(0.01, 4.0 * self.rttvar)
        else:
            diff = abs(self.srtt - measured_rtt)
            self.rttvar = (1.0 - self.beta) * self.rttvar + self.beta * diff
            self.srtt = (1.0 - self.alpha) * self.srtt + self.alpha * measured_rtt
            self.rto = self.srtt + max(0.01, 4.0 * self.rttvar)

        # Clamp RTO
        self.rto = max(self.min_rto, min(self.rto, self.max_rto))

    def backoff(self) -> None:
        """Exponential backoff upon retransmission timeout."""
        self.rto = min(self.rto * 2.0, self.max_rto)


class TCPConnection:
    """
    Manages TCP connection state, sequence numbers, and transitions.
    """
    def __init__(self, local_port: int, remote_port: int, initial_seq: int = 1000):
        self.local_port = local_port
        self.remote_port = remote_port
        self.state: TCPState = TCPState.CLOSED
        self.snd_una: int = initial_seq     # Oldest unacknowledged sequence number
        self.snd_nxt: int = initial_seq     # Next sequence number to send
        self.snd_wnd: int = 65535           # Send window
        self.rcv_nxt: int = 0               # Next expected receive sequence number
        self.rcv_wnd: int = 65535           # Receive window
        self.rtt_tracker = RTTTracker()
        self.duplicate_acks: int = 0
        self.last_ack_received: int = 0

    def handle_segment(self, header: TCPHeader, payload_len: int = 0) -> Optional[TCPHeader]:
        """
        Process an incoming TCP segment according to RFC 793 state machine.
        Returns a response TCPHeader if an immediate reply is required.
        """
        # Active OPEN (SYN_SENT)
        if self.state == TCPState.SYN_SENT:
            if header.flags.syn and header.flags.ack:
                self.rcv_nxt = header.seq_num + 1
                self.snd_una = header.ack_num
                self.state = TCPState.ESTABLISHED
                # Return ACK to complete 3-way handshake
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )
            elif header.flags.syn:
                # Simultaneous open
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.SYN_RCVD
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(syn=True, ack=True),
                )

        # Passive LISTEN
        elif self.state == TCPState.LISTEN:
            if header.flags.syn:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.SYN_RCVD
                resp = TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(syn=True, ack=True),
                )
                self.snd_nxt += 1
                return resp

        # SYN_RCVD
        elif self.state == TCPState.SYN_RCVD:
            if header.flags.ack:
                self.snd_una = header.ack_num
                self.state = TCPState.ESTABLISHED

        # ESTABLISHED
        elif self.state == TCPState.ESTABLISHED:
            if header.flags.fin:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.CLOSE_WAIT
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )
            elif payload_len > 0:
                self.rcv_nxt = header.seq_num + payload_len
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )

        # FIN_WAIT_1
        elif self.state == TCPState.FIN_WAIT_1:
            if header.flags.fin and header.flags.ack:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.TIME_WAIT
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )
            elif header.flags.ack:
                self.state = TCPState.FIN_WAIT_2

        # FIN_WAIT_2
        elif self.state == TCPState.FIN_WAIT_2:
            if header.flags.fin:
                self.rcv_nxt = header.seq_num + 1
                self.state = TCPState.TIME_WAIT
                return TCPHeader(
                    src_port=header.dst_port,
                    dst_port=header.src_port,
                    seq_num=self.snd_nxt,
                    ack_num=self.rcv_nxt,
                    flags=TCPFlags(ack=True),
                )

        # LAST_ACK
        elif self.state == TCPState.LAST_ACK:
            if header.flags.ack:
                self.state = TCPState.CLOSED

        return None
