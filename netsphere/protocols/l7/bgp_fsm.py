"""
NetSphere BGP-4 Finite State Machine (RFC 4271).
Implements the 6-state peering lifecycle (IDLE, CONNECT, ACTIVE, OPENSENT, OPENCONFIRM, ESTABLISHED)
with event transitions, keepalive, and hold timers.
"""
from __future__ import annotations
import enum
import time
from typing import Optional, List, Dict, Any


class BGPState(enum.Enum):
    IDLE = "IDLE"
    CONNECT = "CONNECT"
    ACTIVE = "ACTIVE"
    OPENSENT = "OPENSENT"
    OPENCONFIRM = "OPENCONFIRM"
    ESTABLISHED = "ESTABLISHED"


class BGPEvent(enum.Enum):
    MANUAL_START = "ManualStart"
    MANUAL_STOP = "ManualStop"
    CONNECT_RETRY_TIMER_EXPIRED = "ConnectRetryTimer_Expires"
    HOLD_TIMER_EXPIRED = "HoldTimer_Expires"
    KEEPALIVE_TIMER_EXPIRED = "KeepaliveTimer_Expires"
    TCP_CONNECTION_CONFIRMED = "TcpConnection_Confirmed"
    TCP_CONNECTION_FAILS = "TcpConnectionFails"
    BGP_OPEN_RECEIVED = "BGPOpen"
    BGP_HEADER_ERR = "BGPHeaderErr"
    BGP_OPEN_MSG_ERR = "BGPOpenMsgErr"
    BGP_KEEPALIVE_RECEIVED = "KeepaliveMsg"
    BGP_UPDATE_RECEIVED = "UpdateMsg"
    NOTIFICATION_RECEIVED = "NotificationMessage"


class BGPPeerSession:
    """Represents a BGP-4 Peering Session with state machine."""
    def __init__(self, peer_ip: str, remote_as: int, local_as: int, hold_time: int = 90):
        self.peer_ip = peer_ip
        self.remote_as = remote_as
        self.local_as = local_as
        self.hold_time = hold_time
        self.keepalive_time = hold_time // 3
        self.state: BGPState = BGPState.IDLE
        self.routes_received: List[str] = []
        self.routes_advertised: List[str] = []
        self.last_keepalive: float = 0.0

    def process_event(self, event: BGPEvent) -> BGPState:
        """Advance BGP state machine based on RFC 4271 transition table."""
        prev = self.state

        if self.state == BGPState.IDLE:
            if event == BGPEvent.MANUAL_START:
                self.state = BGPState.CONNECT

        elif self.state == BGPState.CONNECT:
            if event == BGPEvent.TCP_CONNECTION_CONFIRMED:
                self.state = BGPState.OPENSENT
            elif event in (BGPEvent.TCP_CONNECTION_FAILS, BGPEvent.CONNECT_RETRY_TIMER_EXPIRED):
                self.state = BGPState.ACTIVE
            elif event == BGPEvent.MANUAL_STOP:
                self.state = BGPState.IDLE

        elif self.state == BGPState.ACTIVE:
            if event == BGPEvent.TCP_CONNECTION_CONFIRMED:
                self.state = BGPState.OPENSENT
            elif event == BGPEvent.CONNECT_RETRY_TIMER_EXPIRED:
                self.state = BGPState.CONNECT
            elif event == BGPEvent.MANUAL_STOP:
                self.state = BGPState.IDLE

        elif self.state == BGPState.OPENSENT:
            if event == BGPEvent.BGP_OPEN_RECEIVED:
                self.state = BGPState.OPENCONFIRM
                self.last_keepalive = time.time()
            elif event in (BGPEvent.TCP_CONNECTION_FAILS, BGPEvent.NOTIFICATION_RECEIVED, BGPEvent.HOLD_TIMER_EXPIRED):
                self.state = BGPState.IDLE

        elif self.state == BGPState.OPENCONFIRM:
            if event == BGPEvent.BGP_KEEPALIVE_RECEIVED:
                self.state = BGPState.ESTABLISHED
                self.last_keepalive = time.time()
            elif event in (BGPEvent.NOTIFICATION_RECEIVED, BGPEvent.HOLD_TIMER_EXPIRED):
                self.state = BGPState.IDLE

        elif self.state == BGPState.ESTABLISHED:
            if event == BGPEvent.BGP_KEEPALIVE_RECEIVED:
                self.last_keepalive = time.time()
            elif event == BGPEvent.BGP_UPDATE_RECEIVED:
                self.last_keepalive = time.time()
            elif event in (BGPEvent.MANUAL_STOP, BGPEvent.HOLD_TIMER_EXPIRED, BGPEvent.NOTIFICATION_RECEIVED):
                self.state = BGPState.IDLE

        return self.state

    def add_route(self, prefix: str):
        if prefix not in self.routes_received:
            self.routes_received.append(prefix)
