"""
Internal Asynchronous Event Bus and Network Telemetry Event Definitions.
"""
from __future__ import annotations
import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Any, Optional
from netsphere.core.types import PacketDirection


@dataclass
class Event:
    """Base network event object."""
    event_type: str
    timestamp: float = field(default_factory=time.time)
    source: str = "netsphere"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PacketReceivedEvent(Event):
    """Triggered when an interface receives a packet."""
    interface_name: str = ""
    direction: PacketDirection = PacketDirection.INGRESS
    packet_length: int = 0
    protocol: str = ""
    summary: str = ""


@dataclass
class PacketDroppedEvent(Event):
    """Triggered when a packet is dropped due to buffer overflow, TTL, or firewall rule."""
    interface_name: str = ""
    reason: str = ""
    packet_length: int = 0


@dataclass
class InterfaceStateChangeEvent(Event):
    """Triggered when an interface goes up, down, or changes duplex/speed."""
    interface_name: str = ""
    old_state: str = ""
    new_state: str = ""


@dataclass
class RouteAddedEvent(Event):
    """Triggered when routing table adds a new prefix."""
    prefix: str = ""
    next_hop: str = ""
    metric: int = 0


@dataclass
class AnomalyAlertEvent(Event):
    """Triggered when traffic analysis detects a network security threat."""
    threat_type: str = ""
    severity: str = "HIGH"
    target_ip: str = ""
    description: str = ""


class EventBus:
    """
    Thread-safe synchronous and asynchronous event dispatching bus.
    """
    def __init__(self, max_history: int = 1000):
        self._listeners: Dict[str, List[Callable[[Event], None]]] = {}
        self._lock = threading.Lock()
        self._history: List[Event] = []
        self._max_history = max_history

    def subscribe(self, event_type: str, callback: Callable[[Event], None]) -> None:
        """Subscribe a callable to a specific event type, or '*' for all events."""
        with self._lock:
            if event_type not in self._listeners:
                self._listeners[event_type] = []
            self._listeners[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable[[Event], None]) -> None:
        with self._lock:
            if event_type in self._listeners and callback in self._listeners[event_type]:
                self._listeners[event_type].remove(callback)

    def publish(self, event: Event) -> None:
        """Dispatch event synchronously to all registered subscribers."""
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history.pop(0)

            # Targeted listeners
            callbacks = list(self._listeners.get(event.event_type, []))
            # Wildcard listeners
            wildcard_callbacks = list(self._listeners.get("*", []))

        for cb in callbacks + wildcard_callbacks:
            try:
                cb(event)
            except Exception as e:
                # Event dispatch should not crash publisher
                print(f"[EventBus] Error in callback {cb}: {e}")

    def get_history(self, limit: Optional[int] = None) -> List[Event]:
        with self._lock:
            if limit is None:
                return list(self._history)
            return list(self._history[-limit:])

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()


# Default singleton instance for global event bus
global_event_bus = EventBus()
