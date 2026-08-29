"""
Internal Thread-Safe Pub/Sub Event Bus for Server & Telemetry Synchronization.
"""
from __future__ import annotations
import queue
import threading
from typing import Callable, Dict, List, Any


class MessageBus:
    """Thread-safe synchronous and asynchronous pub/sub broker."""
    def __init__(self):
        self.subscribers: Dict[str, List[Callable[[dict], None]]] = {}
        self._lock = threading.Lock()

    def subscribe(self, topic: str, callback: Callable[[dict], None]):
        with self._lock:
            if topic not in self.subscribers:
                self.subscribers[topic] = []
            self.subscribers[topic].append(callback)

    def publish(self, topic: str, message: dict):
        with self._lock:
            callbacks = list(self.subscribers.get(topic, []))
            wildcards = list(self.subscribers.get("*", []))

        for cb in callbacks + wildcards:
            try:
                cb(message)
            except Exception:
                pass
