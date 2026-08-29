"""
Alert Management Rules Engine and Notification Dispatcher.
"""
from __future__ import annotations
import enum
import time
from dataclasses import dataclass
from typing import List, Callable, Dict, Optional


class AlertSeverity(enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class AlertRule:
    rule_id: str
    name: str
    severity: AlertSeverity
    metric_name: str
    threshold: float
    comparison: str  # ">", "<", "=="


class AlertManager:
    """
    Evaluates telemetry metric values against defined alerting rules.
    """
    def __init__(self):
        self.rules: List[AlertRule] = []
        self.active_alerts: List[Dict] = []

    def add_rule(self, rule: AlertRule):
        self.rules.append(rule)

    def evaluate(self, metrics: Dict[str, float]) -> List[Dict]:
        triggered = []
        now = time.time()

        for rule in self.rules:
            if rule.metric_name in metrics:
                val = metrics[rule.metric_name]
                is_hit = False
                if rule.comparison == ">" and val > rule.threshold:
                    is_hit = True
                elif rule.comparison == "<" and val < rule.threshold:
                    is_hit = True
                elif rule.comparison == "==" and val == rule.threshold:
                    is_hit = True

                if is_hit:
                    item = {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "severity": rule.severity.value,
                        "value": val,
                        "threshold": rule.threshold,
                        "timestamp": now,
                    }
                    triggered.append(item)
                    self.active_alerts.append(item)

        return triggered
