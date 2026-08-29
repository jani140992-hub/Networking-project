"""
The Syslog Protocol (RFC 5424 / RFC 3164).
"""
from __future__ import annotations
import enum
import time


class SyslogFacility(enum.IntEnum):
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(enum.IntEnum):
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


class SyslogMessage:
    """RFC 5424 Syslog Message."""
    def __init__(
        self,
        facility: SyslogFacility = SyslogFacility.DAEMON,
        severity: SyslogSeverity = SyslogSeverity.INFORMATIONAL,
        hostname: str = "netsphere-core",
        app_name: str = "netsphere",
        proc_id: str = "-",
        msg_id: str = "-",
        message: str = "System operational",
    ):
        self.facility = facility
        self.severity = severity
        self.hostname = hostname
        self.app_name = app_name
        self.proc_id = proc_id
        self.msg_id = msg_id
        self.message = message

    @property
    def priority(self) -> int:
        return (int(self.facility) * 8) + int(self.severity)

    def pack(self) -> bytes:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Format: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG
        line = f"<{self.priority}>1 {ts} {self.hostname} {self.app_name} {self.proc_id} {self.msg_id} - {self.message}"
        return line.encode("utf-8")
