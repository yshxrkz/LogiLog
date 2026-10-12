"""Turn raw auth.log lines into structured LoginEvent objects.

Detection logic never touches raw text: everything downstream works on
LoginEvent. Keeping parsing separate means supporting a new log format
only requires changes here, and the detectors can be tested with
hand-built events instead of log strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional

# Event outcomes. Plain string constants keep the report and JSON output readable.
FAILED = "failed"
ACCEPTED = "accepted"


@dataclass(frozen=True)
class LoginEvent:
    """One SSH authentication attempt pulled out of the log."""

    timestamp: datetime
    outcome: str          # FAILED or ACCEPTED
    user: str
    ip: str
    method: str           # "password", "publickey", ...
    invalid_user: bool    # True when sshd said the account doesn't exist
    raw: str              # original line, kept so findings can show evidence


# --- Timestamp prefixes ------------------------------------------------------
# Classic syslog, e.g. "Oct 12 03:14:15 web01 sshd[1234]: ..."
# Note: there is NO year in this format, so the caller has to supply one.
SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
# Newer rsyslog / journald style, e.g. "2026-10-12T03:14:15.123456+00:00 web01 sshd[1234]: ..."
ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)

# --- sshd message bodies ------------------------------------------------------
# "Failed password for root from 1.2.3.4 port 22 ssh2"
# "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
# "Accepted publickey for alice from 1.2.3.4 port 50000 ssh2: RSA SHA256:..."
# The IP group accepts IPv4 and IPv6 (hex digits, dots and colons).
AUTH_MESSAGE = re.compile(
    r"^(?P<outcome>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9A-Fa-f:.]+)\s+port\s+\d+"
)
# "Invalid user admin from 1.2.3.4 port 22" is logged *before* the
# "Failed password" line for the same attempt. We deliberately ignore it so
# a single attempt is not counted twice.


def parse_line(line: str, year: int) -> Optional[LoginEvent]:
    """Parse one log line. Returns None for anything that isn't a login result.

    Real auth.log files are full of unrelated noise (sudo, cron, PAM session
    messages, disconnects), so "not interesting" is the normal case, not an error.
    """
    line = line.rstrip("\n")

    match = SYSLOG_PREFIX.match(line)
    if match:
        # Syslog has no year; strptime would default to 1900, so we inject one.
        # Leading spaces in "Oct  2" are collapsed so the format string matches.
        ts_text = " ".join(match.group("ts").split())
        timestamp = datetime.strptime(f"{year} {ts_text}", "%Y %b %d %H:%M:%S")
    else:
        match = ISO_PREFIX.match(line)
        if not match:
            return None
        # Timezone suffix is dropped on purpose: all comparisons are within one
        # file from one host, so naive local timestamps are consistent.
        timestamp = datetime.strptime(match.group("ts"), "%Y-%m-%dT%H:%M:%S")

    body = AUTH_MESSAGE.match(match.group("msg"))
    if not body:
        return None

    return LoginEvent(
        timestamp=timestamp,
        outcome=FAILED if body.group("outcome") == "Failed" else ACCEPTED,
        user=body.group("user"),
        ip=body.group("ip"),
        method=body.group("method"),
        invalid_user=body.group("invalid") is not None,
        raw=line,
    )


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> Iterator[LoginEvent]:
    """Lazily parse many lines, skipping the ones that aren't login events.

    Using a generator means a multi-gigabyte log is streamed line by line
    rather than loaded into memory all at once.
    """
    year = year or datetime.now().year
    previous: Optional[datetime] = None
    for line in lines:
        event = parse_line(line, year)
        if event is None:
            continue
        # Year rollover: syslog lines jump from "Dec 31" to "Jan 1" with no year.
        # If time appears to go backwards by months, we crossed New Year.
        if previous and event.timestamp < previous - timedelta(days=180):
            year += 1
            event = parse_line(line, year)
        previous = event.timestamp
        yield event
