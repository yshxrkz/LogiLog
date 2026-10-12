"""Detection rules. Each detector takes LoginEvents and returns Findings.

All three detectors are pure functions: no file I/O, no printing, no global
state. That makes them easy to unit-test and easy to reason about.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Sequence

from .parser import ACCEPTED, FAILED, LoginEvent

# Severity ordering lets the report sort the most urgent findings first.
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# How many raw log lines to attach to a finding as evidence.
MAX_EVIDENCE = 5


@dataclass
class Config:
    """Tunable thresholds. Defaults are deliberately conservative starting points."""

    # Brute force: this many failures from one IP inside window_minutes.
    failure_threshold: int = 5
    window_minutes: int = 10
    # Normal working hours (24h clock). Logins outside [start, end) are flagged.
    work_start_hour: int = 7
    work_end_hour: int = 20
    # Success-after-failures: this many failures from the same IP shortly before
    # an accepted login. Lower than the brute-force threshold on purpose:
    # even 3 failures followed by a success is worth a look.
    success_after_failures: int = 3


@dataclass
class Finding:
    """One suspicious thing worth a human looking at."""

    severity: str
    category: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    description: str
    users: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


# --- Detector 1: repeated failed logins from one IP --------------------------

def detect_brute_force(events: Sequence[LoginEvent], config: Config) -> List[Finding]:
    """Flag IPs with >= failure_threshold failures inside a sliding time window.

    Why a sliding window instead of a plain total? A total of 20 failures spread
    over a month is a user who keeps mistyping their password; 20 failures in
    60 seconds is a script. The window captures *rate*, which is what separates
    an attack from normal human error.

    Implementation: for each IP keep a deque of recent failure times. On each
    new failure, append it and pop timestamps older than the window off the
    left. The deque length is then "failures in the last N minutes". Each event
    is pushed and popped at most once, so this is O(n) overall.
    """
    window = timedelta(minutes=config.window_minutes)
    recent: Dict[str, Deque[datetime]] = defaultdict(deque)
    peak: Dict[str, int] = {}                       # worst burst seen per IP
    failures_by_ip: Dict[str, List[LoginEvent]] = defaultdict(list)

    for event in events:
        if event.outcome != FAILED:
            continue
        failures_by_ip[event.ip].append(event)

        times = recent[event.ip]
        times.append(event.timestamp)
        while times[0] < event.timestamp - window:
            times.popleft()
        peak[event.ip] = max(peak.get(event.ip, 0), len(times))

    findings = []
    for ip, burst in peak.items():
        if burst < config.failure_threshold:
            continue
        failures = failures_by_ip[ip]
        users = sorted({e.user for e in failures})
        invalid = sum(e.invalid_user for e in failures)

        # Escalate when the burst is far above threshold, or when the attacker
        # is cycling through many usernames (dictionary / password-spraying).
        severity = "HIGH" if burst >= 3 * config.failure_threshold or len(users) >= 5 else "MEDIUM"

        description = (
            f"{len(failures)} failed logins ({burst} within {config.window_minutes} min) "
            f"against {len(users)} account(s)"
        )
        if invalid:
            description += f"; {invalid} attempt(s) used non-existent usernames"

        findings.append(Finding(
            severity=severity,
            category="Brute force",
            ip=ip,
            first_seen=failures[0].timestamp,
            last_seen=failures[-1].timestamp,
            description=description,
            users=users,
            evidence=[e.raw for e in failures[:MAX_EVIDENCE]],
        ))
    return findings


# --- Detector 2: successful logins at unusual hours ---------------------------

def is_unusual_hour(ts: datetime, start_hour: int, end_hour: int) -> bool:
    """True if ts falls outside working hours [start_hour, end_hour).

    Also handles "overnight" shifts where start > end (e.g. 22 -> 6), so the
    rule works for a night-shift ops team too.
    """
    if start_hour <= end_hour:
        return not (start_hour <= ts.hour < end_hour)
    return end_hour <= ts.hour < start_hour


def detect_unusual_hours(events: Sequence[LoginEvent], config: Config) -> List[Finding]:
    """Flag *successful* logins outside normal working hours.

    Only successes are checked: a failed login at 3am is already covered by the
    brute-force rule, while a successful one means someone actually got in.
    On its own this is a weak signal (people do work late), so it is LOW,
    unless the account is root, which should rarely log in directly at all.
    """
    findings = []
    for event in events:
        if event.outcome != ACCEPTED:
            continue
        if not is_unusual_hour(event.timestamp, config.work_start_hour, config.work_end_hour):
            continue
        findings.append(Finding(
            severity="MEDIUM" if event.user == "root" else "LOW",
            category="Unusual hours",
            ip=event.ip,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            description=(
                f"Successful {event.method} login for '{event.user}' at "
                f"{event.timestamp:%H:%M} (outside {config.work_start_hour:02d}:00-"
                f"{config.work_end_hour:02d}:00)"
            ),
            users=[event.user],
            evidence=[event.raw],
        ))
    return findings


# --- Detector 3: success right after many failures ----------------------------

def detect_success_after_failures(events: Sequence[LoginEvent], config: Config) -> List[Finding]:
    """Flag an accepted login from an IP that recently failed several times.

    This is the most important rule: brute force alone means someone is
    *trying*; brute force followed by a success means they probably *got in*
    (guessed or stuffed a valid password). It is rated CRITICAL.

    Same sliding-window idea as detect_brute_force: keep recent failures per
    IP, and when a success arrives, count how many are still inside the window.
    Any success then resets that IP's history: a flagged login is reported
    once, and a user who mistyped once or twice before getting in starts clean.
    """
    window = timedelta(minutes=config.window_minutes)
    recent: Dict[str, Deque[LoginEvent]] = defaultdict(deque)
    findings = []

    for event in events:
        prior = recent[event.ip]
        while prior and prior[0].timestamp < event.timestamp - window:
            prior.popleft()

        if event.outcome == FAILED:
            prior.append(event)
            continue

        # event is an ACCEPTED login
        if len(prior) >= config.success_after_failures:
            targeted_same_user = any(f.user == event.user for f in prior)
            description = (
                f"Login as '{event.user}' succeeded after {len(prior)} failures from this IP "
                f"in the preceding {config.window_minutes} min"
            )
            if targeted_same_user:
                description += " (failures targeted the same account: likely password guessed)"
            findings.append(Finding(
                severity="CRITICAL",
                category="Success after failures",
                ip=event.ip,
                first_seen=prior[0].timestamp,
                last_seen=event.timestamp,
                description=description,
                users=sorted({f.user for f in prior} | {event.user}),
                # Show the last few failures plus the success itself.
                evidence=[f.raw for f in list(prior)[-(MAX_EVIDENCE - 1):]] + [event.raw],
            ))
        prior.clear()

    return findings


def analyze(events: Sequence[LoginEvent], config: Config | None = None) -> List[Finding]:
    """Run every detector and return findings, most severe first."""
    config = config or Config()
    # Sliding windows assume chronological order; sort defensively in case
    # several log files were concatenated out of order.
    events = sorted(events, key=lambda e: e.timestamp)

    findings = (
        detect_brute_force(events, config)
        + detect_unusual_hours(events, config)
        + detect_success_after_failures(events, config)
    )
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
    return findings
