"""Render findings as a human-readable text report or as JSON.

Formatting lives here, apart from detection, so the same findings can feed
a terminal, a JSON pipeline (SIEM, Slack bot, ticketing) or a test assertion.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from typing import List, Sequence

from .detectors import SEVERITY_ORDER, Finding
from .parser import ACCEPTED, FAILED, LoginEvent

RULE = "=" * 72


def build_stats(events: Sequence[LoginEvent]) -> dict:
    """Headline numbers that give context before the findings list."""
    failed = [e for e in events if e.outcome == FAILED]
    accepted = [e for e in events if e.outcome == ACCEPTED]
    return {
        "total_events": len(events),
        "failed": len(failed),
        "accepted": len(accepted),
        "unique_ips": len({e.ip for e in events}),
        "top_failing_ips": Counter(e.ip for e in failed).most_common(5),
        "top_targeted_users": Counter(e.user for e in failed).most_common(5),
        "first_event": min((e.timestamp for e in events), default=None),
        "last_event": max((e.timestamp for e in events), default=None),
    }


def render_text(findings: List[Finding], events: Sequence[LoginEvent], source: str) -> str:
    stats = build_stats(events)
    lines = [RULE, f" LogiLog: SSH auth log report for {source}", RULE]

    if stats["first_event"]:
        lines.append(f" Time range : {stats['first_event']} -> {stats['last_event']}")
    lines += [
        f" Events     : {stats['total_events']} login attempts "
        f"({stats['failed']} failed, {stats['accepted']} successful)",
        f" Unique IPs : {stats['unique_ips']}",
    ]

    severity_counts = Counter(f.severity for f in findings)
    summary = ", ".join(
        f"{severity_counts[s]} {s}" for s in SEVERITY_ORDER if severity_counts[s]
    ) or "none"
    lines.append(f" Findings   : {len(findings)} ({summary})")

    if stats["top_failing_ips"]:
        lines += ["", " Top failing IPs:"]
        lines += [f"   {ip:<40} {n:>5} failed" for ip, n in stats["top_failing_ips"]]
    if stats["top_targeted_users"]:
        lines += ["", " Most targeted usernames:"]
        lines += [f"   {user:<40} {n:>5} failed" for user, n in stats["top_targeted_users"]]

    lines += ["", RULE, " FINDINGS (most severe first)", RULE]
    if not findings:
        lines.append(" No suspicious activity detected with the current thresholds.")

    for i, f in enumerate(findings, 1):
        lines += [
            "",
            f" [{i}] {f.severity:<8} {f.category}  |  IP {f.ip}",
            f"     {f.description}",
            f"     When : {f.first_seen}" + (f" -> {f.last_seen}" if f.last_seen != f.first_seen else ""),
        ]
        if f.users:
            shown = ", ".join(f.users[:8]) + (f" (+{len(f.users) - 8} more)" if len(f.users) > 8 else "")
            lines.append(f"     Users: {shown}")
        lines.append("     Evidence:")
        lines += [f"       | {raw}" for raw in f.evidence]

    lines.append("")
    return "\n".join(lines)


def render_json(findings: List[Finding], events: Sequence[LoginEvent], source: str) -> str:
    stats = build_stats(events)
    payload = {
        "source": source,
        "stats": stats,
        "findings": [asdict(f) for f in findings],
    }
    # default=str turns datetimes into ISO-ish strings instead of crashing.
    return json.dumps(payload, indent=2, default=str)
