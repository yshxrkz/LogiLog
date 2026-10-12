"""Detector tests use hand-built LoginEvents so each scenario is explicit."""

import unittest
from datetime import datetime, timedelta

from logilog.detectors import (
    Config,
    analyze,
    detect_brute_force,
    detect_success_after_failures,
    detect_unusual_hours,
    is_unusual_hour,
)
from logilog.parser import ACCEPTED, FAILED, LoginEvent

BASE = datetime(2026, 10, 11, 14, 0, 0)


def ev(outcome, seconds=0, ip="203.0.113.5", user="root", base=BASE, method="password"):
    """Build an event `seconds` after `base`."""
    ts = base + timedelta(seconds=seconds)
    return LoginEvent(ts, outcome, user, ip, method, False, f"{ts} {outcome} {user} {ip}")


def failures(n, spacing=5, start=0, **kw):
    return [ev(FAILED, start + i * spacing, **kw) for i in range(n)]


class BruteForceTests(unittest.TestCase):
    def test_burst_at_threshold_is_flagged(self):
        found = detect_brute_force(failures(5), Config(failure_threshold=5))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].ip, "203.0.113.5")
        self.assertEqual(found[0].severity, "MEDIUM")

    def test_below_threshold_is_not_flagged(self):
        self.assertEqual(detect_brute_force(failures(4), Config(failure_threshold=5)), [])

    def test_failures_spread_beyond_window_are_not_flagged(self):
        # 6 failures, one every 5 minutes: never 5 inside a 10-minute window.
        events = failures(6, spacing=300)
        self.assertEqual(detect_brute_force(events, Config(failure_threshold=5, window_minutes=10)), [])

    def test_failures_are_counted_per_ip(self):
        events = failures(3, ip="1.1.1.1") + failures(3, ip="2.2.2.2")
        self.assertEqual(detect_brute_force(events, Config(failure_threshold=5)), [])

    def test_one_finding_per_ip_even_with_many_bursts(self):
        events = failures(10) + failures(10, start=3600)
        self.assertEqual(len(detect_brute_force(events, Config())), 1)

    def test_large_burst_escalates_to_high(self):
        found = detect_brute_force(failures(15), Config(failure_threshold=5))
        self.assertEqual(found[0].severity, "HIGH")

    def test_many_usernames_escalates_to_high(self):
        events = [ev(FAILED, i, user=u) for i, u in enumerate(["a", "b", "c", "d", "e"])]
        found = detect_brute_force(events, Config(failure_threshold=5))
        self.assertEqual(found[0].severity, "HIGH")

    def test_successes_do_not_count_as_failures(self):
        events = [ev(ACCEPTED, i) for i in range(10)]
        self.assertEqual(detect_brute_force(events, Config()), [])


class UnusualHoursTests(unittest.TestCase):
    def test_hour_boundaries(self):
        day = datetime(2026, 10, 11)
        self.assertTrue(is_unusual_hour(day.replace(hour=6, minute=59), 7, 20))
        self.assertFalse(is_unusual_hour(day.replace(hour=7), 7, 20))
        self.assertFalse(is_unusual_hour(day.replace(hour=19, minute=59), 7, 20))
        self.assertTrue(is_unusual_hour(day.replace(hour=20), 7, 20))

    def test_overnight_shift(self):
        # Working hours 22:00-06:00: 23:00 is normal, noon is unusual.
        day = datetime(2026, 10, 11)
        self.assertFalse(is_unusual_hour(day.replace(hour=23), 22, 6))
        self.assertTrue(is_unusual_hour(day.replace(hour=12), 22, 6))

    def test_night_login_flagged(self):
        night = datetime(2026, 10, 11, 3, 0)
        found = detect_unusual_hours([ev(ACCEPTED, base=night, user="carol")], Config())
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "LOW")

    def test_root_at_night_is_medium(self):
        night = datetime(2026, 10, 11, 3, 0)
        found = detect_unusual_hours([ev(ACCEPTED, base=night, user="root")], Config())
        self.assertEqual(found[0].severity, "MEDIUM")

    def test_daytime_login_and_night_failure_not_flagged(self):
        night = datetime(2026, 10, 11, 3, 0)
        events = [ev(ACCEPTED), ev(FAILED, base=night)]
        self.assertEqual(detect_unusual_hours(events, Config()), [])


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_success_after_many_failures_is_critical(self):
        events = failures(5) + [ev(ACCEPTED, 60)]
        found = detect_success_after_failures(events, Config(success_after_failures=3))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "CRITICAL")
        self.assertIn("likely password guessed", found[0].description)
        # Evidence ends with the successful login line.
        self.assertIn(ACCEPTED, found[0].evidence[-1])

    def test_single_typo_then_success_is_fine(self):
        events = failures(1) + [ev(ACCEPTED, 10)]
        self.assertEqual(detect_success_after_failures(events, Config()), [])

    def test_success_from_different_ip_not_linked(self):
        events = failures(5, ip="203.0.113.5") + [ev(ACCEPTED, 60, ip="192.0.2.10")]
        self.assertEqual(detect_success_after_failures(events, Config()), [])

    def test_old_failures_outside_window_are_ignored(self):
        events = failures(5) + [ev(ACCEPTED, 3600)]
        self.assertEqual(detect_success_after_failures(events, Config(window_minutes=10)), [])

    def test_success_resets_history(self):
        # One flagged success; a second success right after must not re-use the same failures.
        events = failures(5) + [ev(ACCEPTED, 60), ev(ACCEPTED, 70)]
        self.assertEqual(len(detect_success_after_failures(events, Config())), 1)


class AnalyzeTests(unittest.TestCase):
    def test_results_sorted_by_severity_and_input_order_does_not_matter(self):
        night = datetime(2026, 10, 11, 2, 0)
        events = failures(6, base=night) + [ev(ACCEPTED, 60, base=night)]
        findings = analyze(list(reversed(events)))  # deliberately out of order
        self.assertEqual([f.severity for f in findings], ["CRITICAL", "MEDIUM", "MEDIUM"])
        self.assertEqual(findings[0].category, "Success after failures")

    def test_clean_log_has_no_findings(self):
        self.assertEqual(analyze([ev(ACCEPTED, i * 3600, user="alice") for i in range(3)]), [])


if __name__ == "__main__":
    unittest.main()
