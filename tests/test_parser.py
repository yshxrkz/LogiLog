import unittest
from datetime import datetime

from logilog.parser import ACCEPTED, FAILED, parse_line, parse_lines


class ParseLineTests(unittest.TestCase):
    def test_failed_password_for_valid_user(self):
        e = parse_line("Oct 11 14:31:02 web01 sshd[123]: Failed password for root "
                       "from 203.0.113.45 port 40810 ssh2", 2026)
        self.assertEqual(e.outcome, FAILED)
        self.assertEqual(e.user, "root")
        self.assertEqual(e.ip, "203.0.113.45")
        self.assertEqual(e.method, "password")
        self.assertFalse(e.invalid_user)
        self.assertEqual(e.timestamp, datetime(2026, 10, 11, 14, 31, 2))

    def test_failed_password_for_invalid_user(self):
        e = parse_line("Oct 11 14:31:02 web01 sshd[123]: Failed password for invalid user "
                       "oracle from 203.0.113.45 port 40810 ssh2", 2026)
        self.assertEqual(e.user, "oracle")
        self.assertTrue(e.invalid_user)

    def test_accepted_publickey_with_key_fingerprint(self):
        e = parse_line("Oct 12 04:10:05 web01 sshd[9]: Accepted publickey for alice from "
                       "192.0.2.10 port 38584 ssh2: RSA SHA256:abc", 2026)
        self.assertEqual(e.outcome, ACCEPTED)
        self.assertEqual(e.method, "publickey")

    def test_single_digit_day_with_padding(self):
        # syslog pads single-digit days with a space: "Oct  2"
        e = parse_line("Oct  2 09:00:00 web01 sshd[1]: Accepted password for bob from "
                       "192.0.2.11 port 1 ssh2", 2026)
        self.assertEqual(e.timestamp, datetime(2026, 10, 2, 9, 0, 0))

    def test_ipv6_address(self):
        e = parse_line("Oct 12 10:00:01 web01 sshd[1]: Accepted publickey for alice from "
                       "2001:db8::42 port 5 ssh2", 2026)
        self.assertEqual(e.ip, "2001:db8::42")

    def test_iso_timestamp_format(self):
        e = parse_line("2026-10-12T03:14:15.123456+00:00 web01 sshd[1]: Failed password "
                       "for root from 198.51.100.7 port 22 ssh2", 1999)
        # The year in the line wins over the year argument.
        self.assertEqual(e.timestamp, datetime(2026, 10, 12, 3, 14, 15))

    def test_irrelevant_lines_are_ignored(self):
        noise = [
            "Oct 11 00:17:00 web01 CRON[1]: pam_unix(cron:session): session opened for user root",
            "Oct 11 10:05:00 web01 sudo[2]: alice : TTY=pts/0 ; COMMAND=/usr/bin/apt update",
            # Logged before the matching "Failed password" line; must not double count.
            "Oct 11 05:44:01 web01 sshd[3]: Invalid user admin from 203.0.113.99 port 30015",
            "Oct 11 05:44:09 web01 sshd[4]: Disconnected from user alice 192.0.2.10 port 1",
            "",
            "complete garbage \x00\xff",
        ]
        for line in noise:
            self.assertIsNone(parse_line(line, 2026), line)


class ParseLinesTests(unittest.TestCase):
    def test_skips_noise_and_keeps_events(self):
        lines = [
            "Oct 11 00:17:00 web01 CRON[1]: noise",
            "Oct 11 01:00:00 web01 sshd[2]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ]
        self.assertEqual(len(list(parse_lines(lines, 2026))), 1)

    def test_year_rollover(self):
        lines = [
            "Dec 31 23:59:58 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "Jan  1 00:00:03 web01 sshd[2]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ]
        events = list(parse_lines(lines, 2025))
        self.assertEqual(events[0].timestamp.year, 2025)
        self.assertEqual(events[1].timestamp.year, 2026)


if __name__ == "__main__":
    unittest.main()
