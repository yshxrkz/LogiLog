# LogiLog

A Python command-line tool that reads an SSH `auth.log` and flags suspicious login activity:

| Rule | What it flags | Severity |
|------|---------------|----------|
| **Brute force** | Many failed logins from one IP in a short time window | MEDIUM, or HIGH for huge bursts / many usernames |
| **Unusual hours** | A *successful* login outside normal working hours | LOW, or MEDIUM if the account is `root` |
| **Success after failures** | A successful login from an IP that just failed several times | CRITICAL |

It uses only the Python standard library. Python 3.8+ is enough, and there is nothing to `pip install`.

---

## Quick start

```bash
git clone https://github.com/yshxrkz/LogiLog.git
cd LogiLog

# Analyse the bundled sample log (it is dated 2026, so pass the year)
python3 -m logilog sample_logs/auth.log --year 2026

# Run the unit tests
python3 -m unittest discover -v
```

On a real Linux server (Debian/Ubuntu keep SSH logs in `/var/log/auth.log`; RHEL/CentOS use `/var/log/secure`):

```bash
sudo python3 -m logilog /var/log/auth.log

# systemd-only machines: pipe the journal in on stdin
journalctl -u ssh --no-pager -o short | python3 -m logilog -
```

### Options

```
python3 -m logilog LOGFILE [options]

  LOGFILE               path to auth.log, or '-' to read stdin
  --json                machine-readable output (for a SIEM, script, or Slack bot)
  --year YEAR           year for syslog timestamps, which don't include one (default: this year)
  --threshold N         failures from one IP inside the window that count as brute force (default 5)
  --window MIN          sliding window size in minutes (default 10)
  --success-after N     failures before a success that count as a likely compromise (default 3)
  --work-start H        start of normal hours, 0-23 (default 7)
  --work-end H          end of normal hours, 0-23 (default 20); start > end means an overnight shift
  --fail-on SEVERITY    exit with status 1 if any finding is at or above SEVERITY (for cron/CI)
```

Example: alert from a nightly cron job only when something serious happens:

```bash
python3 -m logilog /var/log/auth.log --fail-on HIGH > /tmp/ssh-report.txt || mail -s "SSH alert" ops@example.com < /tmp/ssh-report.txt
```

---

## Example output

From the bundled sample log (shortened):

```
========================================================================
 LogiLog: SSH auth log report for sample_logs/auth.log
========================================================================
 Time range : 2026-10-11 05:44:01 -> 2026-10-12 16:09:34
 Events     : 62 login attempts (49 failed, 13 successful)
 Unique IPs : 7
 Findings   : 6 (1 CRITICAL, 1 HIGH, 2 MEDIUM, 2 LOW)

 Top failing IPs:
   203.0.113.45                                36 failed
   198.51.100.23                                9 failed
   ...

========================================================================
 FINDINGS (most severe first)
========================================================================

 [1] CRITICAL Success after failures  |  IP 198.51.100.23
     Login as 'deploy' succeeded after 9 failures from this IP in the preceding 10 min (failures targeted the same account: likely password guessed)
     When : 2026-10-12 02:41:13 -> 2026-10-12 02:43:31
     Users: deploy, root
     Evidence:
       | Oct 12 02:43:10 web01 sshd[...]: Failed password for deploy from 198.51.100.23 port 61328 ssh2
       | Oct 12 02:43:31 web01 sshd[...]: Accepted password for deploy from 198.51.100.23 port 51791 ssh2

 [2] HIGH     Brute force  |  IP 203.0.113.45
     36 failed logins (36 within 10 min) against 18 account(s); 27 attempt(s) used non-existent usernames
 ...
```

Every finding includes the raw log lines that triggered it. An analyst can check the evidence directly instead of taking the tool's word for it.

---

## How it works

```
auth.log ──► parser.py ──► LoginEvent objects ──► detectors.py ──► Finding objects ──► report.py ──► text / JSON
             (regex)       (timestamp, ip, user,   (3 independent    (severity, ip,
                            outcome, method)        rules)            description, evidence)
```

The code is split into three layers, and each one can be tested on its own:

1. **Parsing (`logilog/parser.py`)**: regular expressions pull the timestamp, outcome (`Failed`/`Accepted`), auth method, username, and IP out of each `sshd` line. Anything else (cron, sudo, PAM sessions, disconnects) is skipped. Both the classic syslog format (`Oct 11 14:31:02 host sshd[123]: ...`) and the ISO-8601 format used by newer rsyslog/journald are supported. Lines are read through a **generator**, so large logs are streamed instead of loaded into memory.
2. **Detection (`logilog/detectors.py`)**: three pure functions take the list of events and return findings. They don't read files or print anything, which makes them easy to unit-test with hand-built events.
3. **Reporting (`logilog/report.py`)**: turns the findings into a readable report or JSON. `logilog/cli.py` connects the three layers and handles the command-line arguments.

### The sliding-window technique

The brute-force and success-after-failure rules both need to answer the question "how many failures did this IP have in the last N minutes?" A plain total isn't enough, because 20 failures spread over a month is someone who keeps mistyping their password, while 20 failures in 60 seconds is a script. The rule needs to measure the **rate** of failures.

For each IP the tool keeps a `collections.deque` of recent failure timestamps:

```python
times.append(event.timestamp)                       # add the newest failure on the right
while times[0] < event.timestamp - window:          # drop failures that have aged out on the left
    times.popleft()
len(times)                                          # = failures in the last N minutes
```

Each event is appended once and popped at most once, so the whole scan runs in **O(n)** time. Memory per IP is bounded by the number of failures that fit in one window.

### The three rules in detail

**1. Brute force (repeated failed logins from one IP)**
- Flags any IP whose failure count inside the window reaches `--threshold`.
- Produces one finding per IP (not one per window), with the peak burst size and the total.
- Escalates to **HIGH** when the burst is 3× the threshold, or when 5+ different usernames were tried, which points to a dictionary attack or password spraying.
- Counts attempts against **non-existent usernames** (`invalid user`). Real users rarely mistype their own username; bots try `admin`, `oracle`, `pi`, `test`, and so on.

**2. Logins at unusual hours**
- Only *successful* logins are checked. A 3am failure is already covered by rule 1; a 3am success means someone actually got in.
- Working hours are configurable, and overnight shifts are supported (`--work-start 22 --work-end 6`).
- **LOW** by default (people do work late). **MEDIUM** for `root`, because direct root SSH logins should be rare on a well-run server.

**3. Successful login right after many failures**
- When a login succeeds, the tool counts how many failures the same IP had in the preceding window. If there were `--success-after` or more, it raises a **CRITICAL** finding.
- If the failures targeted the same account that then logged in, the report adds "likely password guessed".
- A success clears that IP's history. A legitimate user who mistyped once and then logged in isn't flagged, and one compromise is reported once rather than over and over.

Findings are sorted by severity (CRITICAL → LOW), then by time.

---

## Attacks it helps detect

| Attack | How it shows up in the log | Which rule catches it |
|--------|----------------------------|-----------------------|
| **SSH brute force**: a bot hammers one account (often `root`) with a password list | Dozens of `Failed password for root` from one IP within seconds | Brute force |
| **Dictionary / username enumeration**: a bot cycles through common account names | `Failed password for invalid user admin/oracle/pi/test...` | Brute force, escalated to HIGH by the many-usernames check |
| **Successful password guess / credential stuffing**: the attacker finds a working password (weak, default, or leaked from another site) | A run of failures followed by `Accepted password` from the **same IP** | Success after failures (CRITICAL) |
| **Stolen credentials or keys used out of hours**: an attacker logs in with valid credentials while nobody is watching, often in a different time zone | `Accepted ...` at 02:43 | Unusual hours |
| **Abuse of `root` access** | `Accepted ... for root` outside working hours | Unusual hours (MEDIUM for root) |

In the bundled sample log, `198.51.100.23` shows the complete attack chain: brute force, then a successful login, at 2:43am. All three rules fire on it.

### Recommended response when something is flagged
- **CRITICAL**: treat the account as compromised. Kill its sessions, rotate the credentials, check `last`/`wtmp`, `~/.ssh/authorized_keys`, crontabs and running processes, and block the IP.
- **HIGH/MEDIUM brute force**: block the IP (firewall or `fail2ban`), and make sure password authentication is disabled (`PasswordAuthentication no`) and `PermitRootLogin no`.
- **Unusual hours**: confirm with the account owner.

---

## Limitations (and how I'd extend it)

- **Distributed attacks**: a botnet sending one attempt from each of 1,000 IPs never trips the per-IP threshold. A future rule could count failures **per target username across all IPs** to catch password spraying.
- **Low-and-slow attacks**: an attacker who stays under the rate (e.g. 3 attempts spread over a day, like `203.0.113.99` in the sample) isn't flagged. A longer second window, or a daily per-IP total, would help.
- **Not real-time**: the tool analyses a file after the fact. It could be extended to follow the log (`tail -f`-style) and alert live, which is what `fail2ban` does for blocking.
- **No context about IPs**: a GeoIP/ASN lookup or a threat-intel feed could flag logins from unexpected countries or known-bad ranges. "Impossible travel" (the same user logging in from two countries minutes apart) is another possible rule.
- **Fixed working hours**: a better approach would learn each user's normal login hours from history instead of using one global window.
- **Syslog has no year**: use `--year` for old logs. The tool handles the Dec → Jan rollover automatically.

---

## Project layout

```
LogiLog/
├── logilog/
│   ├── __init__.py       # public API
│   ├── __main__.py       # enables `python -m logilog`
│   ├── cli.py            # argument parsing, wires parser → detectors → report
│   ├── parser.py         # regex parsing of auth.log lines into LoginEvent objects
│   ├── detectors.py      # the three detection rules + Config thresholds
│   └── report.py         # text and JSON report rendering
├── sample_logs/
│   └── auth.log          # fake log with normal traffic and four attack scenarios
└── tests/
    ├── test_parser.py    # log formats, noise lines, IPv6, year rollover
    ├── test_detectors.py # thresholds, window edges, severity escalation
    └── test_cli.py       # end-to-end run against the sample log
```

### About the sample data
`sample_logs/auth.log` is entirely fake. All IP addresses come from the documentation ranges reserved by RFC 5737 / RFC 3849 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), so they can never belong to a real host. The file contains:

- normal daytime key-based logins by `alice` and `bob`, plus cron/sudo noise
- `bob` mistyping his password once, then logging in (**should not** be flagged)
- `203.0.113.45`: a fast dictionary attack across 18 usernames, never successful
- `198.51.100.23`: brute force against `root`/`deploy` that **succeeds** at 02:43
- `203.0.113.99`: 3 failures hours apart (below the threshold, not flagged)
- `carol` at 23:15 and `root` at 04:10 logging in with valid keys (unusual hours)
