#! /usr/bin/env python3
"""
Bitcoin Core debug.log lock *held-time* analyzer.
 
Parses lines emitted by the DEBUG_LOCKCONTENTION held-time patch e.g.:
    2024-01-01T12:00:00Z [lock] LOCK HELD 5000us: cs_main (held at src/validation.cpp:1234)
 
Requires bitcoind to be run with -debug=lock.
 
Automatically splits stats into IBD vs post-IBD phases by detecting the first
UpdateTip line where progress=1.000000.
 
Usage:
    python3 lock_held_analyzer.py                        # reads ~/.bitcoin/debug.log
    python3 lock_held_analyzer.py /path/to/debug.log     # custom path
    tail -n 200000 ~/.bitcoin/debug.log | python3 lock_held_analyzer.py -
"""

import re
import sys

from lock_common import (
    LockStats, open_log, parse_log,
    print_comparison, print_ibd_header, print_report,
)

# Matches lines emitted by LogDebug(BCLog::LOCK, ...) e.g.:
#   2024-01-01T12:00:00Z [lock] LOCK HELD 5000us: cs_main (held at src/validation.cpp:1234)
HELD_REGEX = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r"\s+\[lock\]\s+LOCK HELD (?P<duration_us>\d+)us:\s+"
    r"(?P<lock>\S+)\s+"
    r"\(held at\s+(?P<file>[^:)]+):(?P<line>\d+)\)"
)

def line_parser(line: str):
    match = HELD_REGEX.search(line)
    if not match:
        return None
    ts = match.group("ts")
    lock = match.group("lock")
    location = f"{match.group('file').strip()}:{match.group('line')}"
    if lock == "mut" and "threadinterrupt" in location:
        return None
    duration_us = int(match.group("duration_us"))
    key = f"{lock}@{location}"
    return ts, key, lock, location, duration_us

def main() -> None:
    lines = open_log("lock_held_analyzer.py")
    try:
        ibd_stats, post_ibd_stats, ibd_end_ts = parse_log(lines, line_parser)
    finally:
        if hasattr(lines, "close") and lines is not sys.stdin:
            lines.close()

    print_ibd_header(ibd_end_ts)
    print_report(ibd_stats,  "PHASE 1 — INITIAL BLOCK DOWNLOAD (IBD)",  event_label="held")
    print_report(post_ibd_stats, "PHASE 2 — POST-IBD (steady state)",        event_label="held")
    print_comparison(ibd_stats, post_ibd_stats, event_label="held")

if __name__ == "__main__":
    main()
