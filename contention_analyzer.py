#!/usr/bin/env python3
"""
Bitcoin Core debug.log lock *contention* analyzer.
 
Parses lines emitted by DEBUG_LOCKCONTENTION e.g.:
    2024-01-01T12:00:00Z [lock] ContendedLock: lock contention cs_main, ./validation.cpp:1234 completed (5μs)
 
Requires bitcoind to be run with -debug=lock.
 
Automatically splits stats into IBD vs post-IBD phases by detecting the first
UpdateTip line where progress=1.000000.
 
Usage:
    python3 lock_analyzer.py                        # reads ~/.bitcoin/debug.log
    python3 lock_analyzer.py /path/to/debug.log     # custom path
    tail -n 100000 ~/.bitcoin/debug.log | python3 lock_analyzer.py -
"""

import sys
import re

from lock_common import (
    LockStats, open_log, parse_log,
    print_comparison, print_ibd_header, print_report,
)

# Matches completed contention lines e.g.:
#   2024-01-01T12:00:00Z [lock] ContendedLock: lock contention cs_main, ./validation.cpp:1234 completed (5μs)
LOCK_REGEX = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r"\s+\[lock\]\s+ContendedLock:\s+lock\s+contention\s+"
    r"(?P<lock>\S+),\s+"
    r"(?P<location>\S+)\s+"
    r"completed"
    r"\s+\((?P<duration>\d+)[μu]s\)"
)

def line_parser(line: str):
    match = LOCK_REGEX.search(line)
    if not match:
        return None
    ts = match.group("ts")
    lock = match.group("lock")
    location = match.group("location").replace("./", "")
    duration_us = int(match.group("duration"))
    key = f"{lock}@{location}"
    return ts, key, lock, location, duration_us

def main() -> None:
    lines = open_log("lock_analyzer")
    try:
        ibd_stats, post_stats, ibd_end_ts = parse_log(lines, line_parser)
    finally:
        if hasattr(lines, "close") and lines is not sys.stdin:
            lines.close()

    print_ibd_header(ibd_end_ts)
    print_report(ibd_stats,  "PHASE 1 — INITIAL BLOCK DOWNLOAD (IBD)",  event_label="wait")
    print_report(post_stats, "PHASE 2 — POST-IBD (steady state)",        event_label="wait")
    print_comparison(ibd_stats, post_stats, event_label="wait")

if __name__ == "__main__":
    main()

