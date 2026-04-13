#!/usr/bin/env python3
"""
Bitcoin Core debug.log lock contention analyzer.
Automatically splits stats into IBD vs post-IBD phases by detecting the first
UpdateTip line where progress=1.000000 (the moment Bitcoin Core clears
fInitialBlockDownload).

Usage:
    python3 bitcoin_lock_analyzer.py                          # reads ~/.bitcoin/debug.log
    python3 bitcoin_lock_analyzer.py /path/to/debug.log       # custom path
    tail -n 100000 ~/.bitcoin/debug.log | python3 bitcoin_lock_analyzer.py -
"""

import sys
import re
import statistics
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, field

LOCK_REGEX = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r"\s+\[lock\]\s+Enter:\s+lock\s+contention\s+"
    r"(?P<lock>\S+),\s+"
    r"(?P<location>\S+)\s+"
    r"(?P<state>started|completed)"
    r"(?:\s+\((?P<duration>\d+)μs\))?"
)

IBD_END_REGEX = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r".*UpdateTip:.*progress=1\.000000"
)

@dataclass
class LockStats:
    lock_name: str
    location: str
    durations_us: list = field(default_factory=list)
    unmatched_starts: int = 0

    @property
    def count(self) -> int:
        return len(self.durations_us)

    @property
    def total_us(self) -> int:
        return sum(self.durations_us)

    @property
    def mean_us(self) -> float:
        return statistics.mean(self.durations_us) if self.durations_us else 0.0

    @property
    def median_us(self) -> float:
        return statistics.median(self.durations_us) if self.durations_us else 0.0

    @property
    def p95_us(self) -> float:
        if not self.durations_us:
            return 0.0
        s = sorted(self.durations_us)
        idx = int(len(s) * 0.95)
        return s[min(idx, len(s) - 1)]

    @property
    def max_us(self) -> int:
        return max(self.durations_us) if self.durations_us else 0

    @property
    def min_us(self) -> int:
        return min(self.durations_us) if self.durations_us else 0

def us_to_human(us: float) -> str:
    if us >= 1_000_000:
        return f"{us / 1_000_000:.2f}s"
    if us >= 1_000:
        return f"{us / 1_000:.2f}ms"
    return f"{us:.0f}μs"

def bar(value: float, max_val: float, width: int = 28) -> str:
    if max_val == 0:
        return "░" * width
    filled = int(round(value / max_val * width))
    return "█" * filled + "░" * (width - filled)

def parse_log(lines):
    ibd_stats: dict = {}
    post_ibd_stats: dict = {}
    ibd_end_ts = None

    pending_ibd: dict = defaultdict(list)
    pending_post_ibd: dict = defaultdict(list)

    for raw in lines:
        line = raw.strip()

        if ibd_end_ts is None:
            m_ibd = IBD_END_REGEX.search(line)
            if m_ibd:
                ibd_end_ts = m_ibd.group("ts")

        lock_match = LOCK_REGEX.search(line)
        if not lock_match:
            continue

        ts = lock_match.group("ts")
        lock = lock_match.group("lock")
        loc = lock_match.group("location")
        state = lock_match.group("state")
        dur_str = lock_match.group("duration")
        key = f"{lock}@{loc}"

        is_post_ibd = ibd_end_ts is not None and ts >= ibd_end_ts

        stats = post_ibd_stats if is_post_ibd else ibd_stats
        pending = pending_post_ibd if is_post_ibd else pending_ibd

        if key not in stats:
            stats[key] = LockStats(lock_name=lock, location=loc)

        if state == "started":
            pending[key].append(ts)
        elif state == "completed":
            if dur_str is not None:
                stats[key].durations_us.append(int(dur_str))
            if pending[key]:
                pending[key].pop()

    for key, starts in pending_ibd.items():
        if starts and key in ibd_stats:
            ibd_stats[key].unmatched_starts += len(starts)

    for key, starts in pending_post_ibd.items():
        if starts and key in post_ibd_stats:
            post_ibd_stats[key].unmatched_starts += len(starts)

    return ibd_stats, post_ibd_stats, ibd_end_ts

SEP = "-" * 95
SEP2 = "=" * 95

def print_report(stats: dict, title: str) -> None:
    print(f"\n{SEP2}")
    print(f" {title}")
    print(SEP2)

    if not stats:
        print("   (no lock contenction events recorded in this phase)\n")
        return

    all_locks = [lock for lock in sorted(stats.values(), key=lambda lock: lock.total_us, reverse=True) if lock.count > 0]
    if not all_locks:
        print("   (no completed lock events in this phase)\n")
        return

    max_total = all_locks[0].total_us
    max_mean = max(lock.mean_us for lock in all_locks)

    # Summary table
    print(f"  {'LOCK':<38} {'LOCATION':<22} {'CNT':>5}  {'TOTAL':>9}  {'MEAN':>9}  {'P95':>9}  {'MAX':>9}")
    print(SEP)
    for lock in all_locks:
        loc_short = lock.location.replace("./", "")
        print(
                f"  {lock.lock_name:<38} {loc_short:<22} {lock.count:>5}"
                f"  {us_to_human(lock.total_us):>9}"
                f"  {us_to_human(lock.mean_us):>9}"
                f"  {us_to_human(lock.p95_us):>9}"
                f"  {us_to_human(lock.max_us):>9}"
        )
    print(SEP)

    # Total wait bars
    print(f"\n Total wait time")
    for lock in all_locks:
        pct = lock.total_us / max_total * 100
        print(f"  {lock.lock_name:<38} {bar(lock.total_us, max_total)}  {us_to_human(lock.total_us):9}  ({pct:5.1f}%)")


    # Mean wait bars
    print(f"\n Mean wait time")
    for lock in all_locks:
        pct = lock.mean_us / max_mean * 100
        print(f"  {lock.lock_name:<38} {bar(lock.mean_us, max_mean)}  {us_to_human(lock.mean_us):9}  ({pct:5.1f}%)")

    # Distribution buckets
    print(f"\n Distribution buckets")
    buckets = {"< 1ms": 0, "1-5ms": 0, "5-10ms": 0, "10-50ms": 0, "> 50ms": 0}
    all_dur = []
    for lock in all_locks:
        for duration in lock.durations_us:
            all_dur.append(duration)

    for duration in all_dur:
        if duration < 1_000: buckets["< 1ms"] += 1
        elif duration < 5_000: buckets["1-5ms"] += 1
        elif duration < 10_000: buckets["5-10ms"] += 1
        elif duration < 50_000: buckets["10-50ms"] += 1
        else: buckets["> 50ms"] += 1

    total_events = len(all_dur)
    max_bucket = max(buckets.values(), default=1)
    for label, cnt in buckets.items():
        pct = (cnt / total_events * 100) if total_events else 0
        print(f"  {label:<10} {bar(cnt, max_bucket)}  {cnt:>5} events  ({pct:5.1f}%)")

    # Top 10 worst
    print(f"\n  Top 10 longest individual waits")
    events = []
    for lock in all_locks:
        for duration in lock.durations_us:
            events.append((duration, lock.lock_name, lock.location))

    events.sort(reverse=True)
    print(f"  {'DURATION':>10}  {'LOCK':<83}  LOCATION")
    print(SEP)
    for duration,lock_name, location in events[:10]:
        print(f"  {us_to_human(duration):>10}  {lock_name:<38}  {location}")

    # Unmatched
    unmatched = []
    for lock in all_locks:
        if lock.unmatched_starts:
            unmatched.append((lock.lock_name, lock.location, lock.unmatched_starts))

    if unmatched:
        print(f"\n  Unmatched 'started' lines (truncated log?)")
        for lock_name, location, count in unmatched:
            print(f"  {lock_name} @ {location}: {count} unmatched")

    print()

def print_comparison(ibd: dict, post: dict) -> None:
    """Side-by-side mean comparison for locks that appear in both phases."""
    common = sorted(set(ibd) & set(post))
    if not common:
        return

    print(f"\n{SEP2}")
    print("  IBD vs POST-IBD  —  MEAN WAIT COMPARISON  (locks present in both phases)")
    print(SEP2)
    print(f"  {'LOCK':<38}  {'LOCATION':<35}  {'IBD mean':>10}  {'Post mean':>10}  {'Delta':>13}  {'ratio':>7}")
    print(SEP)
    rows = []
    for key in common:
        ibd_lock = ibd[key]
        post_ibd_lock = post[key]
        if ibd_lock.count == 0 or post_ibd_lock.count == 0:
            continue
        delta = post_ibd_lock.mean_us - ibd_lock.mean_us
        ratio = post_ibd_lock.mean_us / ibd_lock.mean_us if ibd_lock.mean_us else float("inf")
        rows.append((abs(delta), ibd_lock.lock_name, ibd_lock.location, ibd_lock, post_ibd_lock, delta, ratio))
    rows.sort(reverse=True)
    for _, lock_name, location, ibd_lock, post_ibd_lock, delta, ratio in rows:
        sign = "+" if delta >= 0 else ""
        print(
            f"  {lock_name:<38}  {location:<35}  {us_to_human(ibd_lock.mean_us):>10}  {us_to_human(post_ibd_lock.mean_us):>10}"
            f"  {sign}{us_to_human(delta):>12}  {ratio:>6.2f}x"
        )
    print()

def main() -> None:
    if len(sys.argv) > 1:
        path_arg = sys.argv[1]
        if path_arg == "-":
            lines = sys.stdin
        else:
            path = Path(path_arg).expanduser()
            if not path.exists():
                sys.exit(f"File not found: {path}")
            lines = path.open(encoding="utf-8", errors="replace")

    else:
        default = Path("~./bitcoin/debug.log").expanduser()
        if not default.exists():
            sys.exit(
                f"Default log not found at {default}.\n"
                "Pass the log path as an argument, e.g.:\n"
                "  python3 bitcoin_lock_analyzer.py /path/to/debug.log\n"
                "  tail -n 100000 ~/.bitcoin/debug.log | pything3 bitcoin_lock_analyzer.py -"
            )
        lines = default.open(encoding="utf-8", errors="replace")

    try:
        ibd_stats, post_stats, ibd_end_ts = parse_log(lines)
    finally:
        if hasattr(lines, "close") and lines is not sys.stdin:
            lines.close()

    if ibd_end_ts:
        print(f"\n  IBD end detected at: {ibd_end_ts}  (UpdateTip progress=1.000000)")
    else:
        print("\n  NOTE: No 'UpdateTip progress=1.000000' line found.")
        print("  The node may still be in IBD, or -debug=lock was enabled post-sync.")
        print("  All events will appear under IBD.\n")

    print_report(ibd_stats, "PHASE 1 - INITIAL BLOCK DOWNLOAD (IBD)")
    print_report(post_stats, "PHASE 2 - POST-IBD (steady state)")
    print_comparison(ibd_stats, post_stats)

if __name__ == "__main__":
    main()






















