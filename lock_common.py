"""
bitcoin_lock_common.py — shared utilities for Bitcoin Core lock analyzers.
 
Both bitcoin_lock_analyzer.py (contention) and bitcoin_lock_held_analyzer.py
(held-time) import from here.
 
All durations are in microseconds (µs) internally.
"""

import re
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

SEP = "-" * 100
SEP2 = "=" * 100

IBD_END_REGEX = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r".*UpdateTip:.*progress=1\.000000"
)

# ── Stats dataclass ──────────────────────────────────────────────────────────

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

# ── Formatting helpers ───────────────────────────────────────────────────────

def us_to_human(us: float) -> str:
    if us >= 60_000_000:
        return f"{us / 60_000:.2f}min"
    if us >= 1_000_000:
        return f"{us / 1_000:.2f}s"
    return f"{us:.0f}ms"

def bar(value: float, max_val: float, width: int = 28) -> str:
    if max_val == 0:
        return "░" * width
    filled = int(round(value / max_val * width))
    return "█" * filled + "░" * (width - filled)

# ── Phase-aware log parser ───────────────────────────────────────────────────

def parse_log(lines, line_parser):
    """
    Iterate over log lines, split into IBD and post-IBD phases, and accumulate
    LockStats using the provided line_parser callback.
 
    line_parser(line) -> (key, lock_name, location, durations_us) | None
        Called for each line; return None to skip the line.
 
    Returns (ibd_stats, post_ibd_stats, ibd_end_ts).
    """
    ibd_stats: dict[str, LockStats] = {}
    post_ibd_stats: dict[str, LockStats] = {}
    ibd_end_ts: str | None = None

    for raw in lines:
        line = raw.strip()

        if ibd_end_ts is None:
            m = IBD_END_REGEX.search(line)
            if m:
                ibd_end_ts = m.group("ts")

        result = line_parser(line)
        if result is None:
            continue

        ts, key, lock_name, location, durations_us = result

        if ibd_end_ts is not None and ts is not None and ts >= ibd_end_ts:
            stats = post_ibd_stats
        else:
            stats = ibd_stats

        if key not in stats:
            stats[key] = LockStats(lock_name=lock_name, location=location)
        stats[key].durations_us.append(durations_us)

    return ibd_stats, post_ibd_stats, ibd_end_ts

# ── Report printer ───────────────────────────────────────────────────────────

# Buckets in µs
_BUCKETS = [
    ("<1ms", 0, 1_000), # below logging threshold for lock held
    ("1-5ms", 1_000, 5_000),
    ("5-10ms", 5_000, 10_000),
    ("10-50ms", 10_000, 50_000),
    ("50-200ms", 50_000, 200_000),
    ("200ms-1s", 200_000, 1_000_000),
    (">1s", 1_000_000, None),
]

def print_report(stats: dict[str, LockStats], title: str, event_label: str = "wait") -> None:
    print(f"\n{SEP2}")
    print(f" {title}")
    print(SEP2)

    if not stats:
        print(f"   (no lock {event_label} events recorded in this phase)\n")
        return

    all_locks = sorted(
        (lock for lock in stats.values() if lock.count > 0),
        key=lambda lock: lock.total_us,
        reverse=True,
    )
    if not all_locks:
        print(f"   (no completed lock {event_label} events in this phase)\n")
        return

    max_total = all_locks[0].total_us
    max_mean = max(lock.mean_us for lock in all_locks)

    # ── Summary table ────────────────────────────────────────────────────────
    print(f"  {'LOCK':<38} {'LOCATION':<30} {'CNT':>5}  {'TOTAL':>9}  {'MEAN':>9}  {'P95':>9}  {'MAX':>9}")
    print(SEP)
    for lock in all_locks:
        print(
            f"  {lock.lock_name:<38} {lock.location:<30} {lock.count:>5}"
            f"  {us_to_human(lock.total_us):>9}"
            f"  {us_to_human(lock.mean_us):>9}"
            f"  {us_to_human(lock.p95_us):>9}"
            f"  {us_to_human(lock.max_us):>9}"
        )
    print(SEP)

    # ── Total time bar chart ─────────────────────────────────────────────────
    print(f"\n  Total {event_label} time")
    for lock in all_locks:
        pct = lock.total_us / max_total * 100
        print(f"  {lock.lock_name:<38} {bar(lock.total_us, max_total)}  {us_to_human(lock.total_us):>9}  ({pct:5.1f}%)")

    # ── Mean time bar chart ──────────────────────────────────────────────────
    print(f"\n  Mean {event_label} time")
    for lock in sorted(all_locks, key=lambda lock: lock.mean_us, reverse=True):
        pct = lock.mean_us / max_mean * 100
        print(f"  {lock.lock_name:<38} {bar(lock.mean_us, max_mean)}  {us_to_human(lock.mean_us):>9}  ({pct:5.1f}%)")

    # ── Distribution buckets ─────────────────────────────────────────────────
    print(f"\n  Distribution buckets (all locks combined)")
    counts = {label: 0 for label, _, _ in _BUCKETS}
    all_dur = [duration for lock in all_locks for duration in lock.durations_us]
    for duration in all_dur:
        for label, lo, hi in _BUCKETS:
            if hi is None or duration < hi:
                counts[label] += 1
                break

    total_events = len(all_dur)
    max_bucket = max(counts.values(), default=1)
    for label, cnt, in counts.items():
        pct = (cnt / total_events * 100) if total_events else 0
        print(f"  {label:<12} {bar(cnt, max_bucket)}  {cnt:>6} events  ({pct:5.1f}%)")

    # ── Top 10 longest individual events ────────────────────────────────────
    print(f"\n  Top 10 longest individual {event_label}s")
    events = [(duration, lock.lock_name, lock.location) for lock in all_locks for duration in lock.durations_us]
    events.sort(reverse=True)
    print(f"  {'DURATION':>10}  {'LOCK':<38}  LOCATION")
    print(SEP)
    for duration, lock_name, location in events[:10]:
        print(f"  {us_to_human(duration):>10}  {lock_name:<38}  {location}")

    print()

# ── IBD vs post-IBD comparison ───────────────────────────────────────────────

def print_comparison(ibd: dict, post: dict, event_label: str = "wait") -> None:
    """Side-by-side mean comparison for locks present in both phases."""
    common = sorted(set(ibd) & set(post))
    if not common:
        return

    print(f"\n{SEP2}")
    print(f"  IBD vs POST-IBD  —  MEAN {event_label.upper()} TIME COMPARISON  (locks present in both phases)")
    print(SEP2)
    print(f"  {'LOCK':<38}  {'LOCATION':<35}  {'IBD mean':>10}  {'Post mean':>10}  {'Delta':>13}  {'ratio':>7}")
    print(SEP)

    rows = []
    for key in common:
        ibd, post_ibd = ibd[key], post[key]
        if ibd.count == 0 or post_ibd.count == 0:
            continue

        delta = post_ibd.mean_us - ibd.mean_us
        ratio = post_ibd.mean_us / ibd.mean_us if ibd.mean_us else float("inf")
        rows.append((abs(delta), ibd.lock_name, ibd.location, ibd, post_ibd, delta, ratio))
    rows.sort(reverse=True)

    for _, lock_name, location, ibd, post_ibd, delta, ratio, in rows:
        sign = "+" if delta >= 0 else ""
        print(
            f"  {lock_name:<38}  {location:<35}"
            f"  {us_to_human(i.mean_us):>10}"
            f"  {us_to_human(p.mean_us):>10}"
            f"  {sign}{us_to_human(delta):>12}"
            f"  {ratio:>6.2f}x"
        )
    print()

# ── CLI argument / file handling ─────────────────────────────────────────────

def open_log(script_name: str) -> object:
    """
    Parse sys.argv for an optional log path or '-' for stdin.
    Returns an open file-like object. Caller is responsible for closing it.
    """
    if len(sys.argv) > 1:
        path_arg = sys.argv[1]
        if path_arg == "-":
            return sys.stdin
        path = Path(path_arg).expanduser()
        if not path.exists():
            sys.exit(f"File not found: {path}")
        return path.open(encoding="utf-8", errors="replace")

    default = Path("~/.bitcoin/debug.log").expanduser()
    if not default.exists():
        sys.exit(
            f"Default log not found at {default}.\n"
            f"Pass the log path as an argument, e.g.:\n"
            f"  python3 {script_name} /path/to/debug.log\n"
            f"  tail -n 200000 ~/.bitcoin/debug.log | python3 {script_name} -"
        )
    return default.open(encoding="utf-8", errors="replace")

def print_ibd_header(ibd_end_ts: str | None) -> None:
    if ibd_end_ts:
        print(f"\n  IBD end detected at: {ibd_end_ts}  (UpdateTip progress=1.000000)")
    else:
        print("\n  NOTE: No 'UpdateTip progress=1.000000' line found.")
        print("  The node may still be in IBD, or the log was captured post-sync.")
        print("  All events will appear under IBD.\n")

