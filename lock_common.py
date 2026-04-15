"""
lock_common.py — shared utilities for Bitcoin Core lock analyzers.
 
Both lock_analyzer.py (contention) and lock_held_analyzer.py (held-time)
import from here.
 
All durations are in microseconds (µs) internally.
 
Four phases are detected in order:
  1. HEADER SYNC  — Pre-Synchronising and Synchronizing blockheaders
  2. IBD          — Full block download until UpdateTip progress=1.000000
  3. POST-IBD     — Steady state
"""

import re
import statistics
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

SEP = "-" * 126
SEP2 = "=" * 126

# Phase boundary regexes — all keyed on timestamp
HEADER_SYNC_REGEX = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r".*Synchronizing blockheaders.*100\.00"
)

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
        return f"{us / 60_000_000:.2f}min"
    if us >= 1_000_000:
        return f"{us / 1_000_000:.2f}s"
    if us >= 1_000:
        return f"{us / 1_000:.2f}ms"
    return f"{us:.0f}µs"

def bar(value: float, max_val: float, width: int = 28) -> str:
    if max_val == 0:
        return "░" * width
    filled = int(round(value / max_val * width))
    return "█" * filled + "░" * (width - filled)

# ── Phase-aware log parser ───────────────────────────────────────────────────

def _detect_phase_boundary(line: str, current: str | None, regex: re.Pattern[str]) -> str | None:
    """Return the timestamp if regex matches and boundary not yet set, else current."""
    if current is not None:
        return current
    match = regex.search(line)
    return match.group("ts") if match else None

# returns the stats dictionary to be used based on the timestamp
def _assign_phase(ts: str, phases: list[tuple[str | None, dict]]) -> dict:
    for boundary_end_ts, stats in phases:
        if boundary_end_ts is not None and ts > boundary_end_ts:
            return stats
    return phases[-1][1]


def parse_log(lines, line_parser):
    """
    Iterate over log lines, split into three phases, and accumulate
    LockStats using the provided line_parser callback.
 
    line_parser(line) -> (key, lock_name, location, durations_us) | None
        Called for each line; return None to skip the line.
 
    Returns (header_sync_stats, ibd_stats, post_ibd_stats, phase_ts).
    where phase_ts is a dict with keys 'header_sync_end', 'ibd_end'.
    """
    header_sync_stats: dict[str, LockStats] = {}
    ibd_stats: dict[str, LockStats] = {}
    post_ibd_stats: dict[str, LockStats] = {}

    first_ts: str | None = None
    header_sync_end_ts: str | None = None
    ibd_end_ts: str | None = None

    events = []
    for raw in lines:
        line = raw.strip()

        # Detect phase boundaries.
        header_sync_end_ts = _detect_phase_boundary(line, header_sync_end_ts, HEADER_SYNC_REGEX)
        ibd_end_ts = _detect_phase_boundary(line, ibd_end_ts, IBD_END_REGEX)

        result = line_parser(line)
        if result is not None:
            events.append(result)

    phases = [
        (ibd_end_ts, post_ibd_stats),
        (header_sync_end_ts, ibd_stats),
        (None, header_sync_stats),
    ]
    for ts, key, lock_name, location, durations_us in events:
        if first_ts is None:
            first_ts = ts
        stats = _assign_phase(ts, phases)

        if key not in stats:
            stats[key] = LockStats(lock_name=lock_name, location=location)
        stats[key].durations_us.append(durations_us)

    phase_ts = {
        "first_ts": first_ts,
        "header_sync_end": header_sync_end_ts,
        "ibd_end": ibd_end_ts,
    }

    return header_sync_stats, ibd_stats, post_ibd_stats, phase_ts

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
    print(f"  {'LOCK':<38} {'LOCATION':<35} {'CNT':>5}  {'TOTAL':>9}  {'MEAN':>9}  {'P95':>9}  {'MAX':>9}")
    print(SEP)
    for lock in all_locks:
        print(
            f"  {lock.lock_name:<38} {lock.location:<35} {lock.count:>5}"
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

def _ts_diff(start: str, end: str) -> str:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    delta = datetime.strptime(end, fmt) - datetime.strptime(start, fmt)
    h, rem = divmod(int(delta.total_seconds()), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s"

def print_phase_header(phase_ts: dict) -> None:
    first_ts = phase_ts.get("first_ts")
    header_sync_end = phase_ts.get("header_sync_end")
    ibd_end = phase_ts.get("ibd_end")

    print()
    if first_ts and header_sync_end:
        print(f"  Header sync end:  {header_sync_end}  (duration: {_ts_diff(first_ts, header_sync_end)})")
    elif header_sync_end:
        print(f"  Header sync end:  {header_sync_end}")
    else:
        print("  NOTE: No 'Synchronizing blockheaders ~100.00%' line found.")
        print("  Node may still be in header sync, or log was captured after completion.")
    print()

    if header_sync_end and ibd_end:
        print(f"  IBD end:          {ibd_end}  (duration: {_ts_diff(header_sync_end, ibd_end)})")
    elif ibd_end:
        print(f"  IBD end:          {ibd_end}")
    else:
        print("  NOTE: No 'UpdateTip progress=1.000000' line found.")
        if header_sync_end:
            print("  Node is still in IBD.")
        else:
            print("  Node may still be in header sync or IBD, or log was captured post-sync.")

    print()
