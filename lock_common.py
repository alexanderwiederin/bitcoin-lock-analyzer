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

# Locks excluded from held-time analysis — these are condition variable
# wait locks whose "held time" is sleep time, not actual lock contention.
EXCLUDE_LOCKS = {
    "newTaskMutex",
    "NetEventsInterface::g_msgproc_mutex",
}
excluded_names = [e if isinstance(e, str) else f"{e[0]} @ {e[1]}" for e in EXCLUDE_LOCKS]

# ── Constants ────────────────────────────────────────────────────────────────

SEP = "-" * 180
SEP2 = "=" * 180

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
    thread_durations: dict = field(default_factory=dict)

    def add(self, durations_us: int, thread_name: str | None = None) -> None:
        self.durations_us.append(durations_us)
        if thread_name:
            self.thread_durations.setdefault(thread_name, []).append(durations_us)

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

def bar(value: float, max_val: float, width: int = 23) -> str:
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
    last_ts: str | None = None
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
    for ts, key, lock_name, location, durations_us, thread_name in events:
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        stats = _assign_phase(ts, phases)

        if key not in stats:
            stats[key] = LockStats(lock_name=lock_name, location=location)
        stats[key].add(durations_us, thread_name)

    phase_ts = {
        "first_ts": first_ts,
        "last_ts": last_ts,
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
        (lock for lock in stats.values() if lock.count > 0
            and lock.lock_name not in EXCLUDE_LOCKS
            and (lock.lock_name, lock.location.split("/")[-1]) not in EXCLUDE_LOCKS),
        key=lambda lock: lock.total_us,
        reverse=True,
    )
    if not all_locks:
        print(f"   (no completed lock {event_label} events in this phase)\n")
        return

    if EXCLUDE_LOCKS:
        print(f"  (excluded from analysis: {', '.join(sorted(excluded_names))} — lock held during condition variable sleep, not contention)")

    max_total = all_locks[0].total_us
    max_mean = max(lock.mean_us for lock in all_locks)
    total_time = sum(lock.total_us for lock in all_locks)

    # ── Summary table ────────────────────────────────────────────────────────
    print(f"  {'LOCK':<38} {'LOCATION':<35} {'CNT':>10}  {'TOTAL':>15}  {'SHARE OF TIME':<23}  {'PCT':>6}  {'MEAN':>9}  {'P95':>9}  {'MAX':>9}")
    print(SEP)
    for lock in all_locks:
        pct = lock.total_us / total_time * 100
        short_loc = lock.location.split("/")[-1]
        print(
            f"  {lock.lock_name:<38} {short_loc:<35} {lock.count:>10}"
            f"  {us_to_human(lock.total_us):>15}"
            f"  {bar(lock.total_us, total_time):<23}"
            f"  {pct:>5.1f}%"
            f"  {us_to_human(lock.mean_us):>9}"
            f"  {us_to_human(lock.p95_us):>9}"
            f"  {us_to_human(lock.max_us):>9}"
        )
        if lock.thread_durations:
            sorted_threads = sorted(lock.thread_durations.items(),
                                    key=lambda x: sum(x[1]), reverse=True)
            for thread, durs in sorted_threads:
                t_total = sum(durs)
                t_pct = t_total / lock.total_us * 100
                t_mean = statistics.mean(durs)
                t_max = max(durs)
                print(
                    f"    {'↳ ' + thread:<36} {'':35} {len(durs):>10}"
                    f"  {us_to_human(t_total):>15}"
                    f"  {'':23}"
                    f"  {t_pct:>5.1f}%"
                    f"  {us_to_human(t_mean):>9}"
                    f"  {'':9}"
                    f"  {us_to_human(t_max):>9}"
                )

        print()

    print(SEP)

    # ── Distribution buckets ─────────────────────────────────────────────────
    print(f"\n  Distribution buckets (all locks combined)")
    counts = {label: 0 for label, _, _ in _BUCKETS}
    totals = {label: 0 for label, _, _ in _BUCKETS}
    all_dur = [duration for lock in all_locks for duration in lock.durations_us]
    for duration in all_dur:
        for label, lo, hi in _BUCKETS:
            if hi is None or duration < hi:
                counts[label] += 1
                totals[label] += duration
                break

    total_events = len(all_dur)
    for label, lo, hi in _BUCKETS:
        cnt = counts[label]
        tot = totals[label]
        pct_cnt = (cnt / total_events * 100) if total_events else 0
        pct_time = (tot / total_time * 100) if total_time else 0
        print(f"  {label:<12} {bar(tot, total_time)}  {cnt:>6} events  ({pct_cnt:5.1f}%)  {us_to_human(tot):>9}  ({pct_time:5.1f}%)")

        # Show which locks contribute to this bucket
        bucket_locks = sorted(
            [(lock, sum(d for d in lock.durations_us if d >= lo and (hi is None or d < hi)))
             for lock in all_locks],
            key=lambda x: x[1],
            reverse=True
        )
        for lock, lock_tot in bucket_locks:
            if lock_tot == 0:
                continue
            lock_cnt = sum(1 for d in lock.durations_us if d >= lo and (hi is None or d < hi))
            pct = lock_tot / tot * 100 if tot else 0

            if pct < 1.0:
                continue

            print(f"    {lock.lock_name:<38} {lock.location:<35} {lock_cnt:>6} events  {us_to_human(lock_tot):>9}  ({pct:5.1f}%)")

    # ── Top 10 longest individual events ────────────────────────────────────

    print(f"\n  Top 10 longest individual {event_label}s")
    events = [
        (duration, lock.lock_name, lock.location, thread)
        for lock in all_locks
        for thread, durs in lock.thread_durations.items()
        for duration in durs
    ]
    events.sort(reverse=True)
    print(f"  {'DURATION':>10}  {'LOCK':<38}  {'THREAD':<15}  LOCATION")
    print(SEP)
    for duration, lock_name, location, thread in events[:10]:
        print(f"  {us_to_human(duration):>10}  {lock_name:<38}  {thread:<15}  {location}")

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
    last_ts = phase_ts.get("last_ts")
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

    if last_ts:
        duration = f"  (duration: {_ts_diff(first_ts, last_ts)})" if first_ts else ""
        print(f"  Log ends:         {last_ts}{duration}")

    print()
