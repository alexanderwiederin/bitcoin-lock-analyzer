# bitcoin-lock-analyzer
Analyzes Bitcoin Core debug.log lock contention

### Limitations

Phase boundaries are detected via log line pattern matching. `Synchronizing
blockheaders ~100.00` for Header Sync end and `UpdateTip: progress=1.000000`
for IBD end. This is brittle but sufficient for the goal of reducing phase
pollution.

Three deeper limitations apply to the analysis itself:

**Conention data measures collisions, not opportunities.** Threads structurally prevented from running concurrently never appear in the data.

**Lock Held data is samled.** Only lock events above the logging threshold of 1ms are recorded. Short holds are invisible.

**IBD is the wrong phase for actionable conclusions.** The pipeline is intentionally sequential so contention is suppressed.

## Instructions

### Enable lock logging in Bitcoin Core

For **lock held logs**, you'll need a patched version of Bitcoin Core that adds
this instrumentation. The branch instruments `UniqueLock` in
`sync.cpp`/`sync.h` to record acquisition timestamps and log any any lock held
longer than 1ms under the existing `DEBUG_LOCKCONTENTION` guard.

```
git clone https://github.com/alexanderwiederin/bitcoin.git
cd bitcoin
git checkout lock-held-logs
```

Add to `bitcoin.conf`:
```
debug=lock
```
Or pass `-debug=lock` on the command line. Note this generates a large log.

### Run analysis

#### Lock Contention Analysis

The `contention_analyzer` looks at how long threads spent *waiting* to acquire locks.

```bash
# Read default ~/.bitcoin/debug.log
python3 contention_analyzer.py

# Custom path
python3 contention_analyzer.py /path/to/debug.log
```

#### Lock Held times Analysis

The `lock_held_analyzer` looks at how long locks were held, i.e. the
opportunity window for collisions.
```bash
# Read default ~/.bitcoin/debug.log
python3 lock_held_analyzer.py

# Custom path
python3 lock_held_analyzer.py /path/to/debug.log
```

