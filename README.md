# bitcoin-lock-analyzer
Analyzes Bitcoin Core debug.log lock contention

## Instructions

### Enable lock logging in Bitcoin Core

Add to `bitcoin.conf`:
```
debug=lock
```
Or pass `-debug=lock` on the command line. Note this generates a large log.

### Run analysis

```bash
# Read default ~/.bitcoin/debug.log
python3 bitcoin_lock_contention.py

# Custom path
python3 bitcoin_lock_contention.py /path/to/debug.log

# Pipe from tail
tail -n 100000 ~/.bitcoin/debug.log | python3 bitcoin_lock_contention.py -
```
