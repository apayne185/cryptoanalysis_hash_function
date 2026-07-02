# File Integrity Monitor

A minimal file integrity monitor — the same pattern tools like Tripwire/AIDE use to detect
unauthorized changes on a filesystem: hash every file under a directory, store that as a
baseline, and flag anything added, removed, or modified on a later scan.

This only works because SHA-256 is collision-resistant (see [findings/exercise01-collision-attack.md](../../findings/exercise01-collision-attack.md)
for what happens when it isn't) — an attacker can't tamper with a monitored file and
produce the same digest, so any change is detectable.

## Usage

```bash
# record a baseline
python3 fim.py baseline /path/to/watch --db baseline.json

# later, check for drift (exit code 0 = clean, 1 = changes detected)
python3 fim.py check /path/to/watch --db baseline.json
```

Example output after a file is edited, one is deleted, and one is added:

```
ADDED    c.txt  7aa7a5...
REMOVED  b.txt  e258d2...
MODIFIED a.txt  5891b5... -> 92e78d...
```

## Behavior notes

- Unreadable files and broken symlinks are skipped with a `WARNING` on stderr rather than
  aborting the whole scan.
- The baseline file is automatically excluded from its own scan, so storing `--db` inside
  the watched directory (e.g. `fim.py baseline .`) doesn't cause the baseline to flag
  itself as an unexpected addition on the next `check`.

## Limitations

This is a demonstration of the core mechanism, not a hardened production tool: the
baseline file itself isn't signed or protected, so an attacker with write access to both
the monitored files and the baseline could update both. A production FIM stores the
baseline out-of-band (write-once storage, remote signing) for that reason.
