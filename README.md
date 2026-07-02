# Hash Function Security Toolkit

A hands-on demonstration of why cryptographic hash function properties — **collision
resistance** and **preimage resistance** — matter in practice, and what breaks when they're
missing. Each exercise attacks a hash function of increasing strength and documents the
attack as a mini security finding: vulnerability, proof of concept, real-world impact, and
mitigation.

The `tools/` directory extends this into practical blue-team tooling built on the same
hashing primitives: file integrity monitoring, IOC-based threat detection, and password
hash security auditing.

**Stack:** Python · Bash · SHA-256 · Birthday-paradox cryptanalysis · Proof-of-work · pytest

## Why this matters

Hash functions underpin file integrity checks, digital signatures, password storage, and
commitment schemes. If an attacker can find collisions or invert a hash, they can forge
signatures, swap out files without detection, or recover secrets that were supposed to stay
hidden. This repo walks through that failure mode concretely, on functions weak enough to
break by hand or with a laptop, before showing why SHA-256 resists the same attacks.

## Exercises

| # | Target | Attack | Write-up |
|---|--------|--------|----------|
| 1 | [`functions/hash0.py`](functions/hash0.py) — 32-bit XOR hash | Manual collision attack | [findings/exercise01-collision-attack.md](findings/exercise01-collision-attack.md) |
| 2 | [`functions/hash0.py`](functions/hash0.py) — 32-bit XOR hash | First-preimage attack | [findings/exercise02-preimage-attack.md](findings/exercise02-preimage-attack.md) |
| 3 | [`functions/hash1.py`](functions/hash1.py) — djb2-style hash | Birthday-paradox brute-force collision | [findings/exercise03-birthday-collision.md](findings/exercise03-birthday-collision.md) |
| 4 | [`functions/sha256.py`](functions/sha256.py) — SHA-256 | Partial preimage / proof-of-work search | [findings/exercise04-proof-of-work.md](findings/exercise04-proof-of-work.md) |

## Blue-team tooling (`tools/`)

| Tool | What it does |
|------|--------------|
| [`file_integrity_monitor/`](tools/file_integrity_monitor/) | Baselines SHA-256 hashes of a directory tree and detects additions/removals/modifications on later scans (the Tripwire/AIDE pattern) |
| [`ioc_hash_matcher/`](tools/ioc_hash_matcher/) | Hashes files under a directory and flags any digest matching a known indicator of compromise (the core mechanism behind AV/EDR hash-based detection) |
| [`password_hash_audit/`](tools/password_hash_audit/) | Dictionary-attacks an unsalted MD5/SHA1 password hash vs. a salted, iterated PBKDF2-SHA256 hash of the same password, and compares the cost |

Each tool has its own README explaining the mechanism, usage, and limitations, and is
covered by tests in [`tests/`](tests/).

## Structure

```
functions/       hash functions under test
implementation/  attack source code (brute-force collision finder, PoW search)
solutions/       bash runners that execute each attack and produce the result artifact
submissions/     result artifacts produced by the solutions scripts
findings/        per-exercise vulnerability write-ups (PoC + real-world impact + mitigation)
tools/           blue-team tooling built on the same hashing primitives
tests/           pytest suite for tools/
docs/            original assignment instructions
```

## Running it

```bash
bash solutions/solve01.sh   # collision attack, hash0 (manual, instant)
bash solutions/solve02.sh   # preimage attack, hash0 (manual, instant)
bash solutions/solve03.sh   # birthday-paradox collision, hash1 (brute-force, seconds)
bash solutions/solve04.sh   # SHA-256 partial-preimage search (brute-force, seconds)

python3 tools/file_integrity_monitor/fim.py baseline <dir> --db baseline.json
python3 tools/ioc_hash_matcher/ioc_matcher.py <dir>
python3 tools/password_hash_audit/crack_demo.py

python3 -m pytest tests/    # run the test suite
```

## Origin

This started as a cryptography coursework assignment (see
[docs/assignment-instructions.pdf](docs/assignment-instructions.pdf)). See
[DECISIONS.md](DECISIONS.md) for what was original coursework versus what was extended
afterward.
