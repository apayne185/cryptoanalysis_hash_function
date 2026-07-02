# Hash-Based IOC Matcher

Hashes every file under a directory with SHA-256 and flags any digest that matches a known
indicator of compromise (IOC). This is the core mechanism behind AV/EDR hash-based
detection: a curated list of known-malicious file hashes gets checked against everything on
disk, and a match is a high-confidence signal — false positives are essentially impossible
because it relies on the same collision resistance property demonstrated (and broken, for
weak hashes) in [Exercise 1](../../findings/exercise01-collision-attack.md).

## Usage

```bash
python3 ioc_matcher.py /path/to/scan --iocs sample_iocs.csv
```

`sample_iocs.csv` is a CSV of `sha256,label` pairs. The bundled sample contains the SHA-256
of the [EICAR standard antivirus test file](https://www.eicar.org/download-anti-malware-testfile/) —
a harmless string every AV/EDR vendor recognizes as a self-test signature, used here instead
of real malware hashes so the demo is safe to run and share.

## Limitations

Hash-based matching only catches *exact known* files — trivial to evade by changing a
single byte (which is why real EDR pairs it with behavioral/heuristic detection). It's
useful as a fast, cheap, zero-false-positive first pass, not a complete detection strategy.
