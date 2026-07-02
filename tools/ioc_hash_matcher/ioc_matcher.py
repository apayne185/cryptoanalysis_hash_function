import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))
from hashing import walk_and_hash  # noqa: E402


def load_iocs(path):
    iocs = {}
    with open(path, newline='') as f:
        for lineno, row in enumerate(csv.reader(f), start=1):
            if not row or row[0].strip().startswith('#'):
                continue
            if len(row) < 2:
                print(f"WARNING: skipping malformed IOC row {lineno} in {path}: {row}",
                      file=sys.stderr)
                continue
            digest, label = row[0].strip().lower(), row[1].strip()
            iocs[digest] = label
    return iocs


def scan_directory(directory, iocs):
    matches = []
    for path, digest in walk_and_hash(directory):
        if digest in iocs:
            matches.append((path, digest, iocs[digest]))
    return matches


def main():
    parser = argparse.ArgumentParser(
        description="Hash-based IOC matcher: SHA-256 every file under a directory and "
                    "flag any digest present in a known-indicator (IOC) list, the same "
                    "core mechanism EDR/AV hash-matching engines use."
    )
    parser.add_argument('directory')
    parser.add_argument('--iocs', default=os.path.join(os.path.dirname(__file__), 'sample_iocs.csv'))
    args = parser.parse_args()

    iocs = load_iocs(args.iocs)
    matches = scan_directory(args.directory, iocs)

    if not matches:
        print(f"OK: no known indicators matched ({len(iocs)} IOCs checked)")
        return 0

    for path, digest, label in matches:
        print(f"MATCH  {path}  {digest}  {label}")
    return 1


if __name__ == '__main__':
    sys.exit(main())
