import argparse
import csv
import hashlib
import os
import sys


def hash_file(path, chunk_size=65536):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()


def load_iocs(path):
    iocs = {}
    with open(path, newline='') as f:
        for row in csv.reader(f):
            if not row or row[0].startswith('#'):
                continue
            digest, label = row[0].strip().lower(), row[1].strip()
            iocs[digest] = label
    return iocs


def scan_directory(directory, iocs):
    matches = []
    for dirpath, _, filenames in os.walk(directory):
        for name in filenames:
            path = os.path.join(dirpath, name)
            digest = hash_file(path)
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
