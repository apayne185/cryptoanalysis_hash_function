import argparse
import hashlib
import json
import os
import sys


def hash_file(path, chunk_size=65536):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()


def scan(root):
    digests = {}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            digests[rel] = hash_file(path)
    return digests


def cmd_baseline(args):
    digests = scan(args.directory)
    with open(args.db, 'w') as f:
        json.dump(digests, f, indent=2, sort_keys=True)
    print(f"Baseline written: {len(digests)} files -> {args.db}")


def cmd_check(args):
    with open(args.db) as f:
        baseline = json.load(f)
    current = scan(args.directory)

    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    modified = sorted(
        path for path in (set(current) & set(baseline))
        if current[path] != baseline[path]
    )

    if not (added or removed or modified):
        print("OK: no changes detected")
        return 0

    for path in added:
        print(f"ADDED    {path}  {current[path]}")
    for path in removed:
        print(f"REMOVED  {path}  {baseline[path]}")
    for path in modified:
        print(f"MODIFIED {path}  {baseline[path]} -> {current[path]}")

    return 1


def main():
    parser = argparse.ArgumentParser(
        description="File integrity monitor: baseline a directory's SHA-256 hashes "
                    "and detect additions, removals, and modifications on later scans."
    )
    sub = parser.add_subparsers(dest='command', required=True)

    p_baseline = sub.add_parser('baseline', help='record a hash baseline for a directory')
    p_baseline.add_argument('directory')
    p_baseline.add_argument('--db', default='baseline.json')
    p_baseline.set_defaults(func=cmd_baseline)

    p_check = sub.add_parser('check', help='compare a directory against a stored baseline')
    p_check.add_argument('directory')
    p_check.add_argument('--db', default='baseline.json')
    p_check.set_defaults(func=cmd_check)

    args = parser.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == '__main__':
    main()
