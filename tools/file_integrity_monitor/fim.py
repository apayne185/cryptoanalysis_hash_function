import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))
from hashing import walk_and_hash  # noqa: E402


def scan(root, exclude=None):
    digests = {}
    for path, digest in walk_and_hash(root, exclude=exclude):
        rel = os.path.relpath(path, root)
        digests[rel] = digest
    return digests


def cmd_baseline(args):
    db_path = os.path.abspath(args.db)
    digests = scan(args.directory, exclude=db_path)
    with open(args.db, 'w') as f:
        json.dump(digests, f, indent=2, sort_keys=True)
    print(f"Baseline written: {len(digests)} files -> {args.db}")


def cmd_check(args):
    db_path = os.path.abspath(args.db)
    try:
        with open(args.db) as f:
            baseline = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: baseline {args.db!r} not found, run `baseline` first", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"ERROR: baseline {args.db!r} is not valid JSON: {e}", file=sys.stderr)
        return 2
    current = scan(args.directory, exclude=db_path)

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
