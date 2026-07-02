import hashlib
import os
import sys


def hash_file(path, chunk_size=65536):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()


def walk_and_hash(root, exclude=None):
    """Yield (path, digest) for every readable file under root.

    Unreadable files and broken symlinks are skipped with a warning on
    stderr instead of aborting the whole walk. `exclude`, if given, is an
    absolute path to skip silently (e.g. a baseline/output file that lives
    inside the scanned tree).
    """
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            if exclude is not None and os.path.abspath(path) == exclude:
                continue
            try:
                digest = hash_file(path)
            except OSError as e:
                print(f"WARNING: skipping {path}: {e}", file=sys.stderr)
                continue
            yield path, digest
