import hashlib
import os
import stat
import sys


def hash_file(path, chunk_size=65536):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()


def _on_walk_error(error):
    print(f"WARNING: skipping directory, cannot list {error.filename}: {error}", file=sys.stderr)


def walk_and_hash(root, exclude=None):
    """Yield (path, digest) for every readable regular file under root.

    Unreadable files, unreadable directories, broken symlinks, and non-regular
    files (FIFOs, devices, sockets) are skipped with a warning on stderr
    instead of aborting or hanging the walk. `exclude`, if given, is an
    absolute path to skip silently (e.g. a baseline/output file that lives
    inside the scanned tree).
    """
    for dirpath, _, filenames in os.walk(root, onerror=_on_walk_error):
        for name in filenames:
            path = os.path.join(dirpath, name)
            if exclude is not None and os.path.abspath(path) == exclude:
                continue
            try:
                st = os.stat(path)  # follows symlinks, unlike lstat
            except OSError as e:
                print(f"WARNING: skipping {path}: {e}", file=sys.stderr)
                continue
            if not stat.S_ISREG(st.st_mode):
                print(f"WARNING: skipping {path}: not a regular file", file=sys.stderr)
                continue
            try:
                digest = hash_file(path)
            except OSError as e:
                print(f"WARNING: skipping {path}: {e}", file=sys.stderr)
                continue
            yield path, digest
