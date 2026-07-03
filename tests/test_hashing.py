import os

from hashing import walk_and_hash


def test_walk_and_hash_follows_valid_symlinks(tmp_path):
    target = tmp_path / 'target.txt'
    target.write_text('hello')
    link = tmp_path / 'link.txt'
    os.symlink(target, link)

    results = dict(walk_and_hash(str(tmp_path)))
    assert results[str(link)] == results[str(target)]


def test_walk_and_hash_skips_broken_symlink(tmp_path):
    link = tmp_path / 'broken.txt'
    os.symlink(tmp_path / 'missing', link)

    results = dict(walk_and_hash(str(tmp_path)))
    assert str(link) not in results


def test_walk_and_hash_skips_fifo_instead_of_hanging(tmp_path):
    fifo = tmp_path / 'a_fifo'
    os.mkfifo(fifo)

    results = dict(walk_and_hash(str(tmp_path)))
    assert str(fifo) not in results


def test_walk_and_hash_skips_unreadable_directory(tmp_path):
    locked = tmp_path / 'locked'
    locked.mkdir()
    (locked / 'secret.txt').write_text('hidden')
    visible = tmp_path / 'visible.txt'
    visible.write_text('ok')

    os.chmod(locked, 0o000)
    try:
        results = dict(walk_and_hash(str(tmp_path)))
    finally:
        os.chmod(locked, 0o755)

    assert str(visible) in results
    assert all('locked' not in path for path in results)
