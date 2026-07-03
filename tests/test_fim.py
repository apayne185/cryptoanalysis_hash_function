import json
import os

from fim import scan, cmd_baseline, cmd_check


class Args:
    def __init__(self, directory, db):
        self.directory = directory
        self.db = db


def test_baseline_and_check_clean(tmp_path):
    watched = tmp_path / 'watched'
    watched.mkdir()
    (watched / 'a.txt').write_text('hello')
    db = tmp_path / 'baseline.json'

    cmd_baseline(Args(str(watched), str(db)))
    assert json.loads(db.read_text()) == scan(str(watched))
    assert cmd_check(Args(str(watched), str(db))) == 0


def test_check_detects_modification_addition_removal(tmp_path):
    watched = tmp_path / 'watched'
    watched.mkdir()
    (watched / 'a.txt').write_text('hello')
    (watched / 'b.txt').write_text('world')
    db = tmp_path / 'baseline.json'
    cmd_baseline(Args(str(watched), str(db)))

    (watched / 'a.txt').write_text('tampered')
    (watched / 'b.txt').unlink()
    (watched / 'c.txt').write_text('new')

    assert cmd_check(Args(str(watched), str(db))) == 1


def test_scan_skips_broken_symlink_instead_of_crashing(tmp_path):
    watched = tmp_path / 'watched'
    watched.mkdir()
    (watched / 'a.txt').write_text('hello')
    os.symlink(watched / 'missing-target', watched / 'broken_link')

    digests = scan(str(watched))
    assert set(digests) == {'a.txt'}


def test_baseline_stored_inside_watched_dir_does_not_self_flag(tmp_path):
    watched = tmp_path / 'watched'
    watched.mkdir()
    (watched / 'a.txt').write_text('hello')
    db = watched / 'baseline.json'

    cmd_baseline(Args(str(watched), str(db)))
    assert cmd_check(Args(str(watched), str(db))) == 0


def test_check_missing_baseline_returns_error_instead_of_crashing(tmp_path, capsys):
    watched = tmp_path / 'watched'
    watched.mkdir()
    db = tmp_path / 'does-not-exist.json'

    assert cmd_check(Args(str(watched), str(db))) == 2
    assert 'not found' in capsys.readouterr().err


def test_check_corrupt_baseline_returns_error_instead_of_crashing(tmp_path, capsys):
    watched = tmp_path / 'watched'
    watched.mkdir()
    db = tmp_path / 'corrupt.json'
    db.write_text('{not valid json')

    assert cmd_check(Args(str(watched), str(db))) == 2
    assert 'not valid JSON' in capsys.readouterr().err
