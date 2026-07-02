import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools', 'file_integrity_monitor'))
from fim import scan, cmd_baseline, cmd_check  # noqa: E402


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
