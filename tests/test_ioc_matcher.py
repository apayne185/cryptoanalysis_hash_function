import os

from hashing import hash_file
from ioc_matcher import load_iocs, scan_directory

EICAR = (
    r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)
EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'


def test_hash_file_matches_known_eicar_digest(tmp_path):
    f = tmp_path / 'eicar.txt'
    f.write_text(EICAR)
    assert hash_file(str(f)) == EICAR_SHA256


def test_scan_directory_flags_known_ioc_and_ignores_clean_file(tmp_path):
    (tmp_path / 'eicar.txt').write_text(EICAR)
    (tmp_path / 'clean.txt').write_text('nothing to see here')

    iocs_path = tmp_path / 'iocs.csv'
    iocs_path.write_text(f'{EICAR_SHA256},EICAR-Test-File\n')
    iocs = load_iocs(str(iocs_path))

    matches = scan_directory(str(tmp_path), iocs)
    matched_files = {os.path.basename(path) for path, _, _ in matches}

    assert matched_files == {'eicar.txt'}


def test_load_iocs_skips_malformed_row_without_crashing(tmp_path):
    iocs_path = tmp_path / 'iocs.csv'
    iocs_path.write_text(
        f'{EICAR_SHA256}\n'  # malformed: no label column
        f'deadbeef,Valid-Entry\n'
    )
    iocs = load_iocs(str(iocs_path))
    assert iocs == {'deadbeef': 'Valid-Entry'}


def test_load_iocs_ignores_comment_with_leading_whitespace(tmp_path):
    iocs_path = tmp_path / 'iocs.csv'
    iocs_path.write_text(
        '  # indented comment, should be skipped, not treated as data\n'
        'deadbeef,Valid-Entry\n'
    )
    iocs = load_iocs(str(iocs_path))
    assert iocs == {'deadbeef': 'Valid-Entry'}


def test_scan_directory_skips_broken_symlink(tmp_path):
    os.symlink(tmp_path / 'missing-target', tmp_path / 'broken_link')
    (tmp_path / 'clean.txt').write_text('nothing to see here')

    matches = scan_directory(str(tmp_path), {})
    assert matches == []
