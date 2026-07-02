import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools', 'ioc_hash_matcher'))
from ioc_matcher import hash_file, load_iocs, scan_directory  # noqa: E402

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
