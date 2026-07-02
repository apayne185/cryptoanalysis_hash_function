import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools', 'password_hash_audit'))
from crack_demo import crack_unsalted, crack_salted_pbkdf2, load_wordlist  # noqa: E402


def test_load_wordlist_nonempty():
    wordlist = load_wordlist()
    assert len(wordlist) > 10
    assert 'password123' in wordlist


def test_crack_unsalted_md5_finds_known_password():
    password = 'password123'
    target = hashlib.md5(password.encode()).hexdigest()
    found, attempts, _ = crack_unsalted(target, 'md5', load_wordlist())
    assert found == password
    assert attempts > 0


def test_crack_unsalted_fails_on_password_outside_wordlist():
    target = hashlib.md5(b'not-in-the-wordlist-xyz987').hexdigest()
    found, _, _ = crack_unsalted(target, 'md5', load_wordlist())
    assert found is None


def test_crack_salted_pbkdf2_finds_known_password_with_correct_salt():
    password = 'password123'
    salt = os.urandom(16)
    iterations = 1000  # low iteration count so the test stays fast
    target = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations).hex()
    found, attempts, _ = crack_salted_pbkdf2(target, salt, iterations, load_wordlist())
    assert found == password
    assert attempts > 0


def test_same_password_different_salts_produce_different_digests():
    password = b'password123'
    d1 = hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 1000).hex()
    d2 = hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 1000).hex()
    assert d1 != d2
