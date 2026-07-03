import argparse
import hashlib
import os

import pytest

from crack_demo import crack, load_wordlist, positive_int


def test_load_wordlist_nonempty():
    wordlist = load_wordlist()
    assert len(wordlist) > 10
    assert 'password123' in wordlist


def test_crack_unsalted_md5_finds_known_password():
    password = 'password123'
    target = hashlib.md5(password.encode()).hexdigest()
    found, attempts, _ = crack(target, load_wordlist(), lambda w: hashlib.md5(w.encode()).hexdigest())
    assert found == password
    assert attempts > 0


def test_crack_unsalted_fails_on_password_outside_wordlist():
    target = hashlib.md5(b'not-in-the-wordlist-xyz987').hexdigest()
    found, _, _ = crack(target, load_wordlist(), lambda w: hashlib.md5(w.encode()).hexdigest())
    assert found is None


def test_crack_salted_pbkdf2_finds_known_password_with_correct_salt():
    password = 'password123'
    salt = os.urandom(16)
    iterations = 1000  # low iteration count so the test stays fast
    target = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations).hex()
    hash_fn = lambda w: hashlib.pbkdf2_hmac('sha256', w.encode(), salt, iterations).hex()
    found, attempts, _ = crack(target, load_wordlist(), hash_fn)
    assert found == password
    assert attempts > 0


def test_same_password_different_salts_produce_different_digests():
    password = b'password123'
    d1 = hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 1000).hex()
    d2 = hashlib.pbkdf2_hmac('sha256', password, os.urandom(16), 1000).hex()
    assert d1 != d2


@pytest.mark.parametrize('value', ['0', '-5'])
def test_positive_int_rejects_zero_and_negative(value):
    with pytest.raises(argparse.ArgumentTypeError):
        positive_int(value)


def test_positive_int_accepts_positive_value():
    assert positive_int('1000') == 1000
