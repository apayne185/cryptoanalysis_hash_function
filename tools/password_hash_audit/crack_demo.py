import argparse
import hashlib
import os
import time

WORDLIST_PATH = os.path.join(os.path.dirname(__file__), 'wordlist.txt')


def load_wordlist():
    with open(WORDLIST_PATH) as f:
        return [line.strip() for line in f if line.strip()]


def crack_unsalted(target_digest, algo, wordlist):
    start = time.perf_counter()
    for i, word in enumerate(wordlist, start=1):
        digest = hashlib.new(algo, word.encode()).hexdigest()
        if digest == target_digest:
            return word, i, time.perf_counter() - start
    return None, len(wordlist), time.perf_counter() - start


def crack_salted_pbkdf2(target_digest, salt, iterations, wordlist):
    start = time.perf_counter()
    for i, word in enumerate(wordlist, start=1):
        digest = hashlib.pbkdf2_hmac('sha256', word.encode(), salt, iterations).hex()
        if digest == target_digest:
            return word, i, time.perf_counter() - start
    return None, len(wordlist), time.perf_counter() - start


def demo(password, iterations):
    wordlist = load_wordlist()
    print(f"Target password: {password!r}  (dictionary attack, {len(wordlist)} candidates)\n")

    for algo in ('md5', 'sha1'):
        target = hashlib.new(algo, password.encode()).hexdigest()
        found, attempts, elapsed = crack_unsalted(target, algo, wordlist)
        status = f"cracked as {found!r}" if found else "not found"
        print(f"unsalted {algo.upper():<5} {target}  -> {status} "
              f"({attempts} attempts, {elapsed*1000:.2f} ms)")

    salt = os.urandom(16)
    target = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations).hex()
    found, attempts, elapsed = crack_salted_pbkdf2(target, salt, iterations, wordlist)
    status = f"cracked as {found!r}" if found else "not found"
    print(f"salted PBKDF2-SHA256 ({iterations} iters)  -> {status} "
          f"({attempts} attempts, {elapsed*1000:.2f} ms)")

    print(f"\nSame password, two independent salts -> different stored hashes "
          f"(defeats precomputed/rainbow-table attacks):")
    for _ in range(2):
        s = os.urandom(16)
        d = hashlib.pbkdf2_hmac('sha256', password.encode(), s, iterations).hex()
        print(f"  salt={s.hex()}  hash={d}")


def main():
    parser = argparse.ArgumentParser(
        description="Password hashing security demo: dictionary-attack an unsalted "
                    "MD5/SHA1 hash vs a salted, iterated PBKDF2-SHA256 hash of the same "
                    "weak password, and compare cost."
    )
    parser.add_argument('--password', default='password123',
                         help='password to hash and attempt to crack (must be in wordlist.txt to be found)')
    parser.add_argument('--iterations', type=int, default=200_000,
                         help='PBKDF2 iteration count (higher = slower to crack, slower to verify)')
    args = parser.parse_args()
    demo(args.password, args.iterations)


if __name__ == '__main__':
    main()
