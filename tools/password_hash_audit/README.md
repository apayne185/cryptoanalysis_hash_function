# Password Hash Security Audit

Demonstrates why unsalted, fast hash functions (MD5, SHA-1) are unsafe for password
storage, and why salted, iterated KDFs (PBKDF2, bcrypt, scrypt, Argon2) resist the same
attack even against an identical, weak password. This ties directly back to the
[preimage attack in Exercise 2](../../findings/exercise02-preimage-attack.md): password
hashing is exactly the "commitment without revealing the secret" use case that breaks when
a hash is fast to invert or search.

## Usage

```bash
python3 crack_demo.py --password password123 --iterations 200000
```

`--iterations` must be a positive integer; `0` or a negative value is rejected with a clean
argparse error rather than crashing inside `hashlib.pbkdf2_hmac`.

## What it shows

1. **Unsalted MD5/SHA1 dictionary attack** — hashing every candidate in `wordlist.txt`
   (~80 common passwords) and comparing against the target digest takes a fraction of a
   millisecond, because MD5/SHA1 are designed to be *fast*.
2. **Salted PBKDF2-SHA256 with 200,000 iterations** against the *same* wordlist and the
   *same* password takes roughly 3–4 orders of magnitude longer, because each candidate
   costs 200,000 hash rounds instead of one. That slowdown compounds across every password
   in a breached database — the same property that makes it annoying for a legitimate
   login (one PBKDF2 call) makes it far more expensive at attacker scale (millions of
   candidates × millions of accounts).
3. **Salting defeats precomputation** — hashing the same password twice with independent
   random salts produces two completely different digests. A precomputed rainbow table for
   unsalted MD5 is useless here, since the attacker would need a fresh table per salt.

## Why the demo password still "cracks"

The demo password is deliberately weak and present in the wordlist — the point isn't that
PBKDF2 makes weak passwords uncrackable, it's that PBKDF2 makes cracking *cost* dramatically
more per guess. A strong, unpredictable password combined with a slow KDF is what actually
resists both dictionary and brute-force attacks.
