# Exercise 3 — Birthday-Paradox Collision Attack on `hash1`

**Target:** [`functions/hash1.py`](../functions/hash1.py) — `simple_hash` (djb2-style: `h = h*31 + c`)
**Attack type:** Birthday-paradox brute-force collision
**Implementation:** [`implementation/brute.py`](../implementation/brute.py)
**Solution script:** [`solutions/solve03.sh`](../solutions/solve03.sh)
**Result:** [`submissions/exercise03.txt`](../submissions/exercise03.txt)

## Vulnerability

`simple_hash` mixes each character in with multiply-and-add (`h = (h << 5) - h + ord(c)`,
equivalent to `h = h*31 + c`), which resists the by-hand algebraic inversion used against
`hash0` — there's no independent per-lane structure to exploit. But it's still only a
**32-bit** output, and 32 bits is far too small a space for a hash used against an
adversary who can generate and check candidates cheaply.

By the birthday paradox, a collision among random 32-bit outputs is expected after roughly
`sqrt(2^32) ≈ 65,536` samples — not the `2^32 ≈ 4.3 billion` naive brute force intuition
might suggest.

## Proof of Concept

[`implementation/brute.py`](../implementation/brute.py) generates random 8-character ASCII
strings, hashes each with `simple_hash`, and checks a dictionary of `{digest: string}` seen
so far. The first repeated digest is a collision:

```
$ python3 implementation/brute.py
Collision found with <tens of thousands> attempts
h}-6nF2b -> 57db4086
!w4F{$t) -> 57db4086
```

Runs in seconds to low minutes on a laptop — well within the "few seconds to minutes"
the assignment predicted for a birthday-paradox-aware approach, versus the hours a
naive linear search over the full `2^32` space would take.

## Real-World Impact

32-bit (and even 64-bit) digests are unsafe for any security use, no matter how good the
internal mixing is, because the birthday bound applies regardless of how "random-looking"
the output is:

- **Any system using short hashes for authentication tokens, file fingerprints, or
  transaction IDs** is one automated script away from a forged collision.
- This is why real cryptographic hashes (SHA-256, SHA-3) use ≥256-bit output — the birthday
  bound then requires `~2^128` attempts, which is computationally infeasible.

## Mitigation

Use a hash function with an output space large enough that the birthday bound
(`sqrt(2^n)`) itself is infeasible to brute-force — in practice, 256 bits or more for any
new design. Output size is a distinct requirement from having good internal mixing; a hash
needs both.
