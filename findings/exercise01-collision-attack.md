# Exercise 1 — Collision Attack on `hash0` (XOR32)

**Target:** [`functions/hash0.py`](../functions/hash0.py) — `xor32_hash`
**Attack type:** Collision attack (manual)
**Solution script:** [`solutions/solve01.sh`](../solutions/solve01.sh)
**Result:** [`submissions/exercise01.txt`](../submissions/exercise01.txt)

## Vulnerability

`xor32_hash` folds an 8-character ASCII string into 32 bits by XOR-ing each character into
one of 4 byte lanes, based on `i % 4`:

```python
shift = (i % 4) * 8
h ^= (ord(c) << shift)
```

XOR is commutative and self-cancelling (`a ^ b ^ a = b`), and each lane only ever
accumulates characters at positions `i`, `i+4` (i.e. positions 0/4, 1/5, 2/6, 3/7 share a
lane). That means the digest only depends on the XOR of each same-lane character pair, not
on their order or their individual values — collapsing a huge input space onto a 32-bit
output through a completely predictable, invertible-by-hand transformation.

## Proof of Concept

Two 8-character strings that differ only in which half holds the "b", `baaaaaaa` and
`aaaabaaa`, hash identically:

```
$ python3 functions/hash0.py baaaaaaa
00000003
$ python3 functions/hash0.py aaaabaaa
00000003
```

Because lane 0 XORs `s[0]` with `s[4]`, `s[0]='b', s[4]='a'` and `s[0]='a', s[4]='b'`
produce the same XOR (`'a' ^ 'b'` either way) — the function can't tell which half the
byte was in.

## Real-World Impact

A hash used to fingerprint or deduplicate data must make it computationally infeasible to
find two distinct inputs with the same digest. If it doesn't:

- **Data integrity checks are worthless** — an attacker can swap a file for a
  different one with the same "fingerprint" and the swap goes undetected.
- **Digital signatures break** — since signature schemes sign the hash, not the message,
  finding a colliding second message lets an attacker present a forged document under a
  legitimate signature.
- **Deduplication/caching systems can be poisoned**, since two different pieces of content
  collapse to the same key.

## Mitigation

Use a cryptographic hash function designed for collision resistance (SHA-256 or stronger),
where the internal mixing (nonlinear S-boxes, many rounds of diffusion) ensures no
low-cost algebraic shortcut like "just XOR the right half" exists. See Exercise 4 for why
SHA-256 resists this class of attack.
