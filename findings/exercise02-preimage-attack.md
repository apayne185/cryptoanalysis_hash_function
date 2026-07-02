# Exercise 2 — First-Preimage Attack on `hash0` (XOR32)

**Target:** [`functions/hash0.py`](../functions/hash0.py) — `xor32_hash`
**Attack type:** First-preimage attack (manual, target digest `1b575451`)
**Solution script:** [`solutions/solve02.sh`](../solutions/solve02.sh)
**Result:** [`submissions/exercise02.txt`](../submissions/exercise02.txt)

## Vulnerability

Because each output byte lane is the XOR of exactly the input characters that fall in that
lane (see [Exercise 1](exercise01-collision-attack.md)), the transform is trivially
invertible: given a target digest, pick any fixed value for the "even" character in each
lane and solve for the other via `target_byte ^ fixed_byte`.

## Proof of Concept

Target digest: `1b575451`. Fixing positions 4–7 to `'0' 0'0' '0'` (`0x30` each) and solving
each lane for positions 0–3:

```
byte0: 0x51 ^ 0x30 = 0x61 = 'a'   (lane 0: positions 0, 4)
byte1: 0x54 ^ 0x30 = 0x64 = 'd'   (lane 1: positions 1, 5)
byte2: 0x57 ^ 0x30 = 0x67 = 'g'   (lane 2: positions 2, 6)
byte3: 0x1b ^ 0x30 = 0x2b = '+'   (lane 3: positions 3, 7)
```

Giving the preimage `adg+0000`:

```
$ python3 functions/hash0.py 'adg+0000'
1b575451
```

## Real-World Impact

Preimage resistance is what makes it safe to publish a hash without revealing the input it
came from. If a hash function can be inverted:

- **Password hashing breaks entirely** — a leaked hash directly yields a valid (if not
  the exact original) password, since the attacker can construct *any* preimage that
  reproduces the stored digest.
- **Commitment schemes fail** — protocols that rely on "I hashed a secret now, I'll reveal
  it later to prove I knew it" no longer prove anything, since anyone can construct a value
  matching a public hash after the fact.
- **Proof-of-work / rate-limiting schemes become forgeable** without doing the intended work.

## Mitigation

Use a hash function where output bytes are the product of many rounds of non-linear mixing
across the *entire* input, not an independent, closed-form function of a small subset of
input bytes. SHA-256's compression function makes deriving a preimage this way infeasible —
the only known approach is brute force search (see Exercise 4).
