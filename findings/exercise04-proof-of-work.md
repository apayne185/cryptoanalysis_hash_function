# Exercise 4 — Partial Preimage Search on SHA-256 (Proof-of-Work)

**Target:** [`functions/sha256.py`](../functions/sha256.py) — SHA-256 (via `hashlib`)
**Attack type:** Partial preimage search / proof-of-work
**Implementation:** [`implementation/pow.py`](../implementation/pow.py)
**Solution script:** [`solutions/solve04.sh`](../solutions/solve04.sh)
**Result:** [`submissions/exercise04.txt`](../submissions/exercise04.txt)

## What this demonstrates

Unlike Exercises 1–2, this isn't a vulnerability in SHA-256 — it's the reason SHA-256
*resists* the same attacks that broke the earlier hashes, and how that resistance is
turned into a useful primitive (proof-of-work, exactly as Bitcoin mining uses it).

`implementation/pow.py` searches for ASCII strings of the form `bitcoin<N>` whose SHA-256
digest starts with a specific hex prefix — `cafe`, `faded`, `decade` — by brute-forcing
increasing values of `N`:

```
$ python3 implementation/pow.py
Finding SHA256 starting with 'cafe'...
  'bitcoin42353' -> cafe0337... (after 42354 attempts)
Finding SHA256 starting with 'faded'...
  'bitcoin781629' -> faded78fd... (after 781630 attempts)
Finding SHA256 starting with 'decade'...
  'bitcoin41453713' -> decade7c60... (after 41453714 attempts)
```

Each additional hex digit of required prefix multiplies the expected search space by 16
(one hex digit = 4 bits), which is why `decade` (6 hex digits, `~2^24` expected attempts)
takes roughly 50x longer to find than `cafe` (4 hex digits, `~2^16` expected attempts) —
there is no shortcut available other than trying candidates one at a time.

## Why this doesn't break SHA-256

This is a **partial** preimage search (only the first few bytes of the digest are
constrained) run against a target the attacker gets to construct freely (`bitcoin<N>` for
any `N`) — a fundamentally easier problem than finding a preimage for an *arbitrary fixed*
digest, or a collision between two arbitrary chosen inputs. Even so, the cost still scales
exponentially with the number of constrained bits, with no algebraic shortcuts of the kind
that broke `hash0` and `hash1` — the only lever available is raw compute.

## Real-World Impact

This is exactly the mechanism behind Bitcoin's proof-of-work: miners search for a nonce
such that `SHA256(block_header)` falls below a target threshold (equivalent to requiring
enough leading zero bits). The difficulty is tuned by requiring more leading zero
bits/hex digits, mirroring the `cafe` → `faded` → `decade` progression here. The same
"exponential cost per additional constrained bit, no shortcut" property is what makes
proof-of-work computationally expensive to forge but cheap to verify — the network
just checks one hash per submitted block.

## Mitigation / Takeaway

There's no mitigation here — this is the intended, secure behavior. The takeaway is that
resistance to the same classes of attack demonstrated in Exercises 1–3 (algebraic
inversion, birthday-bound collision search) is precisely what a large, well-mixed digest
space (256 bits, non-linear round function) buys you, and why hash functions used in
security contexts need both properties: a large output space *and* no exploitable internal
structure.
