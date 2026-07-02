# Decisions

## Coursework origin

The four exercises (weak-hash collision/preimage attacks, birthday-paradox brute force,
SHA-256 partial preimage/proof-of-work) originate from a university cryptography assignment
(`docs/assignment-instructions.pdf`). The hash functions under test (`functions/hash0.py`,
`functions/hash1.py`) and the exercise targets/constants were provided by the assignment;
the attack implementations and solutions were written independently.

## What was extended beyond the original submission

- Repository structure was reorganized: duplicate/dead code removed (two near-identical
  copies of the SHA-256 proof-of-work script existed in `functions/` and
  `implementation/` — consolidated into one), macOS artifacts (`__MACOSX/`, `.DS_Store`)
  and bytecode caches removed, `.gitignore` fixed (it was previously ignoring tracked
  source files instead of build artifacts).
- Output file naming was standardized. The original assignment PDF asks for exercise 4's
  result at `solutions/exercise06.txt` — an inconsistency in the assignment itself relative
  to the other three exercises, which all follow `submissions/exerciseNN.txt` matching their
  actual exercise number. This repo uses `submissions/exercise04.txt` consistently instead.
- Each exercise got a `findings/` write-up in vulnerability-report format (vulnerability,
  proof of concept, real-world impact, mitigation) rather than just the raw code and
  output artifact, to make the security reasoning explicit rather than implicit in the code.
- The PDF was moved to `docs/` and the README rewritten to frame the repo around the
  security properties being demonstrated rather than as assignment submissions.

## Modeling / implementation notes

- `hash0.py` (XOR-based) and `hash1.py` (djb2-style, `h = h*31 + c`) are both intentionally
  weak 32-bit hashes provided as attack targets — they are not meant to represent real-world
  hash function design, only to make the underlying attacks (bit manipulation, birthday
  paradox) tractable by hand or on a laptop.
- Exercise 3's birthday-paradox collision search is unbounded (loops until a collision is
  found) rather than capped at `2^16` attempts, since expected time to collision for a
  32-bit hash is close to `sqrt(2^32) ≈ 65536` tries but is a random variable, not a hard
  cap.
