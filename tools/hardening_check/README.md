# System Hardening Check

A small, dependency-free auditor for common Linux misconfigurations — the kind of check a
SOC/security analyst runs as part of routine system-hardening work, not a full vulnerability
scanner.

## What it checks

1. **World-writable files** under a target directory (e.g. `/etc`) — anything any local user
   can modify, a common privilege-escalation and tampering vector.
2. **Unexpected SUID/SGID binaries** — setuid/setgid programs outside a small allowlist of
   expected system binaries (`sudo`, `su`, `passwd`, ...). A SUID binary not on that list is
   a red flag for a backdoor or a misconfigured install.
3. **Insecure `sshd_config` directives** — `PermitRootLogin yes`, `PasswordAuthentication yes`,
   `PermitEmptyPasswords yes`, `Protocol 1`, `X11Forwarding yes`.
4. **Unexpected listening ports** — parses `ss -tuln` and flags any listening port outside an
   allowlist you provide. Skipped (with a note on stderr) if `ss` isn't available or exits
   with a non-zero return code (e.g. insufficient privileges) rather than being treated as
   "zero ports found."

The two file-based checks (world-writable, SUID/SGID) share a single directory walk instead
of scanning the tree twice.

## Usage

```bash
python3 harden_check.py --root /etc --sshd-config /etc/ssh/sshd_config --allow-ports 22,80,443
```

Exit codes: `0` = no findings, `1` = at least one finding, `2` = bad input (`--root` isn't a
directory, or `--allow-ports` isn't a comma-separated list of integers) — suitable for
CI/cron use, where `2` should be treated as a configuration error, not "system is clean."

## Limitations

This is a targeted demonstration of a few high-value checks, not a full CIS-benchmark-style
auditor — real hardening tools (Lynis, OpenSCAP) check hundreds of controls. The SUID
allowlist and insecure-directive list here are illustrative, not exhaustive; a production
version would maintain those per OS distribution and version.
