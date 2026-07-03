import argparse
import os
import re
import stat
import subprocess
import sys

DEFAULT_SUID_ALLOWLIST = {
    '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd', '/usr/bin/chsh',
    '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/newgrp', '/usr/bin/mount',
    '/usr/bin/umount', '/usr/bin/pkexec', '/usr/lib/openssh/ssh-keysign',
    '/usr/bin/fusermount', '/usr/bin/fusermount3',
}

# directive -> values that are considered insecure if set
INSECURE_SSHD_DIRECTIVES = {
    'permitrootlogin': {'yes'},
    'passwordauthentication': {'yes'},
    'permitemptypasswords': {'yes'},
    'protocol': {'1'},
    'x11forwarding': {'yes'},
}

_ADDR_PORT_RE = re.compile(r'^.+:(\d+)$')


def _on_walk_error(error):
    print(f"WARNING: skipping directory, cannot list {error.filename}: {error}", file=sys.stderr)


def scan_permissions(root, suid_allowlist=DEFAULT_SUID_ALLOWLIST):
    """Single walk over root, returning (world_writable_paths, unexpected_suid_sgid_paths)."""
    world_writable = []
    suid_sgid = []
    for dirpath, _, filenames in os.walk(root, onerror=_on_walk_error):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_mode & stat.S_IWOTH:
                world_writable.append(path)
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID) and path not in suid_allowlist:
                suid_sgid.append(path)
    return world_writable, suid_sgid


def check_sshd_config(text):
    """Parse sshd_config text, return [(line_no, directive, value)] for insecure directives."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        directive, value = parts[0].lower(), parts[1].strip().lower()
        bad_values = INSECURE_SSHD_DIRECTIVES.get(directive)
        if bad_values and value in bad_values:
            findings.append((lineno, parts[0], parts[1].strip()))
    return findings


def parse_ss_output(output, allowed_ports):
    """Parse `ss -tuln` output, return [(port, local_address)] for ports not in allowed_ports.

    Identifies the local-address column by pattern (ends in ':<digits>') rather than a
    fixed column index, so it isn't thrown off by ss builds that add extra columns
    (e.g. a trailing Process column).
    """
    unexpected = []
    for line in output.splitlines()[1:]:
        for col in line.split():
            m = _ADDR_PORT_RE.match(col)
            if not m:
                continue
            port = int(m.group(1))
            if port not in allowed_ports:
                unexpected.append((port, col))
            break
    return unexpected


def check_listening_ports(allowed_ports):
    """Best-effort: shells out to `ss -tuln`. Returns (unexpected_ports, ss_available)."""
    try:
        result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [], False
    if result.returncode != 0:
        return [], False
    return parse_ss_output(result.stdout, allowed_ports), True


def main():
    parser = argparse.ArgumentParser(
        description="Basic system hardening checks: world-writable files, unexpected "
                    "SUID/SGID binaries, insecure sshd_config directives, and unexpected "
                    "listening ports."
    )
    parser.add_argument('--root', default='/etc', help='directory to scan for world-writable files and SUID/SGID binaries')
    parser.add_argument('--sshd-config', default='/etc/ssh/sshd_config')
    parser.add_argument('--allow-ports', default='22',
                         help='comma-separated list of expected listening ports')
    args = parser.parse_args()

    if not os.path.isdir(args.root):
        print(f"ERROR: --root {args.root!r} is not a directory", file=sys.stderr)
        return 2

    try:
        allowed_ports = {int(p) for p in args.allow_ports.split(',') if p.strip()}
    except ValueError:
        print(f"ERROR: --allow-ports must be a comma-separated list of integers, got {args.allow_ports!r}",
              file=sys.stderr)
        return 2

    findings_found = False

    writable, suid = scan_permissions(args.root)
    if writable:
        findings_found = True
        for path in writable:
            print(f"WORLD-WRITABLE  {path}")
    if suid:
        findings_found = True
        for path in suid:
            print(f"UNEXPECTED-SUID/SGID  {path}")

    if os.path.isfile(args.sshd_config):
        with open(args.sshd_config) as f:
            sshd_findings = check_sshd_config(f.read())
        if sshd_findings:
            findings_found = True
            for lineno, directive, value in sshd_findings:
                print(f"INSECURE-SSHD-CONFIG  {args.sshd_config}:{lineno}  {directive} {value}")

    ports, ss_available = check_listening_ports(allowed_ports)
    if not ss_available:
        print("NOTE: 'ss' unavailable or failed, skipping listening-port check", file=sys.stderr)
    elif ports:
        findings_found = True
        for port, addr in ports:
            print(f"UNEXPECTED-LISTENING-PORT  {port}  ({addr})")

    if not findings_found:
        print("OK: no hardening issues found")
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
