import os
import stat
import subprocess

from harden_check import (
    scan_permissions,
    check_sshd_config,
    parse_ss_output,
    check_listening_ports,
    main,
)


def test_scan_permissions_flags_world_writable_file(tmp_path):
    writable = tmp_path / 'writable.txt'
    writable.write_text('x')
    os.chmod(writable, 0o666)

    safe = tmp_path / 'safe.txt'
    safe.write_text('x')
    os.chmod(safe, 0o644)

    world_writable, _ = scan_permissions(str(tmp_path))
    assert world_writable == [str(writable)]


def test_scan_permissions_skips_symlinks(tmp_path):
    target = tmp_path / 'target.txt'
    target.write_text('x')
    os.chmod(target, 0o644)
    link = tmp_path / 'link.txt'
    os.symlink(target, link)

    world_writable, suid = scan_permissions(str(tmp_path))
    assert world_writable == []
    assert suid == []


def test_scan_permissions_flags_unexpected_suid_and_respects_allowlist(tmp_path):
    unexpected = tmp_path / 'suspicious'
    unexpected.write_text('x')
    os.chmod(unexpected, 0o755 | stat.S_ISUID)

    allowed = tmp_path / 'allowed'
    allowed.write_text('x')
    os.chmod(allowed, 0o755 | stat.S_ISUID)

    _, suid = scan_permissions(str(tmp_path), suid_allowlist={str(allowed)})
    assert suid == [str(unexpected)]


def test_check_sshd_config_flags_insecure_directives():
    config = """
# comment line, should be ignored
PermitRootLogin yes
PasswordAuthentication no
Port 2222
"""
    findings = check_sshd_config(config)
    assert findings == [(3, 'PermitRootLogin', 'yes')]


def test_check_sshd_config_ignores_secure_settings():
    config = "PermitRootLogin no\nPasswordAuthentication no\n"
    assert check_sshd_config(config) == []


def test_parse_ss_output_flags_unexpected_ports():
    output = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "tcp   LISTEN 0      128    0.0.0.0:22           0.0.0.0:*\n"
        "tcp   LISTEN 0      128    0.0.0.0:31337         0.0.0.0:*\n"
    )
    unexpected = parse_ss_output(output, allowed_ports={22})
    assert unexpected == [(31337, '0.0.0.0:31337')]


def test_parse_ss_output_handles_ipv6_and_scoped_addresses():
    output = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "udp   UNCONN 0      0      127.0.0.53%lo:53      0.0.0.0:*\n"
        "tcp   LISTEN 0      128    [::]:45020            [::]:*\n"
    )
    unexpected = parse_ss_output(output, allowed_ports=set())
    assert (53, '127.0.0.53%lo:53') in unexpected
    assert (45020, '[::]:45020') in unexpected


def test_parse_ss_output_tolerates_extra_trailing_column():
    # some ss builds append a Process column; the local-address column should
    # still be found by pattern rather than a fixed index.
    output = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process\n"
        "tcp   LISTEN 0      128    0.0.0.0:31337         0.0.0.0:*           users:((\"nginx\",pid=1,fd=6))\n"
    )
    unexpected = parse_ss_output(output, allowed_ports=set())
    assert unexpected == [(31337, '0.0.0.0:31337')]


def test_check_listening_ports_treats_nonzero_returncode_as_unavailable(monkeypatch):
    def fake_run(*a, **kw):
        return subprocess.CompletedProcess(a, returncode=1, stdout='', stderr='permission denied')

    monkeypatch.setattr(subprocess, 'run', fake_run)
    ports, available = check_listening_ports({22})
    assert available is False
    assert ports == []


def test_main_rejects_nonexistent_root(capsys):
    # main() reads sys.argv directly via argparse; exercise via monkeypatched argv
    import sys as _sys
    old_argv = _sys.argv
    _sys.argv = ['harden_check.py', '--root', '/this/path/does/not/exist']
    try:
        exit_code = main()
    finally:
        _sys.argv = old_argv
    assert exit_code == 2
    assert 'not a directory' in capsys.readouterr().err


def test_main_rejects_malformed_allow_ports(tmp_path, capsys):
    import sys as _sys
    old_argv = _sys.argv
    _sys.argv = ['harden_check.py', '--root', str(tmp_path), '--allow-ports', '22,abc']
    try:
        exit_code = main()
    finally:
        _sys.argv = old_argv
    assert exit_code == 2
    assert 'must be a comma-separated list of integers' in capsys.readouterr().err
