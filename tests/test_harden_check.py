import os
import stat

from harden_check import (
    find_world_writable_files,
    find_suid_sgid_binaries,
    check_sshd_config,
    parse_ss_output,
)


def test_find_world_writable_files_flags_only_writable(tmp_path):
    writable = tmp_path / 'writable.txt'
    writable.write_text('x')
    os.chmod(writable, 0o666)

    safe = tmp_path / 'safe.txt'
    safe.write_text('x')
    os.chmod(safe, 0o644)

    findings = find_world_writable_files(str(tmp_path))
    assert findings == [str(writable)]


def test_find_world_writable_files_skips_symlinks(tmp_path):
    target = tmp_path / 'target.txt'
    target.write_text('x')
    os.chmod(target, 0o644)
    link = tmp_path / 'link.txt'
    os.symlink(target, link)

    assert find_world_writable_files(str(tmp_path)) == []


def test_find_suid_sgid_binaries_flags_unexpected_and_respects_allowlist(tmp_path):
    unexpected = tmp_path / 'suspicious'
    unexpected.write_text('x')
    os.chmod(unexpected, 0o755 | stat.S_ISUID)

    allowed = tmp_path / 'allowed'
    allowed.write_text('x')
    os.chmod(allowed, 0o755 | stat.S_ISUID)

    findings = find_suid_sgid_binaries(str(tmp_path), allowlist={str(allowed)})
    assert findings == [str(unexpected)]


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
