import shutil
from pathlib import Path
from common import command, atomic, require
import account_policy

CONFIG = Path('/etc/ssh/sshd_config.d/60-panasms-users.conf')


def apply():
    binary = shutil.which('sshd')
    if not binary: return
    policy = account_policy.read()
    denied = sorted(name for name, p in policy.items() if p.get('disabled') or p.get('ssh') is False)
    previous = CONFIG.read_text() if CONFIG.exists() else None
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    try:
        atomic(CONFIG, '# Managed by PaNasMs user access policy.\n' + ('DenyUsers ' + ' '.join(denied) + '\n' if denied else ''), 0o644)
        command([binary, '-t'])
        for name in denied:
            effective = command([binary, '-T', '-C', 'user='+name+',host=localhost,addr=127.0.0.1'])
            values = [line.split()[1:] for line in effective.splitlines() if line.startswith('denyusers ')]
            require(any(name in value for value in values), 'OpenSSH does not include the managed user policy; check sshd_config Include')
        command(['systemctl', 'reload', 'ssh.service'], accepted=(0, 5), timeout=15)
    except Exception:
        if previous is None: CONFIG.unlink(missing_ok=True)
        else: atomic(CONFIG, previous, 0o644)
        raise
