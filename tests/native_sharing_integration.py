#!/usr/bin/env python3
"""VM-only sharing acceptance, inside a fresh PID/mount/network namespace.

PANASMS_TEST_VM_UUID must name the operator-verified disposable QEMU/KVM guest.
PANASMS_NATIVE_TEST_BIN supplies the candidate panasms-system-helper.
PANASMS_TEST_PREPARATION_PACKAGE and PANASMS_TEST_PREPARATION_SHA256 bind
the real compatibility metadata CLI. The private root has a synthetic dpkg
inventory; this is protocol acceptance, separate from actual package lifecycle.
Real owned loop storage, Linux credentials, Samba/NFS daemons and loopback
clients run in a private root. The systemctl fixture manages only owned daemons;
no guest system bus, APT or service manager is exposed.
"""
import ast
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


def command(*args, **kwargs):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kwargs).strip()
    except subprocess.CalledProcessError as error:
        print('Fixture command failed:', args, error.output, file=sys.stderr)
        raise


def prove_guest():
    expected = os.environ.get('PANASMS_TEST_VM_UUID', '')
    actual = Path('/sys/class/dmi/id/product_uuid').read_text().strip()
    if not expected or actual.lower() != expected.lower():
        raise SystemExit('Select the verified disposable VM UUID explicitly')
    if os.geteuid() != 0 or command('systemd-detect-virt', '--vm') not in ('kvm', 'qemu'):
        raise SystemExit('A root shell in a disposable QEMU/KVM VM is required')
    links = json.loads(command('ip', '-j', 'link'))
    if any(row['ifname'] != 'lo' and 'LOWER_UP' in row['flags'] for row in links):
        raise SystemExit('Disconnect every guest NIC before running this harness')
    if json.loads(command('ip', '-j', 'route')) or json.loads(command('ip', '-j', '-6', 'route')):
        raise SystemExit('The guest must have no external IPv4 route')
    mounts = subprocess.run(['findmnt', '-J', '-t', 'virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs'], capture_output=True, text=True)
    assert mounts.returncode in (0, 1)
    if json.loads(mounts.stdout or '{}').get('filesystems'):
        raise SystemExit('Shared host or network filesystems must not be mounted')


def outer():
    prove_guest()
    binary = Path(os.environ.get('PANASMS_NATIVE_TEST_BIN', '/tmp/panasms-native-test-bin')) / 'panasms-system-helper'
    if not binary.is_file():
        raise SystemExit('Build the candidate panasms-system-helper first')
    preparation = Path(os.environ.get('PANASMS_TEST_PREPARATION_PACKAGE', ''))
    expected = os.environ.get('PANASMS_TEST_PREPARATION_SHA256', '')
    if not preparation.is_file() or preparation.is_symlink() or hashlib.sha256(preparation.read_bytes()).hexdigest() != expected:
        raise SystemExit('Supply the hash-verified preparation package explicitly')
    if command('dpkg-deb', '-f', str(preparation), 'Package') != 'panasms-prototype':
        raise SystemExit('The preparation fixture must be the core package')
    version = command('dpkg-deb', '-f', str(preparation), 'Version')
    trace_runtime = binary.parent / 'strace-runtime'
    if not (trace_runtime / 'strace').is_file() and not shutil.which('strace'):
        raise SystemExit('Supply strace in the guest or as the owned strace-runtime fixture')
    with tempfile.TemporaryDirectory(prefix='panasms-sharing-', dir='/var/tmp') as temporary:
        scratch = Path(temporary)
        root = scratch / 'root'
        root.mkdir()
        prepared = scratch / 'preparation'
        command('dpkg-deb', '--raw-extract', str(preparation), str(prepared))
        image = scratch / 'owned.img'
        with image.open('wb') as stream:
            stream.truncate(160 * 1024 * 1024)
        loop = command('losetup', '--find', '--show', str(image))
        try:
            owned = json.loads(command('losetup', '--json', '--output', 'NAME,BACK-FILE', loop))['loopdevices']
            assert len(owned) == 1 and Path(owned[0]['back-file']).resolve() == image.resolve()
            command('mkfs.ext4', '-q', '-F', loop)
            nonce = secrets.token_hex(16)
            result = subprocess.run(['unshare', '--mount', '--pid', '--fork', '--net', '--', sys.executable,
                                     __file__, '--namespace', str(root), loop, str(binary.resolve()), str(prepared), version, nonce])
            if result.returncode:
                journal = root / 'var/lib/panasms-agent/sharing-transaction.json'
                if journal.exists():
                    print('Preserved fixture journal:', journal.read_text(), file=sys.stderr)
                for path in ('fixture/smbd.log', 'var/log/samba/log.smbd', 'fixture/rpcbind.log', 'fixture/rpc.mountd.log'):
                    log = root / path
                    if log.is_file():
                        print(path + ':\n' + log.read_text(errors='replace')[-4000:], file=sys.stderr)
                errors = root / 'fixture/tool-errors.jsonl'
                if errors.exists():
                    print('Fixture command failures:', errors.read_text(), file=sys.stderr)
                raise SystemExit(result.returncode)
            print(json.dumps({'helper_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'preparation_sha256': expected, 'private_dpkg_inventory': version, 'result': 'PASS'}))
        finally:
            owned = json.loads(command('losetup', '--json', '--output', 'NAME,BACK-FILE', loop))['loopdevices']
            assert len(owned) == 1 and Path(owned[0]['back-file']).resolve() == image.resolve()
            command('losetup', '--detach', loop)


TOOL = r'''#!/usr/bin/python3
import json,os,signal,subprocess,sys
from pathlib import Path
args=sys.argv[1:]
name=Path(sys.argv[0]).name
if name=='systemctl' and args[:2]==['enable','--now'] and Path('/fixture/fail-reload').exists():
 Path('/fixture/fail-reload').unlink();sys.exit(7)
if name=='smbpasswd' and '-d' in args and Path('/fixture/fail-disable').exists():sys.exit(7)
if name=='smbpasswd' and '-a' in args and Path('/fixture/fail-sync').exists():sys.exit(7)
if name=='exportfs' and args==['-ra'] and Path('/fixture/pause').exists() and Path('/var/lib/panasms-agent/sharing-transaction.json').exists():
 Path('/fixture/event').write_text(json.dumps({'pid':os.getpid(),'helper':os.getppid()}));os.kill(os.getpid(),signal.SIGSTOP)
if name!='systemctl':
 real='/usr/sbin/'+name if name=='exportfs' else '/usr/bin/'+name
 r=subprocess.run([real,*args],capture_output=True,text=True)
 if r.returncode:
  with Path('/fixture/tool-errors.jsonl').open('a') as f:f.write(json.dumps({'tool':name,'args':args,'code':r.returncode,'stderr':r.stderr})+'\n')
 print(r.stdout,end='');print(r.stderr,end='',file=sys.stderr);sys.exit(r.returncode)
if args==['is-active','smbd']:
 if Path('/run/smbd.pid').exists():print('active');sys.exit(0)
 print('inactive');sys.exit(3)
if args==['show','--property=MainPID','--value','smbd']:
 print(Path('/run/smbd.pid').read_text().strip());sys.exit(0)
if args[:2]==['enable','--now'] and args[-1] in ('smbd','nfs-kernel-server'):sys.exit(0)
raise SystemExit('Unexpected fixture service operation: '+repr(args))
'''


def namespace(root, loop, binary, prepared, version, nonce):
    if os.getpid() != 1:
        raise SystemExit('Namespace setup requires a fresh PID namespace')
    prove_guest()
    command('mount', '--make-rprivate', '/')
    root = Path(root)
    for name in ('usr/bin', 'usr/sbin', 'usr/lib/panasms', 'etc/default', 'etc/panasms', 'etc/pam.d',
                 'etc/security', 'etc/skel', 'etc/ssh/sshd_config.d', 'home', 'root/admin', 'proc', 'dev',
                 'tmp', 'run', 'fixture/bin', 'srv/data', 'var/log', 'var/mail', 'var/lib/panasms-agent',
                 'var/lib/panasms-updates', 'etc/samba', 'etc/exports.d', 'var/lib/samba/private',
                 'var/cache/samba', 'var/log/samba', 'var/lib/nfs/rpc_pipefs', 'mnt/client',
                 'var/lib/panasms-installer', 'var/lock', 'run/rpcbind'):
        (root / name).mkdir(parents=True, exist_ok=True)
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        (root / name).symlink_to('usr/' + name)
    for name in ('bin', 'sbin', 'lib64', 'lib/x86_64-linux-gnu'):
        (root / 'usr' / name).mkdir(parents=True, exist_ok=True)
        command('mount', '--bind', '/usr/' + name, str(root / 'usr' / name))
        command('mount', '-o', 'remount,bind,ro', str(root / 'usr' / name))
    for library in list(Path('/usr/lib').glob('python3*')) + [Path('/usr/share/samba')]:
        if library.is_dir():
            target = root / str(library).lstrip('/')
            target.mkdir(parents=True, exist_ok=True)
            command('mount', '--bind', str(library), str(target))
            command('mount', '-o', 'remount,bind,ro', str(target))
    command('mount', '-t', 'proc', 'proc', str(root / 'proc'))
    for name in ('null', 'urandom', 'random', 'zero'):
        (root / 'dev' / name).touch()
        command('mount', '--bind', '/dev/' + name, str(root / 'dev' / name))
    os.mknod(root / 'dev/owned-volume', 0o600 | 0o60000, os.stat(loop).st_rdev)
    command('mount', loop, str(root / 'srv/data'))
    (root / 'etc/fstab').write_text('/dev/owned-volume /srv/data ext4 defaults 0 2\n')
    (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nshadow: files\n')
    (root / 'etc/login.defs').write_text('UID_MIN 15000\nUID_MAX 15999\nGID_MIN 15000\nGID_MAX 15999\n')
    (root / 'etc/shells').write_text('/bin/bash\n/usr/sbin/nologin\n')
    (root / 'tmp').chmod(0o1777)
    (root / 'fixture/nonce').write_text(nonce)
    for tool in ('systemctl', 'exportfs', 'smbcontrol', 'testparm', 'smbpasswd'):
        path = root / 'fixture/bin' / tool
        path.write_text(TOOL)
        path.chmod(0o755)
    for name in ('netconfig', 'services', 'protocols', 'rpc'):
        if Path('/etc', name).is_file():
            shutil.copy(Path('/etc', name), root / 'etc' / name)
    (root / 'etc/hosts').write_text('127.0.0.1 localhost\n')
    (root / 'etc/pam.d/panasms').write_text('auth required pam_unix.so\naccount required pam_unix.so\npassword required pam_unix.so\n')
    (root / 'etc/pam.d/passwd').write_text('password required pam_unix.so\n')
    (root / 'etc/pam.d/samba').write_text('account required pam_unix.so\nsession required pam_permit.so\n')
    (root / 'etc/pam.d/other').write_text('auth required pam_unix.so\naccount required pam_unix.so\npassword required pam_unix.so\nsession required pam_permit.so\n')
    for name in ('panasms-system-helper', 'panasms-agent', 'panasms-password'):
        source = Path(binary).parent / name
        if source.is_file():
            shutil.copy(source, root / 'usr/lib/panasms' / name)
    prepared = Path(prepared)
    source = prepared / 'usr/lib/panasms/management/sharing_compat.py'
    tree = ast.parse(source.read_text())
    attested = next(node.value.args[0].generators[0].iter for node in tree.body
                    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'ATTESTED' for target in node.targets))
    files = ast.literal_eval(attested)
    assert isinstance(files, tuple) and all(isinstance(name, str) and name.startswith('/') for name in files)
    for name in (*files, '/usr/lib/panasms/management/common.py'):
        if name.startswith('/var/lib/dpkg/info/panasms-prototype.'):
            source = prepared / 'DEBIAN' / name.rsplit('.', 1)[1]
        else:
            source = prepared / name.lstrip('/')
        assert source.is_file() and not source.is_symlink()
        target = root / name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, target)
    database = root / 'var/lib/dpkg/status'
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_text('Package: panasms-prototype\nStatus: install ok installed\nPriority: optional\nSection: admin\nArchitecture: amd64\nVersion: ' + version + '\nMaintainer: Fixture\nDescription: Private sharing protocol fixture\n\n')
    trace_runtime = Path(binary).parent / 'strace-runtime'
    if (trace_runtime / 'strace').is_file():
        shutil.copytree(trace_runtime, root / 'fixture/strace-runtime')
    shutil.copy(__file__, root / 'fixture/harness.py')
    os.chroot(root)
    os.chdir('/fixture')
    os.environ['PATH'] = '/fixture/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['PANASMS_SHARING_NONCE'] = nonce
    os.execv('/usr/bin/python3', ['/usr/bin/python3', '/fixture/harness.py', '--scenarios'])


HELPER = '/usr/lib/panasms/panasms-system-helper'


def invoke(mode, body, user='admin'):
    r = subprocess.run([HELPER, mode, user], input=json.dumps(body), text=True, capture_output=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def operation(action, params):
    body = {'action': action, 'params': params}
    p = invoke('plan', body)
    assert not p.get('error'), p
    body.update(fingerprint=p['fingerprint'], confirmation=p['confirmation'])
    r = invoke('execute', body)
    assert not r.get('error'), r
    return r


def cli(action, body=None):
    r = subprocess.run([HELPER, 'sharing', action], input=json.dumps(body) if body is not None else None, text=True, capture_output=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def smb(user, password, cmd, success=True):
    rd, wr = os.pipe()
    try:
        os.write(wr, (password + '\n').encode())
        os.close(wr)
        wr = -1
        r = subprocess.run(['smbclient', '//127.0.0.1/Fixture', '-I', '127.0.0.1', '-U', user,
                            '--use-kerberos=off', '-c', cmd], env={**os.environ, 'PASSWD_FD': str(rd)},
                           pass_fds=(rd,), capture_output=True, text=True, timeout=15)
        assert (r.returncode == 0) == success, (user, cmd, r.returncode, r.stdout, r.stderr)
        return r
    finally:
        os.close(rd)
        if wr >= 0:
            os.close(wr)


def scenarios():
    nonce = os.environ.get('PANASMS_SHARING_NONCE', '')
    if os.getpid() != 1 or len(nonce) != 32 or not Path('/fixture/nonce').is_file() or Path('/fixture/nonce').read_text() != nonce:
        raise SystemExit('Scenarios require the verified private namespace root')
    command('ip', 'link', 'set', 'lo', 'up')
    Path('/etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nadmin:x:15000:15000:Admin:/root/admin:/bin/bash\nalice:x:15001:15001:Alice:/home/alice:/bin/bash\nbob:x:15002:15002:Bob:/home/bob:/bin/bash\neve:x:15003:15003:Eve:/home/eve:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_rpc:x:15004:15004:rpcbind:/run/rpcbind:/usr/sbin/nologin\n')
    Path('/etc/group').write_text('root:x:0:\nsudo:x:27:admin\nadmin:x:15000:\nalice:x:15001:\nbob:x:15002:\neve:x:15003:\nnogroup:x:65534:\n_rpc:x:15004:\n')
    day = int(time.time() // 86400)
    Path('/etc/shadow').write_text(''.join(f'{u}:!:{day}:0:99999:7:::\n' for u in ('root', 'admin', 'alice', 'bob', 'eve')))
    Path('/etc/shadow').chmod(0o600)
    Path('/etc/panasms/accounts.json').write_text(json.dumps({'bob': {'uid': 15002, 'panel': True}}))
    passwords = {u: secrets.token_urlsafe(24) for u in ('alice', 'bob', 'eve')}
    subprocess.run(['chpasswd'], input=''.join(u + ':' + p + '\n' for u, p in passwords.items()), text=True, check=True, capture_output=True)
    Path('/etc/exports').write_text('')
    version = command('dpkg-query', '-W', '-f=${Version}', 'panasms-prototype')
    denied = subprocess.run([HELPER, 'sharing', 'install'], capture_output=True, text=True)
    assert denied.returncode != 0 and not Path('/etc/panasms/sharing.json').exists()
    compatibility = '/usr/lib/panasms/management/sharing_compat.py'
    command('/usr/bin/python3', compatibility, 'configure')
    command('/usr/bin/python3', compatibility, 'prepare-activation', version,
            env={**os.environ, 'PANASMS_MAINTENANCE': '1'})
    ticket = json.loads(Path('/var/lib/panasms-installer/sharing-activation-v1.json').read_text())
    assert ticket['source'] == {'schema': 1, 'packageVersion': version, 'pairedRestore': 1, 'native': False}
    tracer = ['/usr/bin/strace']
    if Path('/fixture/strace-runtime/strace').exists():
        tracer = ['/fixture/strace-runtime/ld-linux-x86-64.so.2', '--library-path', '/fixture/strace-runtime/lib', '/fixture/strace-runtime/strace']
    for boundary, syscalls, path in (
            ('receipt', 'rename,renameat,renameat2', '/var/lib/panasms-installer/sharing-native-v1.json'),
            ('ticket', 'unlink,unlinkat', '/var/lib/panasms-installer/sharing-activation-v1.json')):
        trace = '/fixture/activation-' + boundary + '-kill.trace'
        result = subprocess.run([*tracer, '-f', '-e', 'trace=' + syscalls, '-P', path,
                                 '--inject=' + syscalls + ':signal=SIGKILL', '-o', trace,
                                 HELPER, 'sharing', 'activate'], capture_output=True, text=True)
        assert result.returncode == -signal.SIGKILL, (boundary, result.returncode, result.stderr)
        assert path in Path(trace).read_text()
        assert json.loads(Path('/etc/panasms/sharing.json').read_text())['legacyExportRevision']
        assert json.loads(Path('/var/lib/panasms-installer/sharing-activation-v1.json').read_text()) == ticket
        if boundary == 'receipt':
            assert not Path('/var/lib/panasms-installer/sharing-native-v1.json').exists()
            refused = subprocess.run([HELPER, 'sharing', 'reconcile'], capture_output=True, text=True)
            assert refused.returncode != 0
            rollback = subprocess.run([HELPER, 'sharing', 'rollback-check', '--source'],
                                      input=json.dumps({'schema': 1, 'source': ticket['files']}), capture_output=True, text=True)
            assert rollback.returncode == 0, rollback.stderr
        else:
            receipt = json.loads(Path('/var/lib/panasms-installer/sharing-native-v1.json').read_text())
            assert receipt['nonce'] == ticket['nonce'] and receipt['packageVersion'] == version
            cli('install')
            operation('share.account', {'target': 'alice', 'enabled': True})
    committed_state = Path('/etc/panasms/sharing.json').read_bytes()
    cli('activate')
    assert Path('/etc/panasms/sharing.json').read_bytes() == committed_state
    assert not Path('/var/lib/panasms-installer/sharing-activation-v1.json').exists()
    cli('install')
    print('PASS real helper SIGKILL at seed-to-receipt and receipt-to-ticket-unlink boundaries; nonce commit retry preserves later state', flush=True)
    print('PASS private fixture activation uses actual configured preparation CLI and ticket; no runtime authorization bypass', flush=True)
    main = Path('/etc/samba/smb.conf')
    main.write_text(main.read_text().replace('include = ', 'pid directory = /run\ninterfaces = lo\nbind interfaces only = yes\ninclude = '))
    processes = []
    try:
        log = open('/fixture/smbd.log', 'w')
        processes.append(subprocess.Popen(['smbd', '-F', '--no-process-group', '-d', '2'], stdout=log, stderr=log, start_new_session=True))
        for _ in range(100):
            if Path('/run/smbd.pid').exists():
                break
            time.sleep(.05)
        assert Path('/run/smbd.pid').exists(), Path('/fixture/smbd.log').read_text()
        share = Path('/srv/data/share')
        share.mkdir(mode=0o770)
        os.chown(share, 15001, 15001)
        command('setfacl', '-m', 'u:bob:r-x,u:eve:rwx', str(share))
        payload = share / 'payload'
        payload.write_text('native sharing fixture\n')
        payload.chmod(0o644)
        Path('/fixture/upload').write_text('upload fixture\n')
        params = dict(name='Fixture', path=str(share), smb=True, nfs=False, readOnly=False, clients='', readers=['bob'], writers=['alice'])
        operation('share.save', params)
        for user, password in passwords.items():
            operation('share.account', {'target': user, 'enabled': True})
            cli('sync', {'user': user, 'password': password})
        smb('alice', passwords['alice'], 'get payload /fixture/download; put /fixture/upload alice-file')
        assert Path('/fixture/download').read_text() == payload.read_text()
        assert (share / 'alice-file').read_text() == 'upload fixture\n'
        smb('bob', passwords['bob'], 'get payload /fixture/read-only')
        smb('bob', passwords['bob'], 'put /fixture/upload bob-file', success=False)
        smb('eve', passwords['eve'], 'ls', success=False)
        operation('share.save', dict(params, target='Fixture', readers=[], writers=['alice', 'bob']))
        smb('bob', passwords['bob'], 'put /fixture/upload forbidden-by-unix', success=False)
        assert not (share / 'forbidden-by-unix').exists()
        operation('share.save', dict(params, target='Fixture'))
        print('PASS real SMB writer/read-only/deny and Unix ACL upper bound', flush=True)
        sys.path.insert(0, '/usr/lib/panasms/management')
        import sharing_compat
        operation('share.account', {'target': 'alice', 'enabled': False})
        folder = Path('/var/lib/panasms-updates/backups/account-rollback-fixture')
        folder.mkdir(parents=True)
        with sharing_compat.locked():
            before_accounts = sharing_compat.capture()
            before_activation = sharing_compat.capture_activation()
            command('tar', '-cpf', str(folder / 'data.tar'), '-C', '/', 'etc/panasms/sharing.json')
            (folder / 'data.tar').chmod(0o600)
            pair_hash = sharing_compat.save_pair(folder, before_accounts, before_activation)
        operation('share.account', {'target': 'alice', 'enabled': True})
        cli('sync', {'user': 'alice', 'password': passwords['alice']})
        smb('alice', passwords['alice'], 'ls')
        current_accounts = sharing_compat.capture()
        snapshot = sharing_compat.load_snapshot(folder, pair_hash)
        try:
            sharing_compat.prepare_restore(snapshot['files'], pair_hash, 'account-rollback-fixture', (), snapshot['activation'])
        except sharing_compat.Rejected as error:
            assert str(error) == 'Sharing changed after the backup; verified native rollback is required'
        else:
            raise AssertionError('Rollback restored disabled policy over an enabled Samba passdb record')
        assert sharing_compat.capture() == current_accounts
        assert sharing_compat.capture_activation() == before_activation
        assert not sharing_compat.GUARD.exists() and not Path('/var/lib/panasms-agent/sharing-transaction.json').exists()
        unchanged = subprocess.run([HELPER, 'sharing', 'rollback-check', '--source'],
                                  input=json.dumps({'schema': 1, 'source': current_accounts}), capture_output=True, text=True)
        assert unchanged.returncode == 0, unchanged.stderr
        assert json.loads(unchanged.stdout)['files'] == current_accounts
        smb('alice', passwords['alice'], 'ls')
        print('PASS real SMB disabled-A/enabled-B rollback refuses before mutation; unchanged accounts witness succeeds', flush=True)
        denied = invoke('query', {'view': 'sharing'}, user='bob')
        assert denied.get('error') == 'Administrator permissions required', denied
        before = Path('/etc/panasms/sharing.json').read_text()
        bad = dict(params, target='Fixture', path='/srv/data/share;injection')
        assert invoke('plan', {'action': 'share.save', 'params': bad}).get('error')
        assert Path('/etc/panasms/sharing.json').read_text() == before
        print('PASS native route member denial and invalid config preserves state', flush=True)
        operation('share.account', {'target': 'alice', 'enabled': False})
        smb('alice', passwords['alice'], 'ls', success=False)
        operation('share.account', {'target': 'alice', 'enabled': True})
        cli('sync', {'user': 'alice', 'password': passwords['alice']})
        command('usermod', '--lock', 'alice')
        cli('reconcile')
        smb('alice', passwords['alice'], 'ls', success=False)
        print('PASS real SMB disable and Linux lock reconciliation', flush=True)
        assert all(p not in Path('/etc/panasms/sharing.json').read_text() for p in passwords.values())
        assert 'passwordRevision' not in json.dumps(invoke('query', {'view': 'sharing'}))
        print('PASS no plaintext or password revision returned', flush=True)
        command('usermod', '--unlock', 'alice')
        cli('sync', {'user': 'alice', 'password': passwords['alice']})
        Path('/fixture/fail-sync').touch()
        failed = subprocess.run([HELPER, 'sharing', 'sync'], input=json.dumps({'user': 'alice', 'password': passwords['alice']}), text=True, capture_output=True)
        Path('/fixture/fail-sync').unlink()
        assert failed.returncode != 0 and passwords['alice'] not in failed.stderr
        smb('alice', passwords['alice'], 'ls', success=False)
        assert json.loads(Path('/etc/panasms/sharing.json').read_text())['accounts']['alice']['status'] == 'error'
        print('PASS real failed SMB sync revokes stale credentials', flush=True)
        cli('sync', {'user': 'alice', 'password': passwords['alice']})
        if Path('/usr/lib/panasms/panasms-agent').is_file() and Path('/usr/lib/panasms/panasms-password').is_file():
            pam_scenarios(passwords, processes)
        else:
            print('SKIP real PAM endpoint: supply PAM-enabled agent and password binaries', flush=True)
        account_scenarios(passwords)
        failure_scenarios(params, share, passwords['alice'])
        nfs_scenarios(params, share, processes)
    finally:
        for p in processes:
            p.terminate()
        for p in processes:
            p.wait(timeout=10)


def pam_scenarios(passwords, processes):
    policy = Path('/etc/panasms/accounts.json')
    previous = policy.read_text()
    policy.write_text(json.dumps({'bob': {'uid': 15002, 'panel': True}, 'alice': {'uid': 15001, 'panel': True}}))
    log = open('/fixture/agent.log', 'w')
    agent = subprocess.Popen(['/usr/lib/panasms/panasms-agent', '-socket', '/run/fixture-agent.sock', '-peer-uid', '0', '-peer-gid', '0'], env={**os.environ, 'PANASMS_AUTH_MODE': 'sudo'}, stdout=log, stderr=log, start_new_session=True)
    processes.append(agent)
    class Connection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(25)
            self.sock.connect('/run/fixture-agent.sock')
    def authenticate(**extra):
        client = Connection('localhost')
        try:
            client.request('POST', '/authenticate', body=json.dumps({'username': 'alice', 'password': passwords['alice'], **extra}), headers={'Content-Type': 'application/json'})
            response = client.getresponse()
            body = response.read()
            assert response.status == 200, (response.status, body.decode())
            return json.loads(body)
        finally:
            client.close()
    try:
        for _ in range(100):
            if Path('/run/fixture-agent.sock').exists():
                break
            assert agent.poll() is None, Path('/fixture/agent.log').read_text()
            time.sleep(.05)
        operation('share.account', {'target': 'alice', 'enabled': True})
        authenticate(proofOnly=True)
        assert json.loads(Path('/etc/panasms/sharing.json').read_text())['accounts']['alice']['status'] == 'pending'
        assert not authenticate().get('smbSyncWarning')
        assert json.loads(Path('/etc/panasms/sharing.json').read_text())['accounts']['alice']['status'] == 'ready'
        smb('alice', passwords['alice'], 'ls')
        next_password = secrets.token_urlsafe(24)
        assert not authenticate(proofOnly=True, newPassword=next_password).get('smbSyncWarning')
        passwords['alice'] = next_password
        smb('alice', next_password, 'ls')
        Path('/fixture/fail-sync').touch()
        assert authenticate().get('smbSyncWarning') is True
        smb('alice', next_password, 'ls', success=False)
        Path('/fixture/fail-sync').unlink()
        assert not authenticate().get('smbSyncWarning')
        smb('alice', next_password, 'ls')
        assert all(p not in Path('/fixture/agent.log').read_text() for p in passwords.values())
        print('PASS actual PAM login/proof-only/password-renewal and nonblocking SMB warning/retry', flush=True)
    finally:
        policy.write_text(previous)
        Path('/fixture/fail-sync').unlink(missing_ok=True)


def account_scenarios(passwords):
    main = Path('/run/smbd.pid').read_text()
    clients = []
    try:
        for user in ('alice', 'bob'):
            rd, wr = os.pipe()
            os.write(wr, (passwords[user] + '\n').encode())
            os.close(wr)
            log = open('/fixture/client-' + user + '.log', 'w')
            try:
                child = subprocess.Popen(['smbclient', '//127.0.0.1/Fixture', '-I', '127.0.0.1', '-U', user, '--use-kerberos=off'], stdin=subprocess.PIPE, stdout=log, stderr=log, text=True, pass_fds=(rd,), env={**os.environ, 'PASSWD_FD': str(rd)}, start_new_session=True)
            finally:
                os.close(rd)
            clients.append(child)
            child.stdin.write('ls\n')
            child.stdin.flush()
        def sessions():
            return {r['username'] for r in json.loads(command('smbstatus', '--json'))['sessions'].values()}
        for _ in range(100):
            if {'alice', 'bob'}.issubset(sessions()):
                break
            time.sleep(.025)
        assert {'alice', 'bob'}.issubset(sessions())
        operation('share.disconnect', {'target': 'alice'})
        for _ in range(100):
            if 'alice' not in sessions():
                break
            time.sleep(.025)
        assert 'alice' not in sessions() and 'bob' in sessions()
        assert Path('/run/smbd.pid').read_text() == main
        print('PASS real selected-user disconnect preserves other session and server', flush=True)
    finally:
        for child in clients:
            child.terminate()
            child.wait(timeout=10)
    Path('/fixture/fail-sync').touch()
    Path('/fixture/fail-disable').touch()
    failed = subprocess.run([HELPER, 'sharing', 'sync'], input=json.dumps({'user': 'alice', 'password': passwords['alice']}), text=True, capture_output=True)
    assert failed.returncode != 0
    smb('alice', passwords['alice'], 'ls')
    Path('/fixture/fail-sync').unlink()
    Path('/fixture/fail-disable').unlink()
    cli('reconcile')
    smb('alice', passwords['alice'], 'ls', success=False)
    assert json.loads(Path('/etc/panasms/sharing.json').read_text())['accounts']['alice']['status'] == 'error'
    cli('sync', {'user': 'alice', 'password': passwords['alice']})
    print('PASS real periodic retry revokes stale SMB after failed immediate cleanup', flush=True)
    subprocess.run(['chpasswd'], input='alice:' + secrets.token_urlsafe(24) + '\n', text=True, check=True, capture_output=True)
    cli('reconcile')
    smb('alice', passwords['alice'], 'ls', success=False)
    print('PASS actual external Linux password change revokes SMB revision', flush=True)
    subprocess.run(['chpasswd'], input='alice:' + passwords['alice'] + '\n', text=True, check=True, capture_output=True)
    cli('sync', {'user': 'alice', 'password': passwords['alice']})
    for cause in ('expired', 'inactive', 'uid', 'policy'):
        if cause == 'expired':
            command('chage', '-E', '1', 'alice')
        elif cause == 'inactive':
            command('chage', '-d', '1', '-M', '1', '-I', '1', 'alice')
        elif cause == 'uid':
            command('usermod', '-u', '15011', 'alice')
        else:
            Path('/etc/panasms/accounts.json').write_text(json.dumps({'bob': {'uid': 15002, 'panel': True}, 'alice': {'uid': 15001, 'disabled': True}}))
        cli('reconcile')
        smb('alice', passwords['alice'], 'ls', success=False)
        if cause == 'expired':
            command('chage', '-E', '-1', 'alice')
        elif cause == 'inactive':
            command('chage', '-d', str(int(time.time() // 86400)), '-M', '99999', '-I', '-1', 'alice')
        elif cause == 'uid':
            command('usermod', '-u', '15001', 'alice')
        else:
            Path('/etc/panasms/accounts.json').write_text(json.dumps({'bob': {'uid': 15002, 'panel': True}}))
        cli('sync', {'user': 'alice', 'password': passwords['alice']})
        smb('alice', passwords['alice'], 'ls')
    print('PASS actual expiry/inactivity/UID-change/policy revoke and explicit password resync', flush=True)


def failure_scenarios(params, share, password):
    paths = ['/etc/panasms/sharing.json', '/etc/samba/panasms-shares.conf', '/etc/exports.d/panasms-shares.exports']
    journal = Path('/var/lib/panasms-agent/sharing-transaction.json')
    before = {name: Path(name).read_text() for name in paths}
    changed = dict(params, target='Fixture', name='ChangedFixture')
    plan = invoke('plan', {'action': 'share.save', 'params': changed})
    body = dict(action='share.save', params=changed, fingerprint=plan['fingerprint'], confirmation=plan['confirmation'])
    Path('/fixture/fail-reload').touch()
    result = invoke('execute', body)
    assert result.get('error') == 'Sharing update failed; previous configuration restored. Check service logs.', result
    assert before == {name: Path(name).read_text() for name in paths} and not journal.exists()
    print('PASS real service-manager failure rolls back generated files/state', flush=True)
    Path('/fixture/pause').touch()
    process = subprocess.Popen([HELPER, 'execute', 'admin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    process.stdin.write(json.dumps(body))
    process.stdin.close()
    event = Path('/fixture/event')
    for _ in range(200):
        if event.exists():
            break
        assert process.poll() is None
        time.sleep(.025)
    assert event.exists() and journal.exists()
    stopped = json.loads(event.read_text())
    assert stopped['helper'] == process.pid
    os.kill(process.pid, signal.SIGKILL)
    os.kill(stopped['pid'], signal.SIGKILL)
    process.wait(timeout=10)
    Path('/fixture/pause').unlink()
    event.unlink()
    assert before != {name: Path(name).read_text() for name in paths} and journal.exists()
    for _ in range(2):
        cli('recover')
        assert before == {name: Path(name).read_text() for name in paths} and not journal.exists()
    print('PASS actual SIGKILL after durable journal/config reload boundary; recovery twice', flush=True)
    journal.write_text(json.dumps(before))
    Path(paths[1]).write_text(before[paths[1]] + '# interrupted fixture\n')
    cli('recover')
    assert before == {name: Path(name).read_text() for name in paths} and not journal.exists()
    print('PASS released Python three-path journal recovers natively', flush=True)
    command('umount', '/srv/data')
    try:
        underlying = Path('/srv/data/share')
        underlying.mkdir()
        underlying.chmod(0o777)
        (underlying / 'empty-mount-sentinel').write_text('must never publish')
        smb('alice', password, 'ls', success=False)
    finally:
        command('mount', '/dev/owned-volume', '/srv/data')
    print('PASS missing backing mount cannot publish underlying empty directory', flush=True)


def nfs_scenarios(params, share, processes):
    command('mount', '-t', 'nfsd', 'nfsd', '/proc/fs/nfsd')
    Path('/var/lib/nfs/v4recovery').mkdir()
    for tool, args in [('rpcbind', ['-f', '-w', '-d']), ('rpc.mountd', ['-F', '-N', '2', '-N', '4'])]:
        log = open('/fixture/' + tool + '.log', 'w')
        processes.append(subprocess.Popen([tool, *args], stdout=log, stderr=log, start_new_session=True))
        time.sleep(.2)
        assert processes[-1].poll() is None, Path('/fixture/' + tool + '.log').read_text()
    command('rpc.nfsd', '-d', '-N', '4', '4')
    mounted = False
    try:
        operation('share.save', dict(params, target='Fixture', nfs=True, clients='127.0.0.1/32'))
        effective = command('exportfs', '-v')
        assert 'root_squash' in effective and 'mountpoint=/srv/data' in Path('/etc/exports.d/panasms-shares.exports').read_text()
        command('mount', '-t', 'nfs', '-o', 'vers=3,nolock,soft,sec=sys,proto=tcp,timeo=10,retrans=1,retry=0', '127.0.0.1:' + str(share), '/mnt/client')
        mounted = True
        code = "from pathlib import Path;p=Path('/mnt/client/nfs-alice');p.write_text('NFS fixture');assert p.read_text()=='NFS fixture'"
        command('runuser', '-u', 'alice', '--', 'python3', '-c', code)
        assert (share / 'nfs-alice').read_text() == 'NFS fixture'
        root = subprocess.run(['python3', '-c', "from pathlib import Path;Path('/mnt/client/root-denied').write_text('must fail')"], capture_output=True)
        assert root.returncode != 0 and not (share / 'root-denied').exists()
        bob = subprocess.run(['runuser', '-u', 'bob', '--', 'python3', '-c', "from pathlib import Path;Path('/mnt/client/bob-denied').write_text('must fail')"], capture_output=True)
        assert bob.returncode != 0 and not (share / 'bob-denied').exists()
        print('PASS real NFS user read/write, Unix deny and root_squash', flush=True)
        command('umount', '/mnt/client')
        mounted = False
        operation('share.save', dict(params, target='Fixture', nfs=True, readOnly=True, clients='127.0.0.1/32'))
        command('mount', '-t', 'nfs', '-o', 'vers=3,nolock,soft,sec=sys,proto=tcp,timeo=10,retrans=1,retry=0', '127.0.0.1:' + str(share), '/mnt/client')
        mounted = True
        alice = subprocess.run(['runuser', '-u', 'alice', '--', 'python3', '-c', "from pathlib import Path;Path('/mnt/client/readonly-denied').write_text('must fail')"], capture_output=True)
        assert alice.returncode != 0 and not (share / 'readonly-denied').exists()
        print('PASS real NFS read-only export', flush=True)
        command('umount', '/mnt/client')
        mounted = False
        legacy_nfs_scenarios()
    finally:
        if mounted:
            command('umount', '-fl', '/mnt/client')
        command('exportfs', '-ua')
        command('rpc.nfsd', '0')
        command('umount', '/proc/fs/nfsd')


def legacy_nfs_scenarios():
    legacy = Path('/srv/data/legacy')
    legacy.mkdir(mode=0o770)
    os.chown(legacy, 15001, 15001)
    params = {'target': str(legacy), 'clients': '127.0.0.1/32', 'readOnly': False}
    operation('nfs.export', params)
    Path('/mnt/legacy').mkdir()
    command('mount', '-t', 'nfs', '-o', 'vers=3,nolock,soft,proto=tcp,timeo=10,retrans=1,retry=0', '127.0.0.1:' + str(legacy), '/mnt/legacy')
    try:
        command('runuser', '-u', 'alice', '--', 'python3', '-c', "from pathlib import Path;p=Path('/mnt/legacy/proof');p.write_text('legacy NFS fixture');assert p.read_text()=='legacy NFS fixture'")
    finally:
        command('umount', '/mnt/legacy')
    paths = ['/etc/panasms/sharing.json', '/etc/samba/panasms-shares.conf', '/etc/exports.d/panasms-shares.exports', '/etc/exports.d/panasms.exports']
    before = {path: Path(path).read_text() for path in paths}
    changed = dict(params, readOnly=True)
    plan = invoke('plan', {'action': 'nfs.export', 'params': changed})
    assert not plan.get('error'), plan
    body = dict(action='nfs.export', params=changed, fingerprint=plan['fingerprint'], confirmation=plan['confirmation'])
    Path('/fixture/pause').touch()
    process = subprocess.Popen([HELPER, 'execute', 'admin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    process.stdin.write(json.dumps(body))
    process.stdin.close()
    event = Path('/fixture/event')
    for _ in range(200):
        if event.exists():
            break
        assert process.poll() is None
        time.sleep(.025)
    assert event.exists()
    stopped = json.loads(event.read_text())
    assert stopped['helper'] == process.pid
    os.kill(process.pid, signal.SIGKILL)
    os.kill(stopped['pid'], signal.SIGKILL)
    process.wait(timeout=10)
    Path('/fixture/pause').unlink()
    event.unlink()
    for _ in range(2):
        cli('recover')
        assert before == {path: Path(path).read_text() for path in paths}
    assert (legacy / 'proof').read_text() == 'legacy NFS fixture'
    print('PASS real legacy NFS export and interrupted legacy export recovery twice', flush=True)
    def refuse_republication():
        for action, params in [('share.recover', {}), ('nfs.export-remove', {'target': str(legacy)})]:
            plan = invoke('plan', {'action': action, 'params': params})
            assert not plan.get('error'), plan
            result = invoke('execute', dict(action=action, params=params, fingerprint=plan['fingerprint'], confirmation=plan['confirmation']))
            assert result.get('error') == 'Shared volume unavailable', result
            assert Path('/etc/exports.d/panasms.exports').read_text() == before['/etc/exports.d/panasms.exports']
            assert not Path('/var/lib/panasms-agent/sharing-transaction.json').exists()
    kept = Path('/srv/data/share')
    kept.rename('/srv/data/share-kept')
    kept.symlink_to(legacy)
    try:
        refuse_republication()
    finally:
        kept.unlink()
        Path('/srv/data/share-kept').rename(kept)
    print('PASS retained mounted share symlink refuses unrelated NFS reload', flush=True)
    command('mount', '-t', 'tmpfs', 'go06-replacement', '/srv/data')
    try:
        Path('/srv/data/share').mkdir()
        Path('/srv/data/legacy').mkdir()
        refuse_republication()
    finally:
        command('umount', '/srv/data')
    print('PASS foreign volume at retained mountpoint refuses unrelated NFS reload', flush=True)
    command('umount', '-l', '/srv/data')
    try:
        operation('nfs.export-remove', {'target': str(legacy)})
        assert str(legacy) not in Path('/etc/exports.d/panasms.exports').read_text()
        assert str(legacy) not in command('exportfs', '-v')
    finally:
        command('mount', '/dev/owned-volume', '/srv/data')
    assert (legacy / 'proof').read_text() == 'legacy NFS fixture'
    print('PASS real offline legacy NFS removal with retained offline managed share; data preserved', flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--namespace']:
        namespace(*sys.argv[2:])
    elif sys.argv[1:] == ['--scenarios']:
        scenarios()
    elif not sys.argv[1:]:
        outer()
    else:
        raise SystemExit('Run without arguments in an explicitly selected disposable VM')
