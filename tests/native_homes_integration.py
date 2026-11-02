#!/usr/bin/env python3
"""VM-only home relocation acceptance, inside a fresh PID/mount/network namespace.

PANASMS_TEST_VM_UUID must name the operator-verified disposable QEMU/KVM guest.
PANASMS_NATIVE_TEST_BIN supplies the candidate panasms-system-helper. Real owned
loop storage, rsync, account tools, ACLs and xattrs are exercised; read-only block
inventory presents that loop as a permanent volume because home policy forbids
loop-backed destinations. No host system bus, APT or service manager is exposed.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kwargs).strip()


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
    if json.loads(command('ip', '-j', 'route')):
        raise SystemExit('The guest must have no external IPv4 route')
    mounts = json.loads(command('findmnt', '-J', '-t', 'virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs'))
    if mounts.get('filesystems'):
        raise SystemExit('Shared host or network filesystems must not be mounted')


def outer():
    prove_guest()
    binary = Path(os.environ.get('PANASMS_NATIVE_TEST_BIN', '/tmp/panasms-native-test-bin')) / 'panasms-system-helper'
    if not binary.is_file():
        raise SystemExit('Build the candidate panasms-system-helper first')
    with tempfile.TemporaryDirectory(prefix='panasms-homes-', dir='/var/tmp') as temporary:
        scratch = Path(temporary)
        root = scratch / 'root'
        root.mkdir()
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
                                     __file__, '--namespace', str(root), loop, str(binary.resolve()), nonce])
            if result.returncode:
                journal = root / 'var/lib/panasms-agent/home-move.json'
                if journal.exists():
                    print('Preserved fixture journal:', journal.read_text(), file=sys.stderr)
                errors = root / 'fixture/tool-errors.jsonl'
                if errors.exists():
                    print('Fixture command failures:', errors.read_text(), file=sys.stderr)
                raise SystemExit(result.returncode)
        finally:
            owned = json.loads(command('losetup', '--json', '--output', 'NAME,BACK-FILE', loop))['loopdevices']
            assert len(owned) == 1 and Path(owned[0]['back-file']).resolve() == image.resolve()
            command('losetup', '--detach', loop)


TOOL = r'''#!/usr/bin/python3
import errno,json,os,signal,subprocess,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
journal=Path('/var/lib/panasms-agent/home-move.json')
state=json.loads(journal.read_text()) if journal.exists() else {}
pause=Path('/fixture/pause').read_text() if Path('/fixture/pause').exists() else ''
stage=''
if name=='mount' and '--bind' in args:stage='journal-copying'
if name=='rsync':stage='copy-verified' if '--dry-run' in args else 'target-created'
if name=='usermod':
 stage='one-user-switched' if args[-1]=='bob' else 'journal-switching'
if name=='umount' and state.get('phase')=='committed':stage='journal-committed'
if name=='sync' and state.get('phase')=='copying':stage='copy-synced'
if name=='sync' and state.get('phase')=='committed' and not Path(state['source']).exists():stage='old-tree-renamed'
def barrier(label):
 if label and pause==label:
  Path('/fixture/event').write_text(json.dumps({'stage':label,'pid':os.getpid(),'state':state}))
  os.kill(os.getpid(),signal.SIGSTOP)
barrier(stage)
if name=='rsync':
 try:
  mounts=json.loads(subprocess.check_output(['/usr/bin/findmnt','--json','--list','--output','TARGET,OPTIONS'],text=True))['filesystems']
  assert any(r['target']==state['source'] and 'ro' in r['options'].split(',') for r in mounts),'Source bind is not read-only at the original path'
  parent=Path(state['source']).parent/'.panasms-parent-rw-probe';parent.write_text('parent remains writable');parent.unlink()
  try:(Path(state['source'])/'.panasms-source-ro-probe').write_text('must fail')
  except OSError as e:assert e.errno==errno.EROFS,e
  else:raise AssertionError('Source path remained writable')
 except Exception as e:
  with Path('/fixture/tool-errors.jsonl').open('a') as log:log.write(json.dumps({'command':[name,*args],'error':str(e)})+'\n')
  raise
if name=='getent' and args==['passwd'] and Path('/fixture/duplicate-user').exists():
 raw=subprocess.check_output(['/usr/bin/getent','passwd'],text=True)
 duplicate=next(row.split(':') for row in raw.splitlines() if row.startswith('alice:'))
 if Path('/fixture/duplicate-user').read_text()=='outside':duplicate[5]='/nonexistent'
 print(raw.rstrip()+'\n'+':'.join(duplicate));sys.exit(0)
if name=='systemctl':
 if '--property=Description' in args:print('Fixture background service')
 sys.exit(0)
if name=='lsblk':
 print(json.dumps({'blockdevices':[{'name':'fixture-root','maj:min':'8:1','type':'disk','rm':False,'tran':'sata'}, {'name':'fixture-data','maj:min':'8:2','type':'disk','rm':False,'tran':'sata'}]}))
 sys.exit(0)
if name=='findmnt':
 result=subprocess.run(['/usr/bin/findmnt',*args],capture_output=True,text=True)
 if result.returncode:print(result.stdout,end='');sys.exit(result.returncode)
 value=json.loads(result.stdout)
 for row in value.get('filesystems',[]):
  if row['target']=='/srv/data':row['maj:min']='8:2'
  if row['target']=='/':row['maj:min']='8:1'
 print(json.dumps(value));sys.exit(0)
if name=='du' and Path('/fixture/replace-parent').exists():
 parent=Path('/srv/data/pending');parent.rename('/srv/data/previous-parent');parent.mkdir();Path('/fixture/replace-parent').unlink()
if name=='du' and Path('/fixture/replace-source').exists():
 Path('/home').rename('/home-original');Path('/home').mkdir();Path('/home/alice').mkdir();Path('/home/bob').mkdir();Path('/fixture/replace-source').unlink()
real='/usr/sbin/'+name if name in ('usermod','useradd') else '/usr/bin/'+name
if name in ('mount','umount'):
 result=subprocess.run([real,*args],capture_output=True,text=True)
 if result.returncode:
  with Path('/fixture/tool-errors.jsonl').open('a') as log:log.write(json.dumps({'command':[real,*args],'exit_code':result.returncode,'stderr':result.stderr})+'\n')
 print(result.stdout,end='');print(result.stderr,end='',file=sys.stderr);sys.exit(result.returncode)
if name=='useradd' and pause=='defaults-switched':
 result=subprocess.run([real,*args]);barrier('defaults-switched');sys.exit(result.returncode)
os.execv(real,[real,*args])
'''


def namespace(root, loop, binary, nonce):
    if os.getpid() != 1:
        raise SystemExit('Namespace setup requires a fresh PID namespace')
    command('mount', '--make-rprivate', '/')
    root = Path(root)
    for name in ('usr/bin', 'usr/sbin', 'usr/lib/panasms', 'etc/default', 'etc/panasms', 'etc/pam.d',
                 'etc/security', 'etc/skel', 'etc/ssh/sshd_config.d', 'home', 'root/admin', 'proc', 'dev',
                 'tmp', 'run', 'fixture/bin', 'srv/data', 'var/log', 'var/mail', 'var/lib/panasms-agent',
                 'var/lib/panasms-updates'):
        (root / name).mkdir(parents=True, exist_ok=True)
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        (root / name).symlink_to('usr/' + name)
    for name in ('bin', 'sbin', 'lib64', 'lib/x86_64-linux-gnu'):
        (root / 'usr' / name).mkdir(parents=True, exist_ok=True)
        command('mount', '--bind', '/usr/' + name, str(root / 'usr' / name))
        command('mount', '-o', 'remount,bind,ro', str(root / 'usr' / name))
    for library in Path('/usr/lib').glob('python3*'):
        if library.is_dir():
            target = root / 'usr/lib' / library.name
            target.mkdir()
            command('mount', '--bind', str(library), str(target))
            command('mount', '-o', 'remount,bind,ro', str(target))
    command('mount', '-t', 'proc', 'proc', str(root / 'proc'))
    for name in ('null', 'urandom'):
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
    for tool in ('getent', 'du', 'mount', 'umount', 'rsync', 'usermod', 'useradd', 'sync', 'systemctl', 'findmnt', 'lsblk'):
        path = root / 'fixture/bin' / tool
        path.write_text(TOOL)
        path.chmod(0o755)
    shutil.copy(binary, root / 'usr/lib/panasms/panasms-system-helper')
    shutil.copy(__file__, root / 'fixture/harness.py')
    os.chroot(root)
    os.chdir('/fixture')
    os.environ['PATH'] = '/fixture/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['PANASMS_HOMES_NONCE'] = nonce
    os.execv('/usr/bin/python3', ['/usr/bin/python3', '/fixture/harness.py', '--scenarios'])


HELPER = '/usr/lib/panasms/panasms-system-helper'
JOURNAL = Path('/var/lib/panasms-agent/home-move.json')
TARGET = '/srv/data/homes'


def invoke(mode, body):
    result = subprocess.run([HELPER, mode, 'admin'], input=json.dumps(body), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def reset():
    assert not JOURNAL.exists(), JOURNAL.read_text() if JOURNAL.exists() else ''
    for path in ('/home', '/home-original', TARGET, '/srv/data/pending', '/srv/data/previous-parent', '/srv/data/preserved-alice'):
        if Path(path).exists():
            shutil.rmtree(path)
    Path('/home').mkdir(mode=0o755)
    Path('/etc/default/useradd').write_text('HOME=/home\n')
    Path('/etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nadmin:x:15000:15000:Admin:/root/admin:/bin/bash\nalice:x:15001:15001:Alice:/home/alice:/bin/bash\nbob:x:15002:15002:Bob:/home/bob:/bin/bash\n')
    Path('/etc/group').write_text('root:x:0:\nsudo:x:27:admin\nadmin:x:15000:\nalice:x:15001:\nbob:x:15002:\nusers:x:100:alice,bob\n')
    Path('/etc/shadow').write_text('root:*:20000:0:99999:7:::\nadmin:!:20000:0:99999:7:::\nalice:!:20000:0:99999:7:::\nbob:!:20000:0:99999:7:::\n')
    Path('/etc/gshadow').write_text('root:*::\nsudo:*::admin\nadmin:*::\nalice:*::\nbob:*::\nusers:*::alice,bob\n')
    for path in ('/etc/shadow', '/etc/gshadow'):
        Path(path).chmod(0o600)
    for name, uid in (('alice', 15001), ('bob', 15002)):
        home = Path('/home') / name
        home.mkdir(mode=0o700)
        os.chown(home, uid, uid)
        payload = home / 'payload'
        payload.write_bytes((name.encode() + b'\x00') * 65536)
        os.chown(payload, uid, uid)
        payload.chmod(0o640)
        os.setxattr(payload, 'user.panasms-test', b'home-copy')
        command('/usr/bin/setfacl', '-m', 'u:15002:r--', str(payload))
        os.link(payload, home / 'hardlink')
        sparse = home / 'sparse'
        with sparse.open('wb') as stream:
            stream.seek(5 * 1024 * 1024)
            stream.write(b'end')
        os.chown(sparse, uid, uid)
    for path in ('/fixture/pause', '/fixture/event', '/fixture/replace-parent', '/fixture/replace-source', '/fixture/duplicate-user', '/run/nologin'):
        Path(path).unlink(missing_ok=True)


def snapshot(base):
    root_stat = Path(base).stat()
    result = {'root': {'uid': root_stat.st_uid, 'gid': root_stat.st_gid, 'mode': root_stat.st_mode & 0o7777}}
    for name in ('alice', 'bob'):
        home = Path(base) / name
        payload = home / 'payload'
        stat = payload.stat()
        result[name] = {'sha256': hashlib.sha256(payload.read_bytes()).hexdigest(), 'uid': stat.st_uid,
                        'gid': stat.st_gid, 'mode': stat.st_mode & 0o7777,
                        'mtime_ns': stat.st_mtime_ns,
                        'acl': command('/usr/bin/getfacl', '-cpn', str(payload)),
                        'xattr': base64.b64encode(os.getxattr(payload, 'user.panasms-test')).decode(),
                        'hardlink': stat.st_ino == (home / 'hardlink').stat().st_ino,
                        'sparse': (home / 'sparse').stat().st_blocks < 1024,
                        'home_mode': home.stat().st_mode & 0o7777,
                        'home_uid': home.stat().st_uid, 'home_gid': home.stat().st_gid}
    return result


def plan(destination=TARGET):
    result = invoke('plan', {'action': 'homes.move', 'params': {'destination': destination}})
    assert not result.get('error'), result
    return {'action': 'homes.move', 'params': {'destination': destination},
            'fingerprint': result['fingerprint'], 'confirmation': result['confirmation']}


def recover():
    for _ in range(2):
        result = subprocess.run([HELPER, 'homes', 'recover'], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert not JOURNAL.exists() and not Path('/run/nologin').exists()


def interrupted(stage, expected, legacy=False, missing_home=False, replaced_home=False):
    request = plan()
    Path('/fixture/pause').write_text(stage)
    process = subprocess.Popen([HELPER, 'execute', 'admin'], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    process.stdin.write(json.dumps(request))
    process.stdin.close()
    deadline = time.monotonic() + 30
    while not Path('/fixture/event').exists() and time.monotonic() < deadline and process.poll() is None:
        time.sleep(0.02)
    if not Path('/fixture/event').exists():
        process.kill()
        process.wait()
        raise AssertionError((stage, process.stdout.read(), process.stderr.read()))
    event = json.loads(Path('/fixture/event').read_text())
    process.kill()
    process.wait(timeout=10)
    os.kill(event['pid'], signal.SIGKILL)
    os.waitpid(event['pid'], 0)
    Path('/fixture/pause').unlink()
    if legacy:
        state = json.loads(JOURNAL.read_text())
        state.pop('backupIdentity', None)
        state.pop('nologinIdentity', None)
        state.pop('nologinTemp', None)
        for user in state['users']:
            user.pop('uid', None)
            user.pop('gid', None)
            user.pop('newIdentity', None)
        JOURNAL.write_text(json.dumps(state))
    if missing_home or replaced_home:
        preserved = Path('/srv/data/preserved-alice')
        (Path(TARGET) / 'alice').rename(preserved)
        if replaced_home:
            (Path(TARGET) / 'alice').mkdir()
            (Path(TARGET) / 'alice/unrelated').write_text('unrelated replacement')
        failed = subprocess.run([HELPER, 'homes', 'recover'], capture_output=True, text=True)
        assert failed.returncode != 0 and JOURNAL.exists(), failed.stdout
        state = json.loads(JOURNAL.read_text())
        original = str(Path(state['backup']) / 'previous') if (Path(state['backup']) / 'previous').exists() else '/home'
        assert snapshot(original) == expected
        if replaced_home:
            assert (Path(TARGET) / 'alice/unrelated').read_text() == 'unrelated replacement'
            (Path(TARGET) / 'alice/unrelated').unlink()
            (Path(TARGET) / 'alice').rmdir()
        preserved.rename(Path(TARGET) / 'alice')
    recover()
    committed = stage in ('journal-committed', 'old-tree-renamed')
    base = TARGET if committed else '/home'
    assert snapshot(base) == expected, (stage, snapshot(base), expected)
    defaults = command('/usr/sbin/useradd', '--defaults')
    assert 'HOME=' + base in defaults, (stage, defaults)
    for name in ('alice', 'bob'):
        assert command('/usr/bin/getent', 'passwd', name).split(':')[5] == base + '/' + name
    if committed:
        assert not Path('/home').exists()
    print('PASS interrupted', stage, 'legacy' if legacy else 'native', 'missing-home protected' if missing_home else ('replaced-home protected' if replaced_home else ''), flush=True)


def cancelled_copy(expected):
    request = plan()
    Path('/fixture/pause').write_text('target-created')
    read, write = os.pipe()
    process = subprocess.Popen([HELPER, 'execute', 'admin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, pass_fds=(read,),
                               env={**os.environ, 'PANASMS_CONTROL_FD': str(read)})
    os.close(read)
    try:
        process.stdin.write(json.dumps(request))
        process.stdin.close()
        deadline = time.monotonic() + 30
        while not Path('/fixture/event').exists() and time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.02)
        assert Path('/fixture/event').exists(), 'Copy never reached the cancellable boundary'
        event = json.loads(Path('/fixture/event').read_text())
        os.write(write, b'1')
        process.wait(timeout=15)
        result = json.loads(process.stdout.read())
        assert result.get('cancelled'), result
        try:
            os.kill(event['pid'], 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError('Cancelled copy worker survived')
        assert snapshot('/home') == expected and not JOURNAL.exists() and not Path('/run/nologin').exists()
    finally:
        os.close(write)
        if process.poll() is None:
            process.kill()
            process.wait()
        Path('/fixture/pause').unlink(missing_ok=True)
    print('PASS cancellation restores source and reaps copy worker', flush=True)


def replaced_after_verification(expected):
    request = plan()
    Path('/fixture/pause').write_text('copy-synced')
    process = subprocess.Popen([HELPER, 'execute', 'admin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    event = None
    try:
        process.stdin.write(json.dumps(request))
        process.stdin.close()
        deadline = time.monotonic() + 30
        while not Path('/fixture/event').exists() and time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.02)
        assert Path('/fixture/event').exists(), 'Copy never reached post-verification boundary'
        event = json.loads(Path('/fixture/event').read_text())
        (Path(TARGET) / 'alice').rename('/srv/data/preserved-alice')
        (Path(TARGET) / 'alice').mkdir()
        (Path(TARGET) / 'alice/unrelated').write_text('keep replacement')
        os.kill(event['pid'], signal.SIGCONT)
        process.wait(timeout=30)
        result = json.loads(process.stdout.read())
        assert result.get('error') and not JOURNAL.exists() and not Path('/run/nologin').exists(), result
        assert snapshot('/home') == expected and (Path(TARGET) / 'alice/unrelated').read_text() == 'keep replacement'
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if event:
            try:
                os.kill(event['pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
        Path('/fixture/pause').unlink(missing_ok=True)
    print('PASS user copy replacement after verification rejected before switching', flush=True)


def scenarios():
    assert os.getpid() == 1
    assert Path('/fixture/nonce').read_text() == os.environ.get('PANASMS_HOMES_NONCE')
    assert os.readlink('/proc/1/root') == '/'
    reset()
    expected = snapshot('/home')
    query = invoke('query', {'view': 'homes'})
    assert query['path'] == '/home' and len(query['users']) == 2 and not query['recovery']
    moved = invoke('execute', plan())
    assert not moved.get('error') and snapshot(TARGET) == expected, moved
    assert not Path('/home').exists() and not JOURNAL.exists() and not Path('/run/nologin').exists()
    print('PASS real move, ownership, ACL, xattr, hardlink, sparse data and cleanup', flush=True)
    reset()
    expected_nss = snapshot('/home')
    for path in ('/etc/passwd', '/etc/shadow'):
        value = Path(path).read_text().replace('\nalice:', '\nAlice.Example:')
        Path(path).write_text(value)
    moved_nss = invoke('execute', plan())
    assert not moved_nss.get('error') and not JOURNAL.exists() and not Path('/run/nologin').exists(), moved_nss
    assert snapshot(TARGET) == expected_nss
    assert command('/usr/bin/getent', 'passwd', 'Alice.Example').split(':')[5] == TARGET + '/alice'
    print('PASS existing NSS account name moves and committed cleanup completes', flush=True)
    reset()
    interrupted('journal-committed', snapshot('/home'), missing_home=True)
    reset()
    interrupted('journal-committed', snapshot('/home'), replaced_home=True)
    reset()
    replaced_after_verification(snapshot('/home'))
    reset()
    for duplicate in ('inside', 'outside'):
        original = snapshot('/home')
        Path('/fixture/duplicate-user').write_text(duplicate)
        rejected = invoke('plan', {'action': 'homes.move', 'params': {'destination': TARGET}})
        assert rejected.get('error') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
        assert not Path(TARGET).exists() and not Path('/run/nologin').exists() and snapshot('/home') == original
        Path('/fixture/duplicate-user').unlink()
        print('PASS duplicate NSS name ' + duplicate + ' source rejected before mutation', flush=True)
    reset()
    parent = Path('/home')
    for _ in range(4):
        parent = parent / ('d' * 250)
        parent.mkdir()
    Path('/home/alice').rename(parent / 'alice')
    Path('/etc/passwd').write_text(Path('/etc/passwd').read_text().replace('/home/alice:', str(parent / 'alice') + ':'))
    rejected = invoke('plan', {'action': 'homes.move', 'params': {'destination': TARGET}})
    assert rejected.get('error') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
    assert not Path(TARGET).exists() and not Path('/run/nologin').exists() and (parent / 'alice/payload').is_file()
    print('PASS oversized computed new home rejected before mutation', flush=True)
    reset()
    parent = Path('/home')
    for _ in range(4):
        parent = parent / ('d' * 250)
        parent.mkdir()
    source = parent / 's'
    source.mkdir()
    Path('/home/alice').rename(source / 'alice')
    Path('/etc/default/useradd').write_text('HOME=' + str(source) + '\n')
    Path('/etc/passwd').write_text(Path('/etc/passwd').read_text().replace('/home/alice:', str(source / 'alice') + ':'))
    rejected = invoke('execute', plan())
    assert rejected.get('error') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
    assert not Path(TARGET).exists() and not Path('/run/nologin').exists() and (source / 'alice/payload').is_file()
    assert not list(parent.glob('.panasms-home-*'))
    print('PASS generated backup path rejected by shared journal validation before publication', flush=True)


    for stage in ('journal-copying', 'target-created', 'copy-verified', 'journal-switching',
                  'one-user-switched', 'defaults-switched', 'journal-committed', 'old-tree-renamed'):
        reset()
        interrupted(stage, snapshot('/home'))
    reset()
    interrupted('one-user-switched', snapshot('/home'), legacy=True)
    reset()
    interrupted('journal-committed', snapshot('/home'), legacy=True)
    reset()
    cancelled_copy(snapshot('/home'))
    reset()
    parent = Path('/srv/data/pending')
    parent.mkdir()
    request = plan(str(parent / 'homes'))
    parent.rename('/srv/data/previous-parent')
    parent.mkdir()
    rejected = invoke('execute', request)
    assert rejected.get('error') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
    print('PASS replaced destination-parent stale plan rejected', flush=True)
    reset()
    parent = Path('/srv/data/pending')
    parent.mkdir()
    request = plan(str(parent / 'homes'))
    Path('/fixture/replace-parent').touch()
    rejected = invoke('execute', request)
    assert rejected.get('error') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
    assert not (parent / 'homes').exists() and not Path('/run/nologin').exists()
    print('PASS destination-parent replacement during du rejected before journal', flush=True)
    reset()
    original = snapshot('/home')
    request = plan()
    Path('/fixture/replace-source').touch()
    rejected = invoke('execute', request)
    assert rejected.get('error') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
    assert snapshot('/home-original') == original and not Path(TARGET).exists() and not Path('/run/nologin').exists()
    print('PASS source replacement during du rejected with original retained', flush=True)
    reset()
    request = plan()
    command('/usr/bin/fallocate', '-l', '110M', '/srv/data/full')
    rejected = invoke('execute', request)
    Path('/srv/data/full').unlink()
    assert 'Not enough free space' in rejected.get('error', '') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
    print('PASS full destination rejected before journal mutation', flush=True)
    reset()
    child = os.fork()
    if child == 0:
        os.setgid(15001)
        os.setuid(15001)
        os.chdir('/home/alice')
        time.sleep(60)
        os._exit(0)
    try:
        time.sleep(0.05)
        result = invoke('query', {'view': 'homes-check', 'target': TARGET})
        assert any(row['user'] == 'alice' for row in result.get('blockers', [])), result
        assert not JOURNAL.exists() and not Path(TARGET).exists()
    finally:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
    print('PASS active user blocks read-only preflight', flush=True)
    request = plan()
    command('/usr/bin/umount', '/srv/data')
    rejected = invoke('execute', request)
    assert rejected.get('error') and rejected.get('noChanges') and not JOURNAL.exists(), rejected
    command('/usr/bin/mount', '/dev/owned-volume', '/srv/data')
    print('PASS vanished destination rejected with original retained', flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--namespace']:
        namespace(*sys.argv[2:])
    elif sys.argv[1:] == ['--scenarios']:
        scenarios()
    elif not sys.argv[1:]:
        outer()
    else:
        raise SystemExit('Usage: PANASMS_TEST_VM_UUID=UUID PANASMS_NATIVE_TEST_BIN=DIR python3 native_homes_integration.py')
