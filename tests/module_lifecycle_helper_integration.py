import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
import zipfile


ROOT = Path('/var/lib/panasms-go14-helper-acceptance')
MODULES = Path('/var/lib/panasms-modules')
UPLOADS = Path('/var/lib/panasms-agent/module-uploads')
KEYS = Path('/etc/panasms/module-keys')
HELPER = Path('/usr/lib/panasms/panasms-system-helper')
ID = 'go14-check'
KEY = KEYS / 'go14fixture.pem'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def owned(path, directory=False):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unsafe fixture parent')
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == 0 and not info.st_mode & 0o022
            and (directory or info.st_nlink == 1), 'Unsafe fixture ownership')
    return info


def read(path, limit):
    previous = owned(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        require((opened.st_dev, opened.st_ino) == (previous.st_dev, previous.st_ino)
                and stat.S_ISREG(opened.st_mode) and opened.st_uid == 0 and opened.st_nlink == 1
                and not opened.st_mode & 0o022 and opened.st_size <= limit, 'Fixture input changed or is too large')
        value = source.read(limit + 1)
        require(len(value) <= limit, 'Fixture input too large')
        return value


def no_mounts(path):
    for row in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = row.split()
        require(len(fields) >= 6, 'Invalid mount inventory')
        target = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
        require(target != str(path) and not target.startswith(str(path) + '/'), 'Fixture contains mounted data')


def write_new(path, data, mode):
    owned(path.parent, True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    owned(path)


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=30).strip()


def prove_guest(args):
    require(args.allow_disposable_vm and os.geteuid() == 0, 'Explicit isolated guest root opt-in required')
    require('PANASMS_CONTROL_FD' not in os.environ, 'Borrowed cancellation control refused')
    require(re.fullmatch('[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', args.vm_uuid)
            and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == args.vm_uuid.lower(),
            'VM identity refused')
    require(command('systemd-detect-virt', '--vm') in ('kvm', 'qemu'), 'Hypervisor refused')
    links = json.loads(command('ip', '-j', 'link'))
    require(not any(row['ifname'] != 'lo' and 'LOWER_UP' in row['flags'] for row in links),
            'Connected guest refused')
    require(not json.loads(command('ip', '-4', '-j', 'route')) and not json.loads(command('ip', '-6', '-j', 'route')),
            'Guest routes refused')
    mounts = subprocess.run(['findmnt', '-J', '-t', 'virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs'],
                            capture_output=True, text=True, timeout=20)
    require(mounts.returncode in (0, 1) and not json.loads(mounts.stdout or '{}').get('filesystems'),
            'External mounts refused')
    require(command('dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', 'panasms-prototype') == 'installed ' + args.version,
            'Installed package version refused')
    require(re.fullmatch('[0-9a-f]{64}', args.helper_sha256), 'Missing helper provenance')
    require(hashlib.sha256(read(HELPER, 128 << 20)).hexdigest() == args.helper_sha256, 'Installed helper hash refused')
    require(not ROOT.exists() and not ROOT.is_symlink(), 'Existing fixture refused')
    require(not KEY.exists() and not KEY.is_symlink(), 'Existing fixture signing key refused')
    require(not (MODULES / ID).exists() and not (MODULES / ID).is_symlink(), 'Existing fixture module refused')
    require(not (MODULES / '.transaction').exists() and not (MODULES / '.transaction').is_symlink(),
            'Existing module transaction refused')
    state = Path('/var/lib/panasms-updates/state.json')
    if state.exists() or state.is_symlink():
        phase = json.loads(read(state, 1 << 20)).get('phase', '')
        require(phase in ('', 'idle', 'complete', 'failed', 'checked', 'downloaded', 'rolled-back'),
                'Pending core update refused')


def registry():
    path = MODULES / 'registry.json'
    return json.loads(read(path, 8 << 20)) if path.exists() else {}


def helper(args, mode, body):
    result = subprocess.run([str(HELPER), mode, args.actor], input=json.dumps(body),
                            text=True, capture_output=True)
    require(result.returncode == 0 and len(result.stdout) <= 4 << 20, 'Helper process failed')
    value = json.loads(result.stdout)
    require(isinstance(value, dict), 'Invalid helper result')
    return value


def execute(args, action, params):
    plan = helper(args, 'plan', {'action': action, 'params': params})
    require(not plan.get('error'), 'Native lifecycle plan rejected')
    request = {'action': action, 'params': params,
               'fingerprint': plan['fingerprint'], 'confirmation': plan['confirmation']}
    value = helper(args, 'execute', request)
    require(not value.get('error') and not value.get('cancelled'), 'Native lifecycle execution rejected')
    return plan


def bundle(args, large=False, corrupt=False):
    index = ROOT / ('index-' + uuid.uuid4().hex)
    index.write_bytes(b'export default "isolated fixture";')
    payloads = {'ui/index.js': index}
    if large:
        blob = ROOT / 'blob'
        require(min(shutil.disk_usage(UPLOADS).free, shutil.disk_usage(ROOT).free) >= 512 << 20,
                'Insufficient disposable fixture space')
        with blob.open('xb') as output:
            for _ in range(16):
                output.write(os.urandom(4 << 20))
        payloads['ui/blob'] = blob
    files = {name: hashlib.sha256(read(path, 64 << 20)).hexdigest() for name, path in payloads.items()}
    manifest = {'id': ID, 'version': '1.0.0', 'api': 1, 'core': '>=0.2.0,<1.0.0',
                'architecture': 'all', 'title': 'Helper lifecycle fixture', 'memberAccess': True,
                'signer': 'go14fixture', 'files': files}
    raw = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    source, signature = ROOT / 'manifest.json', ROOT / 'signature'
    source.write_bytes(raw)
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(ROOT / 'private.pem'),
                    '-in', str(source), '-out', str(signature)], check=True, capture_output=True)
    token = uuid.uuid4().hex
    path = UPLOADS / (args.actor + '-' + token + '.zip')
    with path.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_STORED) as archive:
            archive.writestr('bundle.json', json.dumps({'root': ID}))
            archive.writestr('modules/' + ID + '/manifest.json', raw)
            archive.writestr('modules/' + ID + '/signature', read(signature, 128))
            for name, source in payloads.items():
                if corrupt and name == 'ui/index.js':
                    archive.writestr('modules/' + ID + '/' + name, b'unsigned modified content')
                else:
                    archive.write(source, 'modules/' + ID + '/' + name)
    return token, path


def interrupted_copy(args, before, token):
    params = {'upload': token}
    plan = helper(args, 'plan', {'action': 'module.install', 'params': params})
    require(not plan.get('error'), 'Interrupted install plan rejected')
    body = {'action': 'module.install', 'params': params,
            'fingerprint': plan['fingerprint'], 'confirmation': plan['confirmation']}
    process = subprocess.Popen([str(HELPER), 'execute', args.actor], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        pidfd = os.pidfd_open(process.pid)
    except OSError:
        process.kill()
        process.wait(timeout=15)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def cancelled_copy(args, before, token):
    params = {'upload': token}
    plan = helper(args, 'plan', {'action': 'module.install', 'params': params})
    require(not plan.get('error'), 'Cancellable install plan rejected')
    body = {'action': 'module.install', 'params': params,
            'fingerprint': plan['fingerprint'], 'confirmation': plan['confirmation']}
    control, request = os.pipe()
    os.set_blocking(control, False)
    process = subprocess.Popen([str(HELPER), 'execute', args.actor], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env={**os.environ, 'PANASMS_CONTROL_FD': str(control)}, pass_fds=(control,))
    try:
        process.stdin.write(json.dumps(body))
        process.stdin.close()
        process.stdin = None
        path = MODULES / '.transaction/.new' / ID / 'ui/blob'
        deadline = time.monotonic() + 45
        while True:
            require(process.poll() is None, 'Helper finished before the cancellation boundary')
            require(time.monotonic() < deadline, 'Cancellation boundary timed out')
            if path.exists() and 0 < owned(path).st_size < 64 << 20:
                break
            time.sleep(.001)
        os.write(request, b'cancel')
        stdout, _ = process.communicate()
        require(process.returncode == 0 and json.loads(stdout).get('cancelled'), 'Native helper did not cancel at staging')
        require(registry() == before and not (MODULES / '.transaction').exists() and not (MODULES / ID).exists(),
                'Cancelled staging changed installed modules')
    finally:
        os.close(control)
        os.close(request)
        if process.poll() is None:
            # Cancellation may have missed the critical boundary; let mutations finish.
            process.communicate()
        raise
    waited = False
    try:
        process.stdin.write(json.dumps(body))
        process.stdin.close()
        path = MODULES / '.transaction/.new' / ID / 'ui/blob'
        deadline = time.monotonic() + 45
        while True:
            require(process.poll() is None, 'Helper finished before copying boundary')
            require(time.monotonic() < deadline, 'Copy boundary timed out')
            if path.exists():
                info = owned(path)
                require(info.st_size < 64 << 20, 'Helper completed copy before the partial-copy boundary')
                if info.st_size > 0:
                    break
            time.sleep(.001)
        require(hashlib.sha256(Path('/proc', str(process.pid), 'exe').read_bytes()).hexdigest() == args.helper_sha256,
                'Unexpected child executable')
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        require(process.wait(timeout=15) == -signal.SIGKILL, 'Actual helper SIGKILL not observed')
        waited = True
        state = json.loads(read(MODULES / '.transaction/journal.json', 16 << 20))
        require(state['before'] == before and state['affected'] == [ID] and state.get('phase') == 'staging'
                and not state['committed'], 'Helper missed the required staging death boundary')
        require(registry() == before and not (MODULES / ID).exists(), 'Interrupted staging published code')
        execute(args, 'module.recover', {})
        require(registry() == before and not (MODULES / '.transaction').exists(), 'Actual helper recovery changed baseline')
    finally:
        if not waited:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=15)
        os.close(pidfd)
        process.stdout.close()
        process.stderr.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--allow-disposable-vm', action='store_true')
    parser.add_argument('--vm-uuid', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--helper-sha256', required=True)
    parser.add_argument('--actor', required=True)
    args = parser.parse_args()
    require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}', args.actor), 'Invalid fixture actor')
    prove_guest(args)
    for directory in (MODULES, UPLOADS, KEYS):
        if not directory.exists():
            owned(directory.parent, True)
            directory.mkdir(mode=0o700 if directory == UPLOADS else 0o755)
        owned(directory, True)
    ROOT.mkdir(mode=0o700)
    root_identity = owned(ROOT, True)
    uploads = []
    public = None
    before = registry()
    require(ID not in before, 'Existing module receipt refused')
    try:
        query = helper(args, 'query', {'view': 'modules', 'target': ''})
        require(not query.get('error') and len(query['installed']) == len(before), 'Native administrator module query rejected')
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(ROOT / 'private.pem')],
                       check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(ROOT / 'private.pem'), '-pubout', '-out', str(ROOT / 'public.pem')],
                       check=True, capture_output=True)
        public = read(ROOT / 'public.pem', 4096)
        write_new(KEY, public, 0o644)
        data = ROOT / 'retained-data'
        data.write_bytes(b'fixture user data')
        token, path = bundle(args, corrupt=True)
        uploads.append((path, owned(path)))
        rejected = helper(args, 'plan', {'action': 'module.install', 'params': {'upload': token}})
        require(rejected.get('error') == 'Corrupted file: ui/index.js' and registry() == before
                and not (MODULES / '.transaction').exists(),
                'Corrupt signed payload was not rejected before mutation')
        token, path = bundle(args)
        uploads.append((path, owned(path)))
        plan = helper(args, 'plan', {'action': 'module.install', 'params': {'upload': token}})
        require(not plan.get('error'), 'Valid signed install plan rejected')
        stale = helper(args, 'execute', {'action': 'module.install', 'params': {'upload': token},
                                        'fingerprint': '0' * 64, 'confirmation': ID})
        require(stale.get('error') == 'State has changed. Review a new operation plan.' and stale.get('noChanges')
                and registry() == before, 'Stale native plan was not rejected')
        execute(args, 'module.install', {'upload': token})
        installation = registry()[ID]['installation']
        require(re.fullmatch('[0-9a-f]{32}', installation) and registry()[ID]['enabled'], 'Fresh helper install identity missing')
        execute(args, 'module.disable', {'target': ID})
        token, path = bundle(args)
        uploads.append((path, owned(path)))
        execute(args, 'module.install', {'upload': token})
        require(not registry()[ID]['enabled'] and registry()[ID]['installation'] == installation,
                'Helper update changed disabled state or installation identity')
        execute(args, 'module.enable', {'target': ID})
        execute(args, 'module.remove', {'target': ID})
        require(registry() == before and not (MODULES / ID).exists(), 'Helper removal changed unrelated registry entries')
        token, path = bundle(args)
        uploads.append((path, owned(path)))
        sys.path.insert(0, '/usr/lib/panasms/management')
        import module_catalog
        require(hasattr(module_catalog, 'native_install'), 'Installed catalog lacks the native mutation bridge')
        plan = module_catalog.native_install('plan', {'upload': token}, args.actor)
        result = module_catalog.native_install('execute', {'upload': token}, args.actor, plan=plan)
        require(not result.get('error') and registry()[ID]['installation'] != installation,
                'Native catalog bridge or fresh reinstall identity failed')
        execute(args, 'module.remove', {'target': ID})
        token, path = bundle(args, large=True)
        uploads.append((path, owned(path)))
        interrupted_copy(args, before, token)
        cancelled_copy(args, before, token)
        require(read(data, 1024) == b'fixture user data', 'Helper changed retained module data')
        print(json.dumps({'result': 'PASS', 'version': args.version, 'helperSHA256': args.helper_sha256,
                          'administratorModuleQuery': True, 'corruptPayloadRejected': True, 'stalePlanRejected': True,
                          'signedInstallDisableUpdateEnableRemove': True, 'installationIdentityPreserved': True,
                          'catalogNativeMutationBridge': True, 'freshReinstallIdentity': True,
                          'actualCopySIGKILLAndNativeRecovery': True, 'unrelatedRegistryPreserved': True,
                          'actualControlPipeCancellation': True,
                          'moduleDataPreserved': True, 'snapshotRestoreRequired': True}, sort_keys=True))
    finally:
        if (MODULES / '.transaction').exists() or (MODULES / '.transaction').is_symlink():
            state = json.loads(read(MODULES / '.transaction/journal.json', 16 << 20))
            require(state.get('schema') == 1 and state['before'] == before and state['affected'] == [ID],
                    'Unowned transaction preserved; owner snapshot restore required')
            execute(args, 'module.recover', {})
        if ID in registry():
            manifest = registry()[ID]
            require(manifest.get('id') == ID and manifest.get('signer') == 'go14fixture'
                    and manifest.get('version') == '1.0.0' and manifest.get('service') is None,
                    'Unowned module receipt preserved; owner snapshot restore required')
            execute(args, 'module.remove', {'target': ID})
        require(registry() == before, 'Registry drift preserved; owner snapshot restore required')
        if public is not None and KEY.exists():
            require(read(KEY, 4096) == public, 'Changed signing key preserved')
            KEY.unlink()
        for path, previous in uploads:
            if path.exists() or path.is_symlink():
                current = owned(path)
                require((current.st_dev, current.st_ino) == (previous.st_dev, previous.st_ino)
                        and (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                        == (previous.st_size, previous.st_mtime_ns, previous.st_ctime_ns),
                        'Changed upload preserved')
                path.unlink()
        current = owned(ROOT, True)
        require((current.st_dev, current.st_ino) == (root_identity.st_dev, root_identity.st_ino),
                'Changed fixture root preserved')
        no_mounts(ROOT)
        shutil.rmtree(ROOT)


if __name__ == '__main__':
    main()
