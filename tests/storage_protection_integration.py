#!/usr/bin/python3
"""Root-only protection checks using exclusively disposable loop-backed images."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import storage
from common import Rejected


def run(*args, data=None):
    return subprocess.check_output(args, input=data, stderr=subprocess.PIPE).decode().strip()


def rejected(action, params):
    for fn in (storage.plan, storage.execute_unlocked):
        try:
            fn(action, params)
        except Rejected as error:
            assert 'used by' in str(error) or 'storage layer' in str(error), str(error)
        else:
            raise AssertionError(f'{fn.__name__} accepted {action}')


def baseline():
    return {p.name: (p.joinpath('md/uuid').read_text(), sorted(x.name for x in p.joinpath('slaves').iterdir()))
            for p in Path('/sys/class/block').glob('md*') if p.joinpath('md/uuid').exists()}


assert os.geteuid() == 0
before = baseline()
loops = []
array = '/dev/md/panasms_guard_' + str(os.getpid())
crypt = 'panasms_guard_' + str(os.getpid())
array_active = crypt_active = False
with tempfile.TemporaryDirectory(prefix='panasms-storage-guard-', dir='/var/tmp') as scratch:
    try:
        for i in range(2):
            image = Path(scratch) / f'disk{i}.img'
            with image.open('wb') as f:
                f.truncate(128 * 1024 * 1024)
            loop = run('losetup', '--find', '--show', '--partscan', str(image))
            assert loop.startswith('/dev/loop')
            loops.append(loop)
            params = {'target': loop, 'startMiB': 1, 'endMiB': 60}
            plan = storage.plan('partition.create', params)
            assert any('GPT' in item for item in plan['details'])
            storage.execute_unlocked('partition.create', params)
            run('udevadm', 'settle')
            assert Path(loop + 'p1').exists()
        print('PASS blank loop devices receive explicitly planned GPT', flush=True)
        loop = loops[0]
        original = storage.table(loop)
        params = {'target': loop, 'startMiB': 65, 'endMiB': 100}
        storage.plan('partition.create', params)
        storage.execute_unlocked('partition.create', params)
        assert storage.table(loop)['id'] == original['id']
        print('PASS adding a partition preserves existing GPT identity', flush=True)
        image = Path(scratch) / 'disk0.img'
        original_hash = hashlib.sha256(image.read_bytes()).digest()
        with patch.object(storage, 'table', side_effect=Rejected('Injected read error')):
            for fn in (storage.plan, storage.execute_unlocked):
                try:
                    fn('partition.create', {'target':loop, 'startMiB':102, 'endMiB':110})
                except Rejected:
                    pass
                else:
                    raise AssertionError('table read failure accepted')
        assert hashlib.sha256(image.read_bytes()).digest() == original_hash
        print('PASS injected table read failure leaves image unchanged', flush=True)
        parts = [loop + 'p1' for loop in loops]
        run('mdadm', '--create', array, '--run', '--metadata=1.2', '--level=1', '--raid-devices=2', *parts)
        array_active = True
        run('udevadm', 'settle')
        for loop in loops:
            rejected('disk.prepare', {'target': loop})
            storage.plan('partition.create', {'target':loop, 'startMiB':102, 'endMiB':110})
        print('PASS RAID members block disk wipes but allow independent free space', flush=True)
        run('mdadm', '--stop', array)
        array_active = False
        for part in parts:
            run('mdadm', '--zero-superblock', part)
        key = Path(scratch) / 'key'
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--pbkdf', 'pbkdf2', '--iter-time', '10', '--key-file', str(key), parts[0])
        run('cryptsetup', 'open', '--key-file', str(key), parts[0], crypt)
        crypt_active = True
        run('udevadm', 'settle')
        rejected('disk.prepare', {'target':loops[0]})
        storage.plan('partition.create', {'target':loops[0], 'startMiB':102, 'endMiB':110})
        print('PASS LUKS blocks disk wipes but allows independent free space', flush=True)
    finally:
        if crypt_active:
            run('cryptsetup', 'close', crypt)
        if array_active:
            run('mdadm', '--stop', array)
        for loop in reversed(loops):
            run('losetup', '--detach', loop)
        run('udevadm', 'settle')
        assert baseline() == before, 'Existing arrays changed'
        print('PASS temporary devices removed; original arrays unchanged', flush=True)
