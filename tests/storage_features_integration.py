#!/usr/bin/python3
"""Disposable-image acceptance on a Linux host; never accepts physical device paths."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import storage
import storage_luks as luks
import storage_snapshots as snapshots
from common import Rejected


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE).decode().strip()


def operation(module, action, params):
    before = module.plan(action, params)
    assert before['fingerprint']
    return module.execute(action, params)


def rejects(fn):
    try:
        fn()
    except Rejected:
        return
    raise AssertionError('Unsafe operation accepted')


assert os.geteuid() == 0
loops = []
opened = False
mounted = False
mapping = 'panasms_features_' + str(os.getpid())
with tempfile.TemporaryDirectory(prefix='panasms-features-', dir='/var/tmp') as scratch:
    root = Path(scratch)
    point = Path('/mnt') / mapping
    point.mkdir()
    try:
        for i in range(2):
            image = root / f'disk{i}.img'
            with image.open('wb') as f:
                f.truncate(256 * 1024 * 1024)
            loop = run('losetup', '--find', '--show', str(image))
            assert loop.startswith('/dev/loop')
            loops.append(loop)
        key = root / 'initial-key'
        key.write_text('integration-initial-password')
        key.chmod(0o600)
        run('cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--pbkdf', 'pbkdf2', '--iter-time', '10', '--key-file', str(key), loops[0])
        run('udevadm', 'settle')
        with patch.object(luks, 'ROOT', root / 'keys'), patch.object(luks, 'CRYPTTAB', root / 'crypttab'):
            p = {'target': loops[0], 'passphrase': key.read_text(), 'password': 'integration-second-password'}
            operation(luks, 'luks.key-add', p)
            slots = luks.query(loops[0])['slots']
            assert len(slots) == 2
            rejects(lambda: operation(luks, 'luks.key-remove', {**p, 'slot': slots[0]}))
            operation(luks, 'luks.key-remove', {**p, 'slot': slots[1]})
            assert len(luks.query(loops[0])['slots']) == 1
            rejects(lambda: operation(luks, 'luks.key-remove', {**p, 'slot': slots[0]}))
            print('PASS LUKS password add/revoke, last-key and surviving-password protection', flush=True)
            operation(luks, 'luks.header-backup', {'target': loops[0], 'folder': str(root)})
            operation(luks, 'luks.key-add', p)
            operation(luks, 'luks.header-restore', {'target': loops[0], 'folder': str(root)})
            assert len(luks.query(loops[0])['slots']) == 1
            luks.verify(loops[0], key.read_text())
            print('PASS LUKS header backup/restore preserves original access', flush=True)
            operation(luks, 'luks.auto-enable', {**p, 'name': mapping})
            state = luks.query(loops[0])
            assert state['automatic']
            managed_key = root / 'keys' / (state['uuid'] + '.key')
            assert managed_key.stat().st_mode & 0o777 == 0o600
            run('cryptsetup', 'open', '--key-file', str(managed_key), loops[0], mapping)
            opened = True
            run('cryptsetup', 'close', mapping)
            opened = False
            operation(luks, 'luks.auto-disable', p)
            assert not managed_key.exists() and not luks.query(loops[0])['automatic']
            assert len(luks.query(loops[0])['slots']) == 1
            luks.verify(loops[0], key.read_text())
            print('PASS automatic-unlock key unlocks mapping and is revoked on disable', flush=True)
        run('mkfs.btrfs', '-f', loops[1])
        run('mount', loops[1], str(point))
        mounted = True
        (point / 'original.txt').write_text('before snapshot')
        operation(snapshots, 'filesystem.snapshot-create', {'target': loops[1], 'name': 'first'})
        (point / 'original.txt').write_text('after snapshot')
        assert snapshots.query(loops[1])['snapshots'] == [{'name': 'first'}]
        operation(snapshots, 'filesystem.snapshot-restore', {'target': loops[1], 'snapshot': 'first', 'name': 'restored'})
        assert (point / 'restored/original.txt').read_text() == 'before snapshot'
        assert (point / 'original.txt').read_text() == 'after snapshot'
        rejects(lambda: operation(snapshots, 'filesystem.snapshot-restore', {'target': loops[1], 'snapshot': 'first', 'name': 'restored'}))
        operation(snapshots, 'filesystem.snapshot-delete', {'target': loops[1], 'snapshot': 'first'})
        assert snapshots.query(loops[1])['snapshots'] == []
        print('PASS Btrfs create/list/restore/delete and no overwrite of current files', flush=True)
        run('umount', str(point))
        mounted = False
        run('mount', loops[1], str(point))
        mounted = True
        assert (point / 'restored/original.txt').read_text() == 'before snapshot'
        print('PASS restored data survives unmount/mount', flush=True)
    finally:
        if mounted:
            run('umount', str(point))
        if opened:
            run('cryptsetup', 'close', mapping)
        for loop in reversed(loops):
            run('losetup', '--detach', loop)
        point.rmdir()
        run('udevadm', 'settle')
