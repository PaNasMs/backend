#!/usr/bin/python3
"""Root-only checks on disposable images; never change a real disk's partition table."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import storage
from common import Rejected


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, text=True).strip()


def deny(action, target, **params):
    try:
        storage.plan(action, {'target':target, **params})
    except Rejected:
        return
    raise AssertionError(f'{action} accepted protected {target}')


def perform(action, target, **params):
    p = {'target':target, **params}
    storage.plan(action, p)
    storage.execute_unlocked(action, p)
    run('udevadm','settle')


def exercise(disk, root):
    before = storage.table(disk)
    first = before['partitions'][0]
    sentinel = root / 'sentinel'
    sentinel.write_bytes(os.urandom(32768))
    digest = hashlib.sha256(sentinel.read_bytes()).digest()
    inv = storage.inventory()
    storage.protected(disk, inv, layout=True)
    deny('disk.prepare',disk)
    deny('partition.delete',first['node'])
    deny('partition.resize',first['node'],sizeMiB=32)
    deny('filesystem.format',first['node'],format='ext4')
    deny('mount.detach',first['node'])
    deny('partition.create',disk,startMiB=2,endMiB=16)
    perform('partition.create',disk,startMiB=80,endMiB=144)
    after = storage.table(disk)
    assert first == after['partitions'][0] and before['id'] == after['id']
    data = next(p['node'] for p in after['partitions'] if p['node'] != first['node'])
    perform('filesystem.format',data,format='ext4')
    perform('partition.resize',data,sizeMiB=80)
    perform('partition.resize',data,sizeMiB=48)
    perform('partition.delete',data)
    assert not Path(data).exists()
    assert storage.table(disk)['partitions'] == [first]
    assert hashlib.sha256(sentinel.read_bytes()).digest() == digest
    print('PASS mounted system partition preserved; data create/format/grow/shrink/delete', disk, flush=True)


assert os.geteuid() == 0
with tempfile.TemporaryDirectory(prefix='panasms-layout-',dir='/var/tmp') as directory:
    scratch = Path(directory)
    loops = []
    array = '/dev/md/panasms_layout_' + str(os.getpid())
    array_active = False
    root = scratch/'root'
    root.mkdir()
    mounted = False
    try:
        for i in range(3):
            image=scratch/f'disk{i}.img'
            with image.open('wb') as stream: stream.truncate(256*1048576)
            loops.append(run('losetup','--find','--show','--partscan',str(image)))
        for label in ('gpt','msdos'):
            disk=loops[0]
            run('parted','-s',disk,'mklabel',label)
            run('parted','-s',disk,'mkpart','primary','1MiB','65MiB')
            run('udevadm','settle')
            part=storage.table(disk)['partitions'][0]['node']
            run('mkfs.ext4','-F',part)
            run('mount',part,str(root)); mounted=True
            exercise(disk,root)
            run('umount',str(root)); mounted=False
        run('mdadm','--create',array,'--run','--metadata=1.2','--level=1','--raid-devices=2',*loops[1:])
        array_active=True
        run('parted','-s',array,'mklabel','gpt')
        run('parted','-s',array,'mkpart','primary','1MiB','65MiB')
        run('udevadm','settle')
        part=storage.table(array)['partitions'][0]['node']
        run('mkfs.ext4','-F',part)
        run('mount',part,str(root)); mounted=True
        # Resolve the /dev/md alias like the public API does.
        exercise(os.path.realpath(array),root)
        for member in loops[1:]:
            deny('disk.prepare',member)
            deny('partition.create',member,startMiB=160,endMiB=180)
        deny('raid.delete',os.path.realpath(array))
        run('umount',str(root)); mounted=False
        print('PASS system-on-RAID member and array destruction rejected',flush=True)
    finally:
        if mounted: run('umount',str(root))
        if array_active: run('mdadm','--stop',array)
        for loop in reversed(loops): run('losetup','--detach',loop)
