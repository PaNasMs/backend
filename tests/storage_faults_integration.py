#!/usr/bin/python3
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
from common import command, Rejected


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE).decode().strip()


def rejected(args, message):
    try:
        command(args)
    except Rejected as error:
        assert message in str(error), str(error)
    else:
        raise AssertionError('Fault did not reach caller')


assert os.geteuid() == 0
loop = None
mounted = False
point = Path('/mnt/panasms-faults-' + str(os.getpid()))
point.mkdir()
with tempfile.TemporaryDirectory(prefix='panasms-faults-', dir='/var/tmp') as tmp:
    image = Path(tmp) / 'disk.img'
    try:
        with image.open('wb') as f:
            f.truncate(32 * 1024 * 1024)
        loop = run('losetup', '--find', '--show', str(image))
        assert loop.startswith('/dev/loop')
        run('mkfs.ext4', '-F', loop)
        run('mount', loop, str(point))
        mounted = True
        (point / 'proof').write_text('preserved')
        rejected(['dd', 'if=/dev/zero', 'of=' + str(point / 'fill'), 'bs=1M', 'count=64', 'conv=fsync', 'status=none'], 'destination is full')
        assert (point / 'proof').read_text() == 'preserved'
        (point / 'fill').unlink()
        run('sync', '-f', str(point))
        run('mount', '-o', 'remount,ro', str(point))
        rejected(['touch', str(point / 'readonly')], 'read-only')
        assert (point / 'proof').read_text() == 'preserved'
        run('umount', str(point))
        mounted = False
        run('e2fsck', '-f', '-n', loop)
        print('PASS actual ENOSPC and read-only errors are actionable; pre-existing file and filesystem remain intact', flush=True)
    finally:
        if mounted:
            run('umount', str(point))
        if loop:
            run('losetup', '--detach', loop)
        point.rmdir()
