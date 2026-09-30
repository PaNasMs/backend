#!/usr/bin/python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import storage_reshape as reshape
import storage
from common import Rejected

original_command = reshape.command
def diagnostic_command(args, **kwargs):
    if args[0] != 'systemd-run':
        return original_command(args, **kwargs)
    result = subprocess.run(args, text=True, capture_output=True, timeout=kwargs.get('timeout', 300))
    if result.returncode:
        raise Rejected(result.stderr)
    return result.stdout
reshape.command = diagnostic_command


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE).decode().strip()


def settle(md, level=None):
    for _ in range(600):
        if (md / 'sync_action').read_text().strip() == 'idle' and (md / 'reshape_position').read_text().strip() == 'none' and (level is None or (md / 'level').read_text().strip() == 'raid' + level):
            return
        time.sleep(.2)
    raise RuntimeError('Test array did not finish maintenance: ' + run('mdadm', '--detail', array))


assert os.geteuid() == 0
loops = []
array = '/dev/md/panasms_convert_' + str(os.getpid())
active = False
with tempfile.TemporaryDirectory(prefix='panasms-raid-convert-', dir='/var/tmp') as tmp:
    root = Path(tmp)
    try:
        for i in range(5):
            image = root / f'disk{i}.img'
            with image.open('wb') as f:
                f.truncate(128 * 1024 * 1024)
            loop = run('losetup', '--find', '--show', str(image))
            assert loop.startswith('/dev/loop')
            loops.append(loop)
        run('mdadm', '--create', array, '--run', '--metadata=1.2', '--level=1', '--raid-devices=2', *loops[:2])
        active = True
        run('udevadm', 'settle')
        md = Path('/sys/class/block') / Path(os.path.realpath(array)).name / 'md'
        settle(md)
        sample = os.urandom(1024 * 1024)
        with open(array, 'r+b', buffering=0) as f:
            f.write(sample)
            os.fsync(f.fileno())
        with patch.object(reshape, 'ROOT', root / 'recovery'):
            for level, extra in [('5', loops[2]), ('6', loops[3]), ('5', '')]:
                params = {'target': array, 'level': level, 'replacement': extra}
                reshape.plan('raid.convert', params)
                if level == '6':
                    (md / 'sync_speed_max').write_text('1000')
                reshape.execute('raid.convert', params)
                if level == '6':
                    for _ in range(100):
                        if (md / 'sync_action').read_text().strip() == 'reshape':
                            break
                        time.sleep(.05)
                    storage.control_reshape(md, array, 'raid.pause')
                    assert (md / 'sync_action').read_text().strip() == 'frozen'
                    (md / 'sync_speed_max').write_text('200000')
                    storage.control_reshape(md, array, 'raid.resume')
                    print('PASS paused conversion resumes with its recorded backup', flush=True)
                settle(md, level)
                assert (md / 'level').read_text().strip() == 'raid' + level
                with open(array, 'rb', buffering=0) as f:
                    assert f.read(len(sample)) == sample
                print('PASS conversion to RAID' + level + ' preserves data', flush=True)
        uuid = (md / 'uuid').read_text().strip()
        run('mdadm', '--stop', array)
        active = False
        with patch.object(reshape, 'ROOT', root / 'recovery'):
            reshape.recover()
        array = '/dev/md/panasms-recover-' + uuid.replace(':', '')[:16]
        active = True
        with open(array, 'rb', buffering=0) as f:
            assert f.read(len(sample)) == sample
        print('PASS converted array reassembles and preserves data', flush=True)
        md = Path('/sys/class/block') / Path(os.path.realpath(array)).name / 'md'
        for member in md.glob('dev-*'):
            if (member / 'slot').read_text().strip() == 'none':
                run('mdadm', '--manage', array, '--remove', '/dev/' + member.name[4:])
        old = next('/dev/' + member.name[4:] for member in md.glob('dev-*') if (member / 'slot').read_text().strip() == '0')
        run('mdadm', '--manage', array, '--fail', old)
        assert (md / 'degraded').read_text().strip() == '1'
        with open(array, 'rb', buffering=0) as f:
            assert f.read(len(sample)) == sample
        params = {'target': array, 'member': old, 'replacement': loops[4]}
        storage.plan('raid.replace', params)
        storage.execute_unlocked('raid.replace', params)
        settle(md)
        assert (md / 'degraded').read_text().strip() == '0'
        with open(array, 'rb', buffering=0) as f:
            assert f.read(len(sample)) == sample
        print('PASS degraded RAID remains readable and failed-member replacement preserves data', flush=True)
    finally:
        if active:
            run('mdadm', '--stop', array)
        for loop in reversed(loops):
            run('losetup', '--detach', loop)
