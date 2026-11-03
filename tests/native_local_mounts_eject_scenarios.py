"""Run with the guarded ext4 scaffold and a localmounts Go test binary."""
import hashlib,json,os,re,subprocess
from pathlib import Path
assert os.getpid()==1 and os.geteuid()==0
assert len(os.environ['PANASMS_GO09_NONCE'])==32 and Path('/fixture/nonce').read_text()==os.environ['PANASMS_GO09_NONCE']
assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==os.environ['PANASMS_ACCEPTANCE_VM_UUID'].lower()
devices=json.loads(Path('/fixture/devices.json').read_text())
assert re.fullmatch(r'/dev/loop[0-9]+',devices['disk']) and devices['partition']==devices['disk']+'p1'
runner='/usr/lib/panasms/panasms-system-helper'
assert hashlib.sha256(Path(runner).read_bytes()).hexdigest()==os.environ['PANASMS_GO09_HELPER_SHA256']
for point in ('/mnt/x','/mnt/long-eject'):Path(point).mkdir()
for filesystem in ('ext4','btrfs'):
    if filesystem=='btrfs':
        subprocess.run(['mkfs.btrfs','-f','-q',devices['partition']],check=True)
        subprocess.run(['udevadm','trigger','--action=change','--settle',devices['partition']],check=True)
    subprocess.run(['mount',devices['partition'],'/mnt/long-eject'],check=True)
    Path('/mnt/long-eject/retained').write_text('preserved')
    subprocess.run(['mount','--bind','/mnt/long-eject','/mnt/x'],check=True)
    result=subprocess.run([runner,'-test.run','^TestDisposablePartialEject$','-test.v'],capture_output=True,text=True,env={**os.environ,'PANASMS_GO09_EJECT_FIXTURE':'1'})
    assert result.returncode==0 and '--- PASS: TestDisposablePartialEject' in result.stdout and '\nPASS\n' in result.stdout, (result.stdout,result.stderr)
    print(f'PASS {filesystem} busy and partial ordinary unmount, journal preservation, explicit retry and simulated disconnect control')
