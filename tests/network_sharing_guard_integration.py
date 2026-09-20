"""Live preview plus independent systemd rollback using only disposable veth adapters."""
from pathlib import Path
import json
import subprocess
import sys
import time
sys.path.insert(0, '/usr/lib/ostojaos/management')
import network as n
import network_sharing as s

def run(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()

names=['ossrc0','osdst0','osdst1'];peers=['ospeer0','ospeer1','ospeer2']
assert s.load()==[], 'Run only before any user sharing groups are configured'
assert not set(names+peers)&{r['ifname'] for r in json.loads(run('ip','-j','link'))}
before=n.read_state();a=n.Adapter();source_uuid=None
marker=Path('/tmp/ostojaos-share-preview-done');marker.unlink(missing_ok=True)
try:
    for name,peer in zip(names,peers):
        run('ip','link','add',name,'type','veth','peer','name',peer)
        run('ip','link','set',name,'up');run('ip','link','set',peer,'up')
        run('nmcli','device','set',name,'managed','yes')
        run('nmcli','device','set',peer,'managed','no')
    run('nmcli','connection','add','type','ethernet','ifname',names[0],'con-name','ostojaos-share-preview','ipv4.method','manual','ipv4.addresses','198.18.251.1/24','ipv4.never-default','yes','ipv6.method','disabled','connection.autoconnect','no')
    source_uuid=run('nmcli','-g','connection.uuid','connection','show','ostojaos-share-preview')
    run('nmcli','connection','up','uuid',source_uuid)
    device=a.device
    def wrapped(name):
        path,props=device(name)
        if name in names:props['DeviceType']=a.dbus.UInt32(1)
        return path,props
    a.device=wrapped
    with n.locked():
        s.execute(a,'network.share.save',{'name':'Connection sharing test','source':names[0],'outputs':names[1:],'mode':'nat','wifi':{},'autostart':False},'pasha')
    state=n.read_state()
    print('PREVIEW_READY '+state['id'],flush=True)
    for _ in range(0 if '--quick' in sys.argv else 200):
        if marker.exists():break
        time.sleep(.5)
    run('systemd-run','--quiet','--collect','--unit=ostojaos-share-guard-test-'+state['id'],'--on-active=2s','--timer-property=AccuracySec=1s','/usr/bin/python3','-B',s.HELPER,'--rollback',state['id'])
    for _ in range(100):
        if n.read_state()['status']=='rolled-back':break
        time.sleep(.2)
    assert s.load()==[]
    assert n.read_state()['status']=='rolled-back'
    assert state['checkpoint'] not in a.checkpoints()
    assert not set(state['newUUIDs'])&set(s.profiles(a))
    print('Independent installed systemd guard restored interfaces and removed provisional profiles',flush=True)
finally:
    state=n.read_state()
    if state and state.get('kind','').startswith('network.share.') and state['status'] in ('applying','pending'):
        with n.locked():s.rollback(a,state)
    if source_uuid:subprocess.run(['nmcli','connection','delete','uuid',source_uuid],capture_output=True)
    for name in names:subprocess.run(['ip','link','del',name],capture_output=True)
    if before:
        with n.locked():n.save_state(before)
    marker.unlink(missing_ok=True)
