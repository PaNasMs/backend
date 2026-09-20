"""Root-only: exercises sharing with disposable veth pairs, never existing adapters."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import network as n
import network_sharing as s

def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()

def main():
    os.environ.pop('OSTOJAOS_OPERATION', None)
    names=['ossrc0','osdst0','osdst1']
    peers=['ospeer0','ospeer1','ospeer2']
    namespaces=['osshare-up','osshare-a','osshare-b']
    existing=json.loads(run('ip','-j','link'))
    assert not set(names+peers)&{x['ifname'] for x in existing}
    before=[run('nmcli','-g','GENERAL.CONNECTION,IP4.ADDRESS','device','show',name) for name in ('eth0','wlan0')]
    test_profiles=[]
    with tempfile.TemporaryDirectory(prefix='ostojaos-share-test-') as temp:
        n.STATE_DIR=Path(temp)/'state'
        s.ROOT=Path(temp)/'sharing'
        a=n.Adapter()
        try:
            for name,peer,ns in zip(names,peers,namespaces):
                run('ip','netns','add',ns)
                run('ip','link','add',name,'type','veth','peer','name',peer)
                run('ip','link','set',peer,'netns',ns)
                run('ip','netns','exec',ns,'ip','link','set','lo','up')
                run('ip','netns','exec',ns,'ip','link','set',peer,'up')
                run('ip','link','set',name,'up')
                run('nmcli','device','set',name,'managed','yes')
            run('ip','netns','exec',namespaces[0],'ip','addr','add','198.18.250.2/24','dev',peers[0])
            run('nmcli','connection','add','type','ethernet','ifname',names[0],'con-name','ostojaos-share-test-source','ipv4.method','manual','ipv4.addresses','198.18.250.1/24','ipv4.never-default','yes','ipv6.method','disabled','connection.autoconnect','no')
            test_profiles.append(run('nmcli','-g','connection.uuid','connection','show','ostojaos-share-test-source'))
            run('nmcli','connection','up','uuid',test_profiles[0])
            # NetworkManager identifies veth separately; exercise Ethernet logic on the identical port API.
            real_device=a.device
            def device(name):
                path,props=real_device(name)
                if name in names: props['DeviceType']=a.dbus.UInt32(1)
                return path,props
            a.device=device
            for mode in ('nat','bridge'):
                params={'name':'Integration '+mode,'source':names[0],'outputs':names[1:],'mode':mode,'wifi':{},'autostart':False}
                with n.locked():
                    result=s.execute(a,'network.share.save',params,'pasha')
                    state=n.read_state()
                    assert state['status']=='pending'
                    s.confirm(a,state)
                g=s.load()[0]
                subnet=g.get('subnet','198.18.250.0/24')
                prefix=subnet.rsplit('.',1)[0]
                for idx,ns in enumerate(namespaces[1:]):
                    run('ip','netns','exec',ns,'ip','addr','flush','dev',peers[idx+1])
                    run('ip','netns','exec',ns,'ip','addr','add',prefix+'.'+str(20+idx)+'/24','dev',peers[idx+1])
                    if mode=='nat': run('ip','netns','exec',ns,'ip','route','replace','default','via',prefix+'.1')
                if mode=='nat': s.routing(g)
                for ns in namespaces[1:]:
                    for attempt in range(20):
                        try:
                            run('ip','netns','exec',ns,'ping','-c','1','-W','2','198.18.250.2')
                            break
                        except subprocess.CalledProcessError as error:
                            if attempt==19:
                                print(error.output,flush=True)
                                print(run('ip','-4','rule'),flush=True)
                                print(run('ip','-4','route','show','table',str(28000+g['slot'])),flush=True)
                                print(run('bridge','link'),flush=True)
                                raise
                            time.sleep(1)
                run('ip','netns','exec',namespaces[1],'ping','-c','1','-W','3',prefix+'.21')
                print(mode+': client forwarding and client-to-client OK',flush=True)
                with n.locked():
                    s.execute(a,'network.share.stop',{'id':g['id']},'pasha')
                    s.rollback(a,n.read_state())
                assert s.load()[0]['enabled']
                print(mode+': stop rollback OK',flush=True)
                with n.locked():
                    s.execute(a,'network.share.stop',{'id':g['id']},'pasha')
                    s.confirm(a,n.read_state())
                    s.execute(a,'network.share.start',{'id':g['id']},'pasha')
                    s.confirm(a,n.read_state())
                    s.execute(a,'network.share.delete',{'id':g['id']},'pasha')
                    s.confirm(a,n.read_state())
                assert s.load()==[]
                print(mode+': stop/start/delete OK',flush=True)
        finally:
            state=n.read_state()
            if state and state['status'] in ('applying','pending'):
                s.rollback(a,state)
            for g in s.load():
                if g['enabled']: s.deactivate(a,g)
                s.delete_profiles(a,g['profiles'].values())
            for ident in test_profiles: subprocess.run(['nmcli','connection','delete','uuid',ident],capture_output=True)
            for name in names: subprocess.run(['ip','link','del',name],capture_output=True)
            for ns in namespaces: subprocess.run(['ip','netns','del',ns],capture_output=True)
    after=[run('nmcli','-g','GENERAL.CONNECTION,IP4.ADDRESS','device','show',name) for name in ('eth0','wlan0')]
    assert before==after
    print('Existing Ethernet and Wi-Fi connections unchanged',flush=True)

if __name__=='__main__':main()
