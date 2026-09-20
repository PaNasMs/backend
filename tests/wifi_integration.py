"""Test radio/scan/recovery on an idle Wi-Fi adapter while management stays on Ethernet."""
from pathlib import Path
import json
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'management'))
import network as n
w = n.wifi


def main():
    a = n.Adapter()
    assert not w.radio(a)['enabled'], 'This test requires initially disabled Wi-Fi'
    profiles = a.interface(n.NM_PATH+'/Settings',n.NM+'.Settings').ListConnections()
    assert not any(a.interface(p,n.NM+'.Settings.Connection').GetSettings()['connection']['type']=='802-11-wireless' for p in profiles), 'Do not enable Wi-Fi with existing auto-connect profiles during this test'
    before = subprocess.check_output(['nmcli','-g','IP4.ADDRESS,IP4.GATEWAY,IP4.DNS','device','show','eth0'])
    state_before = n.read_state()
    recovery_before = w.RECOVERY.read_text() if w.RECOVERY.exists() else None
    w.HELPER = str(Path(n.__file__).with_name('wifi.py'))
    states = []
    def change(enabled):
        result=n.execute('network.wifi.radio',{'interface':'wlan0','enabled':enabled},'pasha')
        states.append(n.read_state())
        return {'id':result['change']['id']}
    try:
        n.TIMEOUT=5
        pending=change(True)
        assert w.radio(a)['enabled']
        # No query/current call: the independent systemd guard must perform rollback.
        for _ in range(30):
            time.sleep(.5)
            if n.read_state()['status']=='expired': break
        assert n.read_state()['status']=='expired', 'Independent radio watchdog did not run'
        assert not w.radio(a)['enabled']
        print('PASS: independent systemd timeout restores Wi-Fi radio',flush=True)
        n.TIMEOUT=120
        pending=change(True)
        n.execute('network.confirm',pending,'pasha')
        assert w.radio(a)['enabled']
        time.sleep(3)
        n.execute('network.wifi.scan',{'interface':'wlan0'},'pasha')
        view=n.query()
        assert view['wifi']['present'] and view['wifi']['enabled']
        row=next(r for r in view['interfaces'] if r['name']=='wlan0')
        print('PASS: enable, confirm, scan; found '+str(len(row['wifi']['networks']))+' access points',flush=True)
        pending=change(False)
        n.execute('network.rollback',pending,'pasha')
        assert w.radio(a)['enabled']
        pending=change(False)
        n.execute('network.confirm',pending,'pasha')
        assert not w.radio(a)['enabled']
        print('PASS: disable, explicit rollback and persistent confirmation',flush=True)
        pending=change(True)
        with n.locked():
            state=n.read_state();state['boot']='simulated-previous-boot';w.remember(state)
        w.recover()
        assert not w.radio(a)['enabled'] and n.read_state()['status']=='expired'
        print('PASS: recovery restores radio after a simulated boot change',flush=True)
    finally:
        with n.locked():
            state=n.read_state()
            if state and state.get('kind','').startswith('network.wifi.') and state['status'] in ('pending','applying'):
                w.rollback(a,state)
            w.set_radio(a,False)
            for state in states: w.disarm(state)
            if state_before: n.save_state(state_before)
            else: (n.STATE_DIR/'change.json').unlink(missing_ok=True)
            if recovery_before is not None: w.RECOVERY.write_text(recovery_before)
            else: w.RECOVERY.unlink(missing_ok=True)
        assert before==subprocess.check_output(['nmcli','-g','IP4.ADDRESS,IP4.GATEWAY,IP4.DNS','device','show','eth0'])
        print('PASS: management connection unchanged; original radio state restored',flush=True)


if __name__=='__main__': main()
