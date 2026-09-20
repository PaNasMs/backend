"""Temporarily use wlan0 as a private AP; preserve the wired management connection and restore Wi-Fi."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import network as n
import network_sharing as s

def run(*args): return subprocess.check_output(args,text=True).strip()

def main():
    before={name:run('nmcli','-g','GENERAL.CONNECTION,IP4.ADDRESS','device','show',name) for name in ('eth0','wlan0')}
    with tempfile.TemporaryDirectory(prefix='panasms-ap-test-') as temp:
        n.STATE_DIR=Path(temp)/'state';s.ROOT=Path(temp)/'sharing'
        a=n.Adapter()
        params={'name':'AP integration','source':'eth0','outputs':['wlan0'],'mode':'nat','autostart':False,'wifi':{'wlan0':{'ssid':'PaNasMs-test','band':'bg','password':secrets.token_urlsafe(18)}}}
        try:
            with n.locked():
                s.execute(a,'network.share.save',params,'pasha')
                assert int(a.properties(a.device('wlan0')[0],n.NM+'.Device.Wireless')['Mode'])==3
                state=n.read_state()
                assert params['wifi']['wlan0']['password'] not in json.dumps(state)
                s.confirm(a,state)
            print('AP activated; profile saved; password absent from journal',flush=True)
            g=s.load()[0]
            with n.locked():
                s.execute(a,'network.share.stop',{'id':g['id']},'pasha')
                s.confirm(a,n.read_state())
                s.execute(a,'network.share.delete',{'id':g['id']},'pasha')
                s.confirm(a,n.read_state())
        finally:
            state=n.read_state()
            if state and state['status'] in ('applying','pending'):s.rollback(a,state)
            for g in s.load():
                if g['enabled']:s.deactivate(a,g)
                s.delete_profiles(a,g['profiles'].values())
    after={name:run('nmcli','-g','GENERAL.CONNECTION,IP4.ADDRESS','device','show',name) for name in ('eth0','wlan0')}
    assert before==after,(before,after)
    print('Original Ethernet and Wi-Fi restored',flush=True)

if __name__=='__main__':main()
