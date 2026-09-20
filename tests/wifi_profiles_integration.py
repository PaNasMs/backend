import sys,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'management'))
import network as n
w=n.wifi
a=n.Adapter()
assert not w.radio(a)['enabled']
settings_api=a.interface(n.NM_PATH+'/Settings',n.NM+'.Settings')
for kind in ('wpa2','wpa3','owe','open'):
    token=uuid.uuid4().hex
    secret=uuid.uuid4().hex if kind in ('wpa2','wpa3') else ''
    values=w.new_settings(a,{'ssid':('ostoja-test-'+token[:16]).encode(),'security':kind,'password':secret,'hidden':True},'wlan0',str(uuid.uuid4()))
    profile,_=settings_api.AddConnection2(values,2,a.dbus.Dictionary(signature='sv'))
    api=a.interface(profile,n.NM+'.Settings.Connection')
    try:
        settings=api.GetSettings()
        assert not settings['connection']['autoconnect']
        assert secret not in str(settings) if secret else True
        api.Save()
        if secret:
            actual=api.GetSecrets('802-11-wireless-security')
            assert actual['802-11-wireless-security']['psk']==secret
        print('PASS: '+kind+' D-Bus profile accepted; secret persistence verified without activation')
    finally:
        api.Delete()
