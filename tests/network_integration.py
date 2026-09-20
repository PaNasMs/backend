"""Root-only integration test on an isolated veth; never edits existing interfaces."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import network as n


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def main():
    name = 'osnet-test0'
    peer = 'osnet-test1'
    profile = 'panasms-network-integration'
    assert name not in [r['ifname'] for r in json.loads(run('ip', '-j', 'link'))]
    assert profile not in run('nmcli', '-t', '-f', 'NAME', 'connection', 'show').splitlines()
    before = run('nmcli', '-g', 'IP4.ADDRESS,IP4.GATEWAY,IP4.DNS', 'device', 'show', 'eth0')
    created = False
    with tempfile.TemporaryDirectory(prefix='panasms-network-state-') as state:
        n.STATE_DIR = Path(state)
        try:
            run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', peer)
            created = True
            run('ip', 'link', 'set', peer, 'up')
            run('nmcli', 'connection', 'add', 'type', 'ethernet', 'ifname', name, 'con-name', profile,
                'ipv4.method', 'manual', 'ipv4.addresses', '198.18.91.1/30', 'ipv4.never-default', 'yes',
                'ipv6.method', 'disabled', 'connection.autoconnect', 'no')
            run('nmcli', '--wait', '10', 'connection', 'up', profile)
            a = n.Adapter()
            original = n.config(a.active(name)[2])
            values = copy.deepcopy(original)
            values['ipv4']['addresses'] = ['198.18.91.2/30']
            values['ipv4']['routes'] = [{'destination': '198.18.92.0/24', 'gateway': '198.18.91.1', 'metric': 321}]
            values['ipv6'].update(method='manual', addresses=['fd61:1a8e:99::2/64'], neverDefault=True)
            values['mtu'] = 1400
            params = {'interface': name, 'config': values}
            n.plan('network.configure', params, 'pasha')
            result = n.execute('network.configure', params, 'pasha')
            assert n.config(a.active(name)[2]) == original, 'Temporary change wrote saved profile'
            assert n.config(a.active(name)[3])['ipv4']['addresses'] == ['198.18.91.2/30']
            try:
                n.plan('network.confirm', {'id': result['change']['id']}, 'another-admin')
                raise AssertionError('Different administrator could confirm')
            except n.Rejected:
                pass
            n.execute('network.rollback', {'id': result['change']['id']}, 'pasha')
            time.sleep(1)
            assert n.config(a.active(name)[3])['ipv4']['addresses'] == original['ipv4']['addresses']
            assert not a.checkpoints(), 'Explicit rollback left checkpoint behind'
            print('PASS: temporary apply, actor restriction, explicit rollback', flush=True)
            n.TIMEOUT = 5
            result = n.execute('network.configure', params, 'pasha')
            time.sleep(7)
            with n.locked():
                assert n.current(a)['status'] == 'expired'
            assert n.config(a.active(name)[2]) == original
            assert n.config(a.active(name)[3])['ipv4']['addresses'] == original['ipv4']['addresses']
            print('PASS: automatic timeout restores original configuration', flush=True)
            n.TIMEOUT = 120
            result = n.execute('network.configure', params, 'pasha')
            n.execute('network.confirm', {'id': result['change']['id']}, 'pasha')
            assert n.config(a.active(name)[2]) == values
            assert not a.checkpoints()
            print('PASS: confirmation persists configuration', flush=True)
            params['config']['mtu'] = 1450
            result = n.execute('network.configure', params, 'pasha')
            run('nmcli', 'connection', 'modify', profile, 'ipv4.route-metric', '123')
            try:
                n.execute('network.confirm', {'id': result['change']['id']}, 'pasha')
                raise AssertionError('External profile edit was overwritten')
            except n.Rejected as error:
                assert 'externally' in str(error)
            n.execute('network.rollback', {'id': result['change']['id']}, 'pasha')
            print('PASS: external change prevents confirmation', flush=True)
        finally:
            if n.read_state() and n.read_state()['checkpoint'] in n.Adapter().checkpoints():
                n.Adapter().rollback(n.read_state()['checkpoint'])
            if created:
                subprocess.run(['nmcli', 'connection', 'delete', profile], check=False, stdout=subprocess.DEVNULL)
                subprocess.run(['ip', 'link', 'delete', name], check=False)
            assert before == run('nmcli', '-g', 'IP4.ADDRESS,IP4.GATEWAY,IP4.DNS', 'device', 'show', 'eth0'), 'Management connection changed'
            print('PASS: management connection unchanged; test devices removed', flush=True)


if __name__ == '__main__':
    main()
