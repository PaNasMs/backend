#!/usr/bin/env python3
"""Disposable user/mount/PID/network namespaces; never run against host accounts.

Build panasms-system-helper, panasms-keys and PAM-tagged panasms-password into
PANASMS_NATIVE_TEST_BIN (default /tmp/panasms-native-test-bin) before running.
Storage discovery and systemd are fixtures; account tools, PAM and key writes are real.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get('PANASMS_NATIVE_TEST_BIN', '/tmp/panasms-native-test-bin'))
if '--isolated' not in sys.argv:
    raise SystemExit(subprocess.call(['unshare', '--user', '--map-auto', '--map-root-user',
        '--mount', '--pid', '--fork', '--net', '--', sys.executable, __file__, '--isolated']))
assert os.geteuid() == 0
subprocess.run(['mount', '--make-rprivate', '/'], check=True)
with tempfile.TemporaryDirectory(prefix='panasms-native-') as temporary:
    root = Path(temporary)
    root.chmod(0o755)
    for name in ('usr/bin','usr/sbin','usr/lib/panasms','etc/pam.d','etc/default','etc/security',
                 'etc/panasms','etc/skel','etc/ssh/sshd_config.d','var/lib/panasms-agent',
                 'var/lib/panasms-updates','var/log','var/mail','home/admin','proc','dev','tmp',
                 'run','fixture/bin','srv/data','mnt/usb'):
        (root/name).mkdir(parents=True, exist_ok=True)
    for name in ('bin','sbin','lib','lib64'):
        (root/name).symlink_to('usr/'+name)
    (root/'tmp').chmod(0o1777)
    mounts=[]
    def bind(source,dest):
        dest.mkdir(parents=True,exist_ok=True)
        subprocess.run(['mount','--bind',str(source),str(dest)],check=True)
        mounts.append(dest)
        subprocess.run(['mount','-o','remount,bind,ro',str(dest)],check=True)
    try:
        for name in ('bin','sbin','lib64','lib/x86_64-linux-gnu','lib/cargo'):
            bind(Path('/usr')/name,root/'usr'/name)
        for lib in Path('/usr/lib').glob('python3*'):
            if lib.is_dir(): bind(lib,root/'usr/lib'/lib.name)
        subprocess.run(['mount','-t','proc','proc',str(root/'proc')],check=True)
        mounts.append(root/'proc')
        for name in ('null','urandom'):
            (root/'dev'/name).touch()
            subprocess.run(['mount','--bind','/dev/'+name,str(root/'dev'/name)],check=True)
            mounts.append(root/'dev'/name)
        (root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nadmin:x:15000:15000:Admin:/home/admin:/bin/bash\n')
        (root/'etc/group').write_text('root:x:0:\nadmin:x:15000:\nsudo:x:27:admin\n')
        (root/'etc/shadow').write_text('root:*:20000:0:99999:7:::\nadmin:!:20000:0:99999:7:::\n')
        (root/'etc/gshadow').write_text('root:*::\nadmin:*::\nsudo:*::admin\n')
        for name in ('shadow','gshadow'): (root/'etc'/name).chmod(0o600)
        (root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nshadow: files\n')
        (root/'etc/login.defs').write_text('UID_MIN 15000\nUID_MAX 15999\nGID_MIN 15000\nGID_MAX 15999\nENCRYPT_METHOD SHA512\n')
        (root/'etc/default/useradd').write_text('HOME=/home\n')
        (root/'etc/fstab').write_text('/dev/test /srv/data ext4 defaults 0 2\n')
        shutil.copy('/etc/shells',root/'etc/shells')
        for path in Path('/etc/pam.d').iterdir():
            if path.is_file(): shutil.copy(path,root/'etc/pam.d'/path.name)
        (root/'etc/pam.d/panasms').write_text('@include common-auth\n@include common-account\n')
        os.chown(root/'home/admin',15000,15000)
        for name in ('panasms-system-helper','panasms-keys','panasms-password'):
            shutil.copy(BIN/name,root/'usr/lib/panasms'/name)
        shutil.copytree(SOURCE/'management',root/'usr/lib/panasms/management',ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copy(__file__,root/'fixture/harness.py')
        shutil.copy(Path(__file__).with_name('native_accounts_scenarios.py'),root/'fixture/scenarios.py')
        fixture = '''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
if name=='findmnt':
 if '-n' in args: print('/srv/data' if args[-1].startswith('/srv/data') else '/');sys.exit(0)
 print(json.dumps({'filesystems':[{'target':'/','fstype':'ext4','options':'rw','maj:min':'8:1'},{'target':'/srv/data','fstype':'ext4','options':'rw','maj:min':'8:2'},{'target':'/mnt/usb','fstype':'ext4','options':'rw','maj:min':'8:3'}]}))
elif name=='lsblk':
 print(json.dumps({'blockdevices':[{'name':'sda','maj:min':'8:1','type':'disk','rm':False,'tran':'sata','children':[{'name':'sda2','maj:min':'8:2','type':'part','rm':False}]},{'name':'sdb','maj:min':'8:3','type':'disk','rm':False,'tran':'usb'}]}))
elif name=='sshd':
 if '-T' in args:
  text=Path('/etc/ssh/sshd_config.d/60-panasms-users.conf').read_text()
  print(text.lower().replace('denyusers','denyusers'))
elif name=='apt-get':
 if '--simulate' in args: print('Inst sample [1.0] (2.0 Debian:stable [amd64])')
 else:
  with open('/fixture/commands','a') as f:f.write(json.dumps([name,*args])+'\\n')
elif name=='dpkg':
 path=Path('/fixture/dpkg-audit')
 if '--audit' in args: print(path.read_text() if path.exists() else '',end='')
 elif '--configure' in args: path.write_text('')
 else: sys.exit(1)
elif name=='vcgencmd': print('throttled=0x10005')
elif name=='journalctl': print(json.dumps({'__REALTIME_TIMESTAMP':'123456','PRIORITY':'4','_SYSTEMD_UNIT':'demo.service','MESSAGE':'Fixture journal'}))
elif name=='loginctl': pass
elif name in ('systemctl','systemd-run'):
 with open('/fixture/commands','a') as f:f.write(json.dumps([name,*args])+'\\n')
 if name=='systemctl' and args[0]=='list-units': print(json.dumps([{'unit':'demo.service','active':'active'}]))
 if name=='systemctl' and args[0]=='list-unit-files': print(json.dumps([{'unit_file':'demo.service','state':'enabled'}]))
 if name=='systemctl' and args[0]=='show':
  print('loaded' if '--value' in args and '--property=LoadState' in args else 'ActiveState=active\\nUnitFileState=enabled\\nLoadState=loaded')
else: sys.exit(1)
'''
        for name in ('findmnt','lsblk','sshd','loginctl','systemctl','systemd-run','apt-get','dpkg','vcgencmd','journalctl'):
            path=root/'fixture/bin'/name;path.write_text(fixture);path.chmod(0o755)
        proc=subprocess.run(['chroot',str(root),'/usr/bin/env','PATH=/fixture/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                             '/usr/bin/python3','/fixture/scenarios.py'],text=True)
        if proc.returncode: raise SystemExit(proc.returncode)
    finally:
        for path in reversed(mounts): subprocess.run(['umount','-l',str(path)],check=True)
