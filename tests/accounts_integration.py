#!/usr/bin/python3
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

os.chdir("/")

if sys.argv[1:] != ["--isolated"]:
    raise SystemExit(
        subprocess.call(
            ["unshare", "--mount", "--pid", "--fork", "--", sys.executable, __file__, "--isolated"]
        )
    )
subprocess.run(["mount", "--make-rprivate", "/"], check=True)
with tempfile.TemporaryDirectory(prefix="ostojaos-accounts-test-", dir="/var/tmp") as temporary:
    root = Path(temporary)
    root.chmod(0o755)
    for p in [
        "usr",
        "etc/pam.d",
        "etc/default",
        "var/lib/ostojaos-agent",
        "srv/data",
        "etc/security",
        "etc/skel",
        "home/admin",
        "proc",
        "dev",
        "tmp",
        "var/log",
        "var/mail",
        "run",
        "code",
    ]:
        (root / p).mkdir(parents=True, exist_ok=True)
    for p in ["bin", "sbin", "lib"]:
        (root / p).symlink_to("usr/" + p)
    mounted = []
    try:
        subprocess.run(["mount", "--bind", "/usr", str(root / "usr")], check=True)
        mounted.append(root / "usr")
        subprocess.run(["mount", "-o", "remount,bind,ro", str(root / "usr")], check=True)
        subprocess.run(["mount", "-t", "proc", "proc", str(root / "proc")], check=True)
        mounted.append(root / "proc")
        for name in ["null", "urandom"]:
            (root / "dev" / name).touch()
            subprocess.run(["mount", "--bind", "/dev/" + name, str(root / "dev" / name)], check=True)
            mounted.append(root / "dev" / name)
        subprocess.run(["mount", "--bind", str(root / "srv/data"), str(root / "srv/data")], check=True)
        mounted.append(root / "srv/data")
        (root / "etc/fstab").write_text("/dev/test /srv/data ext4 defaults 0 2\n")
        (root / "etc/default/useradd").write_text("HOME=/home\n")
        (root / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\nadmin:x:15000:15000:Admin:/home/admin:/bin/bash\n"
        )
        (root / "etc/group").write_text("root:x:0:\nadmin:x:15000:\nsudo:x:27:admin\n")
        (root / "etc/shadow").write_text("root:*:20000:0:99999:7:::\nadmin:!:20000:0:99999:7:::\n")
        (root / "etc/shadow").chmod(0o600)
        (root / "etc/gshadow").write_text("root:*::\nadmin:*::\nsudo:*::admin\n")
        (root / "etc/gshadow").chmod(0o600)
        (root / "etc/nsswitch.conf").write_text("passwd: files\nshadow: files\ngroup: files\n")
        (root / "etc/login.defs").write_text(
            "UID_MIN 15000\nUID_MAX 15999\nGID_MIN 15000\nGID_MAX 15999\nENCRYPT_METHOD SHA512\n"
        )
        for name in ["common-password", "chpasswd"]:
            shutil.copy("/etc/pam.d/" + name, root / "etc/pam.d" / name)
        for p in (Path(__file__).resolve().parents[1] / "management").glob("*.py"):
            shutil.copy(p, root / "code" / p.name)
        (root / "code/test.py").write_text(
            """import accounts,pwd,grp
from common import Rejected
from pathlib import Path

def perform(action,p):
    accounts.plan(action,p,'admin');accounts.execute(action,p);print('PASS',action,flush=True)
perform('group.create',{'target':'family'})
perform('user.create',{'target':'testuser','name':'Initial','home':'/home/testuser','password':'isolated-test-only'})
u=pwd.getpwnam('testuser');assert u.pw_shell=='/usr/sbin/nologin';assert Path(u.pw_dir).stat().st_mode&0o777==0o700
perform('user.edit',{'target':'testuser','name':'Changed','groups':['family']})
assert pwd.getpwnam('testuser').pw_gecos=='Changed'
perform('user.password',{'target':'testuser','password':'different-isolated-test'})
(Path(u.pw_dir)/'marker').write_text('preserve')
import os
os.chown(Path(u.pw_dir)/'marker',u.pw_uid,u.pw_gid)
perform('user.home',{'target':'testuser','home':'/home/moved'})
assert Path('/home/moved/marker').read_text()=='preserve'
try:accounts.plan('user.delete',{'target':'root'},'admin');raise AssertionError('root accepted')
except Rejected:pass
try:accounts.plan('user.delete',{'target':'admin'},'admin');raise AssertionError('self accepted')
except Rejected:pass
perform('user.delete',{'target':'testuser','deleteHome':True})
assert not Path('/home/moved').exists()
perform('group.delete',{'target':'family'})
import homes,subprocess
Path('/home/admin/marker').write_text('preserve home data')
Path('/home/admin/link').symlink_to('marker')
os.link('/home/admin/marker','/home/admin/hardlink')
os.chmod('/home/admin',0o2750)
subprocess.run(['setfacl','-m','d:u::rwx,d:g::r-x,d:o::---','/home/admin'],check=True)
acl=subprocess.check_output(['getfacl','-cp','/home/admin'],text=True)
perform('homes.move',{'destination':'/srv/data/homes'})
assert homes.base()=='/srv/data/homes'
assert pwd.getpwnam('admin').pw_dir=='/srv/data/homes/admin'
assert not Path('/home').exists()
new=Path('/srv/data/homes/admin')
assert (new/'marker').read_text()=='preserve home data'
assert (new/'marker').stat().st_ino==(new/'hardlink').stat().st_ino
assert (new/'link').is_symlink()
assert new.stat().st_mode&0o7777==0o2750
assert subprocess.check_output(['getfacl','-cp',str(new)],text=True)==acl
assert not homes.JOURNAL.exists() and not homes.NOLOGIN.exists()
perform('user.create',{'target':'newuser','password':'isolated-test-only'})
assert pwd.getpwnam('newuser').pw_dir=='/srv/data/homes/newuser'
perform('user.delete',{'target':'newuser','deleteHome':True})
from unittest.mock import patch
original=homes.command
def fail_switch(args, **kwargs):
    if args==['useradd','--defaults','--base-dir','/srv/data/failed']:
        raise Rejected('injected switch failure')
    return original(args, **kwargs)
with patch.object(homes,'command',side_effect=fail_switch):
    try:
        homes.execute({'destination':'/srv/data/failed'})
        raise AssertionError('failure injection not triggered')
    except Rejected as e:
        assert 'injected switch failure' in str(e),str(e)
assert homes.base()=='/srv/data/homes'
assert pwd.getpwnam('admin').pw_dir=='/srv/data/homes/admin'
assert (new/'marker').read_text()=='preserve home data'
assert not homes.mounted('/srv/data/homes')
assert not homes.JOURNAL.exists() and not homes.NOLOGIN.exists()
print('PASS users/groups, whole-home move, defaults, metadata, and rollback isolated from host')
"""
        )
        subprocess.run(["chroot", str(root), "/usr/bin/python3", "/code/test.py"], check=True)
    finally:
        if subprocess.run(["findmnt", "--mountpoint", str(root / "home")], stdout=subprocess.DEVNULL).returncode == 0:
            subprocess.run(["umount", str(root / "home")], check=True)
        for p in reversed(mounted):
            subprocess.run(["umount", str(p)], check=True)
