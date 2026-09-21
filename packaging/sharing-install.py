#!/usr/bin/python3
from pathlib import Path
import subprocess
import shutil
import hashlib
import json
import sys

root = Path('/var/lib/panasms-installer')
conf = Path('/etc/samba/smb.conf')
marker = root / 'sharing-installed'
include = 'include = /etc/samba/panasms-shares.conf'
if sys.argv[1:] == ['--remove']:
    if marker.exists() and conf.read_text() == marker.read_text():
        saved = root / 'smb.conf.before-sharing'
        if saved.exists(): shutil.copy2(saved, conf)
    marker.unlink(missing_ok=True)
    sys.exit(0)
if not marker.exists():
    original = conf.read_text() if conf.exists() else ''
    # Existing server shares need explicit integration instead of silent replacement.
    sections = [l.strip().lower() for l in original.splitlines() if l.strip().startswith('[')]
    packaged = subprocess.check_output(['dpkg-query','-W','-f=${Conffiles}','samba-common'],text=True)
    vendor = Path('/usr/share/samba/smb.conf')
    pristine = not conf.exists() or (vendor.exists() and conf.read_bytes() == vendor.read_bytes()) or any(len(line.split()) >= 2 and line.split()[0] == str(conf) and line.split()[1] == hashlib.md5(conf.read_bytes()).hexdigest() for line in packaged.splitlines())
    if pristine:
        if conf.exists(): shutil.copy2(conf, root / 'smb.conf.before-sharing')
        managed = '''# PaNasMs standalone file server
[global]
server role = standalone server
security = user
map to guest = Never
server min protocol = SMB2_02
obey pam restrictions = yes
unix password sync = no
load printers = no
disable spoolss = yes
usershare max shares = 0
include = /etc/samba/panasms-shares.conf
'''
        conf.write_text(managed)
        marker.write_text(managed)
    else:
        print('Existing Samba configuration preserved. Add '+include+' to smb.conf after review to enable managed SMB shares.')
share = Path('/etc/samba/panasms-shares.conf')
if not share.exists(): share.write_text('# Managed by PaNasMs. Edit using Shared folders.\n')
subprocess.run(['testparm','-s'],check=True,stdout=subprocess.DEVNULL)
