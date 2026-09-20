#!/usr/bin/python3
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import subprocess
import sys
import tempfile


def key_info(line):
    tokens=line.split()
    position=next((i for i,t in enumerate(tokens) if t.startswith(('ssh-','ecdsa-','sk-'))),None)
    if position is None or position+1>=len(tokens):
        return None
    try:
        blob=base64.b64decode(tokens[position+1],validate=True)
    except ValueError:
        return None
    fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    return {'id':hashlib.sha256(line.encode()).hexdigest(),'type':tokens[position], 'fingerprint':fingerprint,'comment':' '.join(tokens[position+2:])}


def manage(home, body):
    action=body['action']
    ssh=Path(home)/'.ssh'
    if not ssh.exists() and not ssh.is_symlink():
        if action=='list': return []
        ssh.mkdir(mode=0o700)
    directory=os.open(ssh,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fcntl.flock(directory,fcntl.LOCK_EX)
        try:
            fd=os.open('authorized_keys',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            with os.fdopen(fd) as f:
                text=f.read(131073)
                if len(text)>131072: raise ValueError('SSH keys file too large')
        except FileNotFoundError:
            text=''
        lines=text.splitlines()
        if action=='list': return [item for line in lines if (item:=key_info(line))]
        if action=='add':
            line=body.get('key','').strip()
            if '\n' in line or '\r' in line or len(line)>16384 or not re.match(r'^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ',line):
                raise ValueError('Expected one OpenSSH public key without options')
            with tempfile.NamedTemporaryFile(mode='w') as f:
                f.write(line+'\n'); f.flush()
                check=subprocess.run(['/usr/bin/ssh-keygen','-l','-f',f.name],capture_output=True,timeout=5)
                if check.returncode: raise ValueError('Invalid public key')
            item=key_info(line)
            if item is None: raise ValueError('Invalid public key')
            if any(k and k['fingerprint']==item['fingerprint'] for k in map(key_info,lines)): raise ValueError('Key already exists')
            lines.append(line)
        elif action=='delete':
            before=len(lines)
            lines=[line for line in lines if hashlib.sha256(line.encode()).hexdigest()!=body.get('id')]
            if len(lines)==before: raise ValueError('Key not found')
        else: raise ValueError('Unknown action')
        name='.authorized_keys-'+secrets.token_hex(8)
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'w') as f:
                f.write('\n'.join(lines)+'\n');f.flush();os.fsync(f.fileno())
            os.replace(name,'authorized_keys',src_dir_fd=directory,dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try: os.unlink(name,dir_fd=directory)
            except FileNotFoundError: pass
        return [item for line in lines if (item:=key_info(line))]
    finally:
        os.close(directory)


if __name__=='__main__':
    try:
        account=pwd.getpwnam(sys.argv[1])
        if account.pw_uid==0: raise ValueError('Protected account')
        os.initgroups(account.pw_name,account.pw_gid);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
        print(json.dumps(manage(account.pw_dir,json.load(sys.stdin))))
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired):
        print('SSH key operation failed',file=sys.stderr);sys.exit(1)
