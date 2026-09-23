"""Executed only by native_accounts_integration.py inside its disposable chroot."""
import grp
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

assert Path('/fixture/bin/findmnt').exists(), 'Run through isolated harness'
import ctypes
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0  # Reap optional PAM daemons in the disposable PID namespace.
sys.path.insert(0,'/usr/lib/panasms/management')
import accounts as legacy
import host as legacy_host
import job_recovery as legacy_recovery
from unittest.mock import patch
helper='/usr/lib/panasms/panasms-system-helper'
subprocess.run(['chpasswd'],input='admin:isolated-admin-password\n',text=True,check=True)

def call(mode,body,user='admin'):
    p=subprocess.run([helper,mode,user],input=json.dumps(body),text=True,capture_output=True,check=True)
    return json.loads(p.stdout)

def plan(action,params,user='admin',parity=True):
    result=call('plan',{'action':action,'params':params},user)
    assert not result.get('error'),result
    if parity:
        expected=legacy.plan(action,params,user)
        assert result==expected,(action,result,expected)
    return result

def perform(action,params,parity=True):
    planned=plan(action,params,parity=parity)
    result=call('execute',{'action':action,'params':params,**{k:planned[k] for k in ('fingerprint','confirmation')}})
    assert not result.get('error'),result
    print('PASS',action,flush=True)
    return result

def denied(action,params,user='admin'):
    result=call('plan',{'action':action,'params':params},user)
    assert result.get('error') and result.get('noChanges'),result

perform('group.create',{'target':'family'})
perform('user.create',{'target':'testuser','name':'Initial','password':'isolated-test-password'})
u=pwd.getpwnam('testuser')
assert u.pw_shell=='/usr/sbin/nologin' and Path(u.pw_dir).stat().st_mode&0o777==0o700
for target in ('','admin','testuser','root'):
    result=call('query',{'view':'accounts' if not target else 'account-details','target':target})
    with patch.object(legacy,'key_operation',lambda *args:[]): expected=legacy.query(target or None)
    assert result==expected,(target,result,expected)
print('PASS query parity',flush=True)
denied('user.create',{'target':'usbuser','home':'/mnt/usb/user','password':'test'})
denied('user.delete',{'target':'admin'})
denied('user.delete',{'target':'root'})
denied('user.edit',{'target':'admin','groups':[]})
denied('group.edit',{'target':'sudo','members':[]})
perform('user.edit',{'target':'testuser','name':'Changed','groups':['family']})
assert pwd.getpwnam('testuser').pw_gecos=='Changed'
perform('group.edit',{'target':'family','members':[]})
assert 'testuser' not in grp.getgrnam('family').gr_mem
perform('user.password',{'target':'testuser','password':'different-isolated-password'})

def change(current,next):
 p=subprocess.run(['/usr/lib/panasms/panasms-password'],input=json.dumps({'user':'testuser','current':current,'next':next}),text=True,capture_output=True,check=True)
 return json.loads(p.stdout)
assert change('wrong','new-isolated-password').get('error')
assert not change('different-isolated-password','changed-isolated-password').get('error')
subprocess.run(['chage','--mindays','10','testuser'],check=True)
assert change('changed-isolated-password','too-soon-password').get('error')
subprocess.run(['chage','--mindays','0','--lastday','0','testuser'],check=True)
assert not change('changed-isolated-password','forced-isolated-password').get('error')
subprocess.run(['chage','--expiredate','1','testuser'],check=True)
assert change('forced-isolated-password','expired-change').get('error')
assert call('query',{'view':'account-details'},'testuser').get('error')
subprocess.run(['chage','--expiredate','-1','testuser'],check=True)
print('PASS PAM wrong/current password, minimum age, forced change and expiry',flush=True)
security={'target':'testuser','panel':True,'ssh':True,'disabled':False,'forcePasswordChange':False,'expiry':'','minDays':0,'maxDays':99999,'warnDays':7,'inactiveDays':-1,'shell':'/bin/bash'}
perform('user.security',security)
assert pwd.getpwnam('testuser').pw_shell=='/bin/bash'
assert call('query',{'view':'account-details','target':'admin'},'testuser')['username']=='testuser'
denied('group.create',{'target':'bad'},'testuser')
perform('user.security',{**security,'disabled':True})
assert call('query',{'view':'account-details'},'testuser').get('error')
perform('user.security',security)
# Fresh state rejects a previously valid plan before mutation.
stale=plan('group.create',{'target':'stale'})
perform('group.create',{'target':'intervening'})
result=call('execute',{'action':'group.create','params':{'target':'stale'},**stale})
assert result.get('noChanges') and result.get('error'),result
# Updater gate blocks otherwise valid changes.
state=Path('/var/lib/panasms-updates/state.json');state.write_text('{"phase":"installing"}')
denied('group.create',{'target':'blocked'})
state.unlink()
# Recreated identity cannot use an old policy or queued actor.
policy=json.loads(Path('/etc/panasms/accounts.json').read_text())
actor={'uid':u.pw_uid,'epoch':policy['testuser']['epoch'],'principal':policy['testuser']['principal']}
perform('user.password',{'target':'testuser','password':'another-isolated-password'})
result=call('plan',{'action':'user.session.end','params':{'target':'testuser'},'actor':actor},'testuser')
assert result.get('noChanges') and 'changed' in result.get('error',''),result
# Actual key writes occur with target credentials, never root.
subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f','/tmp/key'],check=True)
key=Path('/tmp/key.pub').read_text().strip()
perform('user.key.add',{'target':'testuser','key':key},parity=False)
keys=call('query',{'view':'account-details','target':'testuser'})['keys']
assert len(keys)==1 and Path('/home/testuser/.ssh/authorized_keys').stat().st_uid==u.pw_uid
perform('user.key.delete',{'target':'testuser','keyId':keys[0]['id']},parity=False)
ssh=Path('/home/testuser/.ssh');ssh.rename('/home/testuser/.ssh-saved');ssh.symlink_to('/tmp')
result=call('execute',{'action':'user.key.add','params':{'target':'testuser','key':key},'fingerprint':'invalid','confirmation':'testuser'})
assert result.get('error') and result.get('noChanges')
ssh.unlink();Path('/home/testuser/.ssh-saved').rename(ssh)
while True:
 try:
  if os.waitpid(-1,os.WNOHANG)[0]==0: break
 except ChildProcessError: break
perform('user.home',{'target':'testuser','home':'/srv/data/testuser'})
assert pwd.getpwnam('testuser').pw_dir=='/srv/data/testuser'
perform('user.identity',{'target':'testuser','uid':15500})
assert Path('/srv/data/testuser').stat().st_uid==15500
# Primary sudo membership participates in protection independently of gr_mem.
perform('user.edit',{'target':'testuser','groups':[],'primaryGroup':'sudo'})
denied('user.edit',{'target':'testuser','groups':[],'primaryGroup':'family'},'testuser')
# Group primary members cannot be removed implicitly.
denied('group.edit',{'target':'sudo','members':['admin']})
perform('user.edit',{'target':'testuser','groups':[],'primaryGroup':'family'})
Path('/srv/data/testuser/keep').write_text('data');os.chown('/srv/data/testuser/keep',15500,grp.getgrnam('family').gr_gid)
Path('/tmp/outside').write_text('preserve')
Path('/srv/data/testuser/link').symlink_to('/tmp/outside')
perform('user.delete',{'target':'testuser','deleteHome':True})
assert not Path('/srv/data/testuser').exists() and Path('/tmp/outside').read_text()=='preserve'
perform('group.delete',{'target':'family'})
print('PASS native isolated account acceptance',flush=True)

for action in ('service.start','service.stop','service.restart','service.enable','service.disable'):
 params={'target':'demo.service'}
 expected=legacy_host.plan(action,params)
 actual=call('plan',{'action':action,'params':params})
 assert actual==expected,(action,actual,expected)
 result=call('execute',{'action':action,'params':params,**actual})
 assert not result.get('error'),result
 print('PASS',action,flush=True)
for target in ('ssh.service','panasms-core.service','systemd-logind.service','../bad.service'):
 denied('service.stop',{'target':target})
for action,params in [('user.delete',{'target':'testuser'}),('user.password',{'target':'admin'}),('service.restart',{'target':'demo.service'}),('system.reboot',{}),('system.poweroff',{}),('system.web-port',{})]:
 body={'action':action,'params':params}
 expected=legacy_recovery.inspect(body)
 actual=call('recover',body)
 assert actual==expected,(action,actual,expected)
print('PASS native recovery parity (inspection only)',flush=True)

for view in ('services','journal','power','updates'):
 expected=legacy_host.query(view,'')
 actual=call('query',{'view':view})
 assert actual==expected,(view,actual,expected)
 print('PASS host query parity',view,flush=True)
for action in ('updates.refresh','updates.install','updates.repair','system.reboot','system.poweroff'):
 if action=='updates.repair': Path('/fixture/dpkg-audit').write_text('sample requires configuration\n')
 expected=legacy_host.plan(action,{})
 actual=call('plan',{'action':action,'params':{}})
 assert actual==expected,(action,actual,expected)
 result=call('execute',{'action':action,'params':{},**actual})
 assert not result.get('error'),result
 print('PASS host fixture execution',action,flush=True)
import web_access as legacy_web
params={'port':8080}
expected=legacy_web.plan('system.web-port',params)
actual=call('plan',{'action':'system.web-port','params':params})
assert actual==expected,(actual,expected)
result=call('execute',{'action':'system.web-port','params':params,**actual})
assert not result.get('error'),result
assert call('query',{'view':'web-access'})==legacy_web.query()
assert call('query',{'view':'web-access'})['pending']
subprocess.run([helper,'web-access','--recover'],check=True)
assert call('query',{'view':'web-access'})==legacy_web.query()
assert not call('query',{'view':'web-access'})['pending']
assert subprocess.check_output([helper,'web-access','--configure','--port','8081'],text=True).strip()=='8081'
assert subprocess.check_output([helper,'web-access','--current'],text=True).strip()=='8081'
print('PASS web port CLI, deferred schedule, startup rollback and Python parity',flush=True)
