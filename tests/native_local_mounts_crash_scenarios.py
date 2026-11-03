#!/usr/bin/env python3
"""Controlled helper termination inside the approved owned-loop namespace."""
import hashlib,json,os,signal,subprocess,time
from pathlib import Path

def command(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
def invoke(mode,action,params,plan=None):
 body={'action':action,'params':params}
 if mode=='execute':
  if plan is None:plan=invoke('plan',action,params)
  assert not plan.get('error'),plan
  body.update(fingerprint=plan['fingerprint'],confirmation=plan['confirmation'])
 r=subprocess.run(['/usr/lib/panasms/panasms-system-helper',mode,'admin'],input=json.dumps(body),capture_output=True,text=True,timeout=180)
 assert r.returncode==0,r.stderr
 return json.loads(r.stdout)
def apply(action,params):
 result=invoke('execute',action,params);assert not result.get('error'),result
 return result

def main():
 assert os.getpid()==1 and os.geteuid()==0
 assert Path('/fixture/nonce').read_text()==os.environ['PANASMS_GO09_NONCE'] and len(os.environ['PANASMS_GO09_NONCE'])==32
 assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==os.environ['PANASMS_ACCEPTANCE_VM_UUID'].lower()
 assert not json.loads(command('ip','-j','route')) and not json.loads(command('ip','-6','-j','route'))
 helper='/usr/lib/panasms/panasms-system-helper';assert hashlib.sha256(Path(helper).read_bytes()).hexdigest()==os.environ['PANASMS_GO09_HELPER_SHA256']
 devices=json.loads(Path('/fixture/devices.json').read_text());target=devices['partition'];point='/mnt/interrupted';params={'target':target,'point':point,'mountPolicy':'manual'}
 original=Path('/etc/fstab').read_bytes()
 shim=Path('/fixture/bin/mount')
 shim.write_text('#!/usr/bin/python3\nimport os,sys,time,json\nfrom pathlib import Path\nif Path("/fixture/pause-stage").exists():\n assert sys.argv[-1].startswith("/run/panasms-local-mounts/") and sys.argv[-1].endswith(".stage")\n Path("/fixture/mount-event").write_text(json.dumps({"pid":os.getpid(),"parent":os.getppid()}))\n while True:time.sleep(.05)\nos.execv("/usr/bin/mount",["mount",*sys.argv[1:]])\n');shim.chmod(0o755)
 Path('/fixture/pause-stage').touch()
 plan=invoke('plan','mount.attach',params);assert not plan.get('error'),plan
 body=dict(action='mount.attach',params=params,fingerprint=plan['fingerprint'],confirmation=plan['confirmation'])
 worker=subprocess.Popen([helper,'execute','admin'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 worker.stdin.write(json.dumps(body));worker.stdin.close()
 event=Path('/fixture/mount-event')
 try:
  for _ in range(300):
   if event.exists():break
   assert worker.poll() is None
   time.sleep(.05)
  assert event.exists(),'stage command not observed'
  observed=json.loads(event.read_text());pid=observed['pid'];assert observed['parent']==worker.pid and pid>1
  childfd=os.pidfd_open(pid)
  try:
   assert Path('/proc',str(pid),'status').read_text().split('PPid:\t',1)[1].splitlines()[0]==str(worker.pid)
   assert str(shim).encode() in Path('/proc',str(pid),'cmdline').read_bytes()
   journal=Path('/var/lib/panasms-agent/local-mounts')/(hashlib.sha256(target.encode()).hexdigest()+'.json')
   state=json.loads(journal.read_text());assert state['phase']=='pending' and state['stageIntent'] and state.get('mountID',0)==0
   worker.kill();signal.pidfd_send_signal(childfd,signal.SIGKILL);worker.wait(timeout=10)
  finally:os.close(childfd)
 finally:
  if worker.poll() is None:worker.kill();worker.wait(timeout=10)
 Path('/fixture/pause-stage').unlink();event.unlink()
 assert Path('/etc/fstab').read_bytes()==original
 recovery=invoke('recover','mount.attach',params);assert not recovery.get('error'),recovery
 apply('mount.detach',{'target':target})
 assert not list(Path('/run/panasms-local-mounts').glob('*.stage'))
 apply('mount.attach',params);Path(point,'retained').write_text('after interrupted attach')
 apply('mount.detach',{'target':target})
 print('PASS real helper SIGKILL before staged mount, retained journal, explicit ordinary cleanup, successful next attach',flush=True)
 # A real configuration write followed by a controlled reload failure must remain retryable.
 ctl=Path('/fixture/bin/systemctl');ctl.write_text('#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\nassert sys.argv[1:]==["daemon-reload"]\nwith Path("/fixture/reload-count").open("a") as f:f.write("reload\\n")\nsys.exit(17 if Path("/fixture/fail-reload").exists() else 0)\n');ctl.chmod(0o755)
 Path('/fixture/fail-reload').touch()
 failed=invoke('execute','mount.attach',{**params,'mountPolicy':'boot'});assert failed.get('error'),failed
 Path('/fixture/fail-reload').unlink()
 before=Path('/fixture/reload-count').read_text().count('\n')
 apply('mount.detach',{'target':target})
 assert Path('/fixture/reload-count').read_text().count('\n')>before
 apply('mount.attach',params);assert Path(point,'retained').read_text()=='after interrupted attach'
 apply('mount.detach',{'target':target})
 print(json.dumps({'result':'PASS','scope':'real own helper SIGKILL and controlled daemon-reload failure; no powerloss/coldboot proof'}),flush=True)
if __name__=='__main__':main()
