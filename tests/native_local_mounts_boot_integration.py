#!/usr/bin/env python3
"""Persistent mount policy acceptance in a disposable VM.

Set PANASMS_ACCEPTANCE_VM_UUID, verify a preserved snapshot, run setup, reboot,
run check, then restore that snapshot with the VM stopped. setup configures
four owned loop images and a fixture service in this VM.
"""
import grp,hashlib,json,os,pwd,re,stat,subprocess,sys,time
from pathlib import Path
UUID=os.environ.get('PANASMS_ACCEPTANCE_VM_UUID','').strip().lower()
ROOT=Path('/var/tmp/panasms-go09b-boot')
UNIT='panasms-go09b-fixture-loops.service'
def run(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
def guard():
 assert UUID and os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==UUID
 assert run('systemd-detect-virt','--vm') in ('kvm','qemu')
 assert not json.loads(run('ip','-j','route')) and not json.loads(run('ip','-6','-j','route'))
 assert not any(x['ifname']!='lo' and 'LOWER_UP' in x['flags'] for x in json.loads(run('ip','-j','link')))
 r=subprocess.run(['findmnt','-J','-t','virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs'],capture_output=True,text=True)
 assert r.returncode in (0,1) and not json.loads(r.stdout or '{}').get('filesystems')
def write_json(path,value):
 path.write_text(json.dumps(value));path.chmod(0o600)
 with path.open() as f:os.fsync(f.fileno())
def state():
 assert ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_uid==0 and ROOT.stat().st_mode&0o777==0o700
 p=ROOT/'state.json';assert p.is_file() and not p.is_symlink() and p.stat().st_uid==0 and p.stat().st_mode&0o777==0o600
 return json.loads(p.read_text())
def mount_rows():
 rows=[]
 for line in Path('/proc/self/mountinfo').read_text().splitlines():
  left,right=line.split(' - ',1);a=left.split();b=right.split();rows.append((a[4],b[0]))
 return rows
def owned(loop,image):
 assert re.fullmatch(r'/dev/loop[0-9]+',loop)
 rows=json.loads(run('losetup','--json','--output','BACK-FILE',loop))['loopdevices']
 assert len(rows)==1 and Path(rows[0]['back-file']).resolve()==image.resolve()
def invoke(helper,actor,action,params):
 def request(mode,body):
  r=subprocess.run([str(helper),mode,actor],input=json.dumps(body),capture_output=True,text=True,timeout=180)
  assert r.returncode==0,r.stderr
  answer=json.loads(r.stdout);assert not answer.get('error'),answer
  return answer
 body={'action':action,'params':params};plan=request('plan',body)
 body.update(fingerprint=plan['fingerprint'],confirmation=plan['confirmation']);return request('execute',body)
def setup(helper_path,expected):
 guard();helper_source=Path(helper_path);fd=os.open(helper_source,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
  data=f.read(128*1024*1024+1)
 assert len(data)<=128*1024*1024 and hashlib.sha256(data).hexdigest()==expected
 assert not ROOT.exists();ROOT.mkdir(mode=0o700);helper=ROOT/'helper';helper.write_bytes(data);helper.chmod(0o700)
 members=grp.getgrnam('sudo').gr_mem;users=[u for u in pwd.getpwall() if 1000<=u.pw_uid<65534 and u.pw_name in members];assert users
 actor=sorted(users,key=lambda x:x.pw_uid)[0].pw_name
 original=Path('/etc/fstab').read_bytes();(ROOT/'fstab-before').write_bytes(original);(ROOT/'fstab-before').chmod(0o600)
 config={'schema':1,'bootBefore':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'helperSHA256':expected,'actor':actor,'volumes':[],'services':{}}
 for name in ('panasms-agent.service','panasms-core.service','smbd.service','nfs-server.service'):
  r=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True);config['services'][name]=r.stdout.strip()
 write_json(ROOT/'state.json',config)
 for name,policy in [('boot','boot'),('manual','manual'),('demand','on-demand'),('missing','boot')]:
  image=ROOT/(name+'.img')
  with image.open('xb') as f:f.truncate(64*1024*1024)
  loop=run('losetup','--find','--show',str(image));owned(loop,image)
  point=Path('/mnt/panasms-go09b-'+name);assert not point.exists();point.mkdir(mode=0o755)
  run('mkfs.ext4','-F','-q',loop);run('udevadm','trigger','--action=change','--settle',loop)
  uuid=run('blkid','-s','UUID','-o','value',loop);assert re.fullmatch(r'[0-9a-f-]{36}',uuid)
  run('mount',loop,str(point));payload='GO09B retained '+name+'\n';(point/'payload').write_text(payload);run('umount',str(point))
  volume={'name':name,'policy':policy,'image':str(image),'point':str(point),'uuid':uuid,'payload':payload,'initialLoop':loop};config['volumes'].append(volume);write_json(ROOT/'state.json',config)
  invoke(helper,actor,'mount.settings',{'target':loop,'point':str(point),'mountPolicy':policy})
  if name=='missing':owned(loop,image);run('losetup','--detach',loop)
 script=ROOT/'fixture.py';script.write_bytes(Path(__file__).read_bytes());script.chmod(0o700)
 unit=Path('/etc/systemd/system')/UNIT;assert not unit.exists()
 unit.write_text('[Unit]\nDescription=Disposable GO09B owned loop fixture\nDefaultDependencies=no\nAfter=systemd-udevd.service\nBefore=local-fs-pre.target shutdown.target\nConflicts=shutdown.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment=PANASMS_ACCEPTANCE_VM_UUID='+UUID+'\nExecStart=/usr/bin/python3 '+str(script)+' loops\nExecStop=/usr/bin/python3 '+str(script)+' detach\n[Install]\nWantedBy=sysinit.target\n')
 run('systemctl','daemon-reload');run('systemctl','enable',UNIT)
 assert Path('/etc/fstab').read_bytes().startswith(original)
 print(json.dumps({'result':'SETUP_READY_FOR_REBOOT','helperSHA256':expected,'ownedUUIDs':[v['uuid'] for v in config['volumes']],'bootBefore':config['bootBefore']}))
def loops(detach=False):
 # Executed at boot/shutdown: network/service readiness is deliberately not required.
 assert UUID and os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==UUID
 config=state()
 for volume in config['volumes']:
  if volume['name']=='missing':continue
  image=Path(volume['image']);assert image.parent==ROOT and image.is_file() and not image.is_symlink() and image.stat().st_uid==0
  rows=json.loads(run('losetup','--list','--json','--associated',str(image)))['loopdevices']
  if detach:
   for row in rows:
    loop=row['name'];owned(loop,image);run('losetup','--detach',loop)
  else:
   assert not rows
   loop=run('losetup','--find','--show',str(image));owned(loop,image);run('udevadm','trigger','--action=change','--settle',loop)
def wait_for_services(previous,timeout=180):
 names=sorted(name for name,state in previous.items() if state=='active')
 if not names:return {}
 states={}
 deadline=time.monotonic()+timeout
 while (remaining:=deadline-time.monotonic())>0:
  try:
   result=subprocess.run(['systemctl','is-active',*names],capture_output=True,text=True,timeout=min(5,remaining))
  except subprocess.TimeoutExpired:
   states=dict.fromkeys(names,'query timeout')
  else:
   values=result.stdout.splitlines()
   states={name:values[i] if i<len(values) else 'missing status' for i,name in enumerate(names)}
   if len(values)==len(names) and all(value=='active' for value in values):return states
  time.sleep(min(2,max(0,deadline-time.monotonic())))
 raise AssertionError({'servicesAfterBoot':states})
def check():
 guard();config=state();assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=config['bootBefore']
 helper=ROOT/'helper';assert hashlib.sha256(helper.read_bytes()).hexdigest()==config['helperSHA256']
 before=mount_rows();evidence={}
 for volume in config['volumes']:
  name=volume['name'];point=volume['point'];types=[fs for path,fs in before if path==point]
  if name=='boot':assert types==['ext4'],types
  elif name=='demand':assert types==['autofs'],types
  else:assert types==[],types
  if name=='missing':
   assert not Path('/dev/disk/by-uuid',volume['uuid']).exists();continue
  rows=json.loads(run('losetup','--list','--json','--associated',volume['image']))['loopdevices'];assert len(rows)==1
  loop=rows[0]['name'];owned(loop,Path(volume['image']))
  if name=='manual':invoke(helper,config['actor'],'mount.attach',{'target':loop,'point':point,'mountPolicy':'manual'})
  assert Path(point,'payload').read_text()==volume['payload']
  assert (point,'ext4') in mount_rows()
  unit=run('systemd-escape','--path','--suffix=mount',point)
  evidence[name]={'beforeAccess':types,'afterAccess':'ext4','beforeUnits':run('systemctl','show',unit,'--property=Before','--value')}
 states=wait_for_services(config['services'])
 print(json.dumps({'result':'PASS','scope':'actual VM reboot; native persistent boot/manual/on-demand/missing policy and retained own-loop data','evidence':evidence,'servicesAfterBoot':states,'shutdownOrdering':'Before dependencies recorded; no claim that every module consumer has mount-specific ordering'}))
if __name__=='__main__':
 if sys.argv[1:2]==['setup'] and len(sys.argv)==4:setup(*sys.argv[2:])
 elif sys.argv[1:]==['loops']:loops()
 elif sys.argv[1:]==['detach']:loops(True)
 elif sys.argv[1:]==['check']:check()
 else:raise SystemExit('setup HELPER SHA256 | loops | detach | check; VM-only')
