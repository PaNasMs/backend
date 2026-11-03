#!/usr/bin/env python3
"""VM-only storage fixture; requires PANASMS_ACCEPTANCE_VM_UUID and a preserved snapshot.

Usage: native_storage_integration.py HELPER SHA256 CHILD.py SHA256 blank|ext4
The child runs as PID1 in a private root/mount/network namespace. Only its owned
loop appears in fixture inventory/cache adapters; this is not live-system proof.
Restore the disposable VM snapshot after acceptance. Never run on the NAS.
"""
import hashlib,json,os,re,secrets,shutil,signal,stat,subprocess,sys,tempfile,time
from pathlib import Path
UUID=os.environ.get('PANASMS_ACCEPTANCE_VM_UUID','').lower()
COLS='NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,UUID,LABEL,PARTUUID,PARTTYPE,MOUNTPOINTS,PKNAME,RO,PARTN,ROTA,TRAN,MAJ:MIN'
def run(*args,**kw):
 return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,**kw).strip()
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def guard():
 assert UUID and os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==UUID
 assert run('systemd-detect-virt','--vm') in ('kvm','qemu')
 assert not any(x['ifname']!='lo' and 'LOWER_UP' in x['flags'] for x in json.loads(run('ip','-j','link')))
 assert not json.loads(run('ip','-j','route')) and not json.loads(run('ip','-6','-j','route'))
 r=subprocess.run(['findmnt','-J','-t','virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs'],capture_output=True,text=True)
 assert r.returncode in (0,1) and not json.loads(r.stdout or '{}').get('filesystems')
def trusted_bytes(path,expected):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022
  data=f.read(128*1024*1024+1);assert len(data)<=128*1024*1024
 assert hashlib.sha256(data).hexdigest()==expected
 return data
def outer():
 assert len(sys.argv)==6,'helper helper-sha child.py child-sha blank|ext4'
 guard();helper_data=trusted_bytes(sys.argv[1],sys.argv[2]);child_data=trusted_bytes(sys.argv[3],sys.argv[4]);layout=sys.argv[5]
 assert layout in ('blank','ext4')
 scratch=Path(tempfile.mkdtemp(prefix='panasms-go09-',dir='/var/tmp'));image=scratch/'volume.img';root=scratch/'root';root.mkdir(mode=0o755)
 helper=scratch/'verified-helper';child=scratch/'verified-child.py'
 helper.write_bytes(helper_data);child.write_bytes(child_data);helper.chmod(0o600);child.chmod(0o600)
 with image.open('xb') as f:f.truncate(512*1024*1024)
 loop=None
 def owned():
  rows=json.loads(run('losetup','--json','--output','BACK-FILE',loop))['loopdevices']
  assert len(rows)==1 and Path(rows[0]['back-file']).resolve()==image.resolve()
 clean=False;p=None
 try:
  loop=run('losetup','--find','--show','--partscan',str(image));assert re.fullmatch(r'/dev/loop[0-9]+',loop)
  owned();nonce=secrets.token_hex(16)
  args=['unshare','--mount','--pid','--fork','--net','--kill-child=KILL','--',sys.executable,__file__,'--namespace',str(root),loop,str(helper),str(child),nonce,layout]
  p=subprocess.Popen(args,start_new_session=True)
  try:p.wait(timeout=900)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);p.wait();raise
  assert p.returncode==0,p.returncode
  print(json.dumps({'result':'PASS','helperSHA256':sys.argv[2],'childSHA256':sys.argv[4],'layout':layout,'scope':'private namespace/root, owned loop, fixture inventory/cache; not live-system integration'}),flush=True)
 finally:
  # Namespace PID1 exit terminates all descendants before the owned device is detached.
  if p is not None and p.poll() is None:
   os.killpg(p.pid,signal.SIGKILL);p.wait()
  if loop is not None:
   owned();run('losetup','--detach',loop)
   assert subprocess.run(['losetup',loop],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
  assert not run('losetup','--associated',str(image))
  clean=True
  if clean:shutil.rmtree(scratch)
def bind(source,target):
 target=Path(target);target.parent.mkdir(parents=True,exist_ok=True)
 if Path(source).is_dir():target.mkdir(exist_ok=True)
 elif target.exists() or target.is_symlink():assert stat.S_ISREG(target.lstat().st_mode)
 else:target.touch()
 run('mount','--bind',str(source),str(target));run('mount','-o','remount,bind,ro',str(target))
def namespace(root,loop,helper,child,nonce,layout):
 assert os.getpid()==1;guard();run('mount','--make-rprivate','/');root=Path(root)
 dirs=['usr/bin','usr/sbin','usr/lib/panasms','etc/panasms','etc/exports.d','proc','sys','dev','tmp','run/udev/data','fixture/bin','var/lib/panasms-agent','var/lib/panasms-installer','var/lib/dpkg','var/lib/panasms-updates','mnt','srv','root']
 for p in dirs:(root/p).mkdir(parents=True,exist_ok=True)
 for name in ('bin','sbin','lib','lib64'):(root/name).symlink_to('usr/'+name)
 for name in ('bin','sbin','lib64','lib/x86_64-linux-gnu',*[str(p.relative_to('/usr')) for p in Path('/usr/lib').glob('python3*') if p.is_dir()]):bind('/usr/'+name,root/'usr'/name)
 bind('/sys',root/'sys');run('mount','-t','proc','proc',str(root/'proc'))
 for name in ('null','urandom','random','zero'):bind('/dev/'+name,root/'dev'/name)
 (root/'dev/fd').symlink_to('/proc/self/fd')
 st=os.stat(loop);assert stat.S_ISBLK(st.st_mode);os.mknod(root/loop.lstrip('/'),stat.S_IFBLK|0o600,st.st_rdev)
 (root/'tmp').chmod(0o1777)
 for name,text in {'nsswitch.conf':'passwd: files\ngroup: files\nshadow: files\n','passwd':'root:x:0:0:root:/root:/bin/bash\nadmin:x:15000:15000:Admin:/srv/home:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n','group':'root:x:0:\nsudo:x:27:admin\nusers:x:100:admin\nadmin:x:15000:\nnogroup:x:65534:\n','shadow':'root:!:1:0:99999:7:::\nadmin:!:1:0:99999:7:::\n','fstab':'# private GO09 fixture\n','exports':''}.items():(root/'etc'/name).write_text(text)
 (root/'etc/shadow').chmod(0o600)
 (root/'etc/panasms/sharing.json').write_text('{"shares":[],"accounts":{}}');(root/'etc/panasms/sharing.json').chmod(0o600)
 (root/'var/lib/dpkg/status').write_text('Package: panasms-prototype\nStatus: install ok installed\nArchitecture: amd64\nVersion: 0.0.0-fixture\nDescription: Private fixture\n\n')
 receipt=root/'var/lib/panasms-installer/sharing-native-v1.json';receipt.write_text(json.dumps({'schema':1,'packageVersion':'0.0.0-fixture','nonce':nonce,'source':{'fresh':True}}));receipt.chmod(0o600)
 for name,source in [('panasms-system-helper',helper)]:shutil.copy(source,root/'usr/lib/panasms'/name);(root/'usr/lib/panasms'/name).chmod(0o755)
 shutil.copy(child,root/'fixture/child.py');shutil.copy(__file__,root/'fixture/scaffold.py')
 shutil.copy('/usr/bin/lsblk',root/'fixture/lsblk-real');(root/'fixture/lsblk-real').chmod(0o755)
 (root/'fixture/nonce').write_text(nonce);(root/'fixture/devices.json').write_text(json.dumps({'disk':loop,'partition':loop+'p1'}))
 lsblk=root/'fixture/bin/lsblk';lsblk.write_text('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\nassert sys.argv[1:]==["--json","--bytes","--output",'+repr(COLS)+'],sys.argv\nd=json.loads(Path("/fixture/devices.json").read_text())["disk"]\nos.execv("/fixture/lsblk-real",["lsblk",*sys.argv[1:],d])\n');lsblk.chmod(0o755)
 bind(lsblk,root/'usr/bin/lsblk')
 udev=root/'fixture/bin/udevadm';udev.write_text('#!/usr/bin/python3\nimport runpy,sys,os\nfrom pathlib import Path\nos.environ["PANASMS_GO09_NONCE"]=Path("/fixture/nonce").read_text()\nns=runpy.run_path("/fixture/scaffold.py",run_name="adapter")\nns["refresh"](sys.argv[1:])\n');udev.chmod(0o755);bind(udev,root/'usr/bin/udevadm')
 systemctl=root/'fixture/bin/systemctl';systemctl.write_text('#!/usr/bin/python3\nimport json,sys\nfrom pathlib import Path\nassert sys.argv[1:]==["daemon-reload"],sys.argv\nwith Path("/fixture/reloads.log").open("a") as f:f.write("daemon-reload\\n")\n');systemctl.chmod(0o755)
 os.chroot(root);os.chdir('/fixture');os.environ.update(PATH='/fixture/bin:/usr/sbin:/usr/bin:/sbin:/bin',PANASMS_GO09_NONCE=nonce,PANASMS_ACCEPTANCE_VM_UUID=UUID,PANASMS_GO09_HELPER_SHA256=digest('/usr/lib/panasms/panasms-system-helper'))
 if layout=='ext4':
  run('parted','--script',loop,'mklabel','gpt','mkpart','primary','ext4','1MiB','100%')
  refresh([]);run('mkfs.ext4','-F','-q',loop+'p1')
 refresh([])
 os.execv('/usr/bin/python3',['python3','/fixture/child.py'])
def refresh(args):
 assert os.geteuid()==0 and Path('/fixture/nonce').read_text()==os.environ.get('PANASMS_GO09_NONCE')
 disk=json.loads(Path('/fixture/devices.json').read_text())['disk'];name=Path(disk).name
 assert re.fullmatch(r'loop[0-9]+',name)
 assert args==[] or args==['settle'] or (args[:2]==['trigger','--action=change'] and args[2:3]==['--settle'] and len(args)==4 and re.fullmatch(re.escape(disk)+r'(p[0-9]+)?',args[3])),args
 for old in Path('/dev').glob(name+'p[0-9]*'):
  assert re.fullmatch(re.escape(name)+r'p[1-9][0-9]*',old.name)
  st=old.lstat();assert stat.S_ISBLK(st.st_mode) and st.st_uid==0
  if not (Path('/sys/class/block')/old.name).exists():old.unlink()
 paths=[Path('/sys/class/block')/name,*sorted(Path('/sys/class/block').glob(name+'p[0-9]*'))]
 active=set()
 for source in paths:
  assert source.resolve().is_relative_to(Path('/sys/devices'))
  device='/dev/'+source.name;major,minor=map(int,(source/'dev').read_text().strip().split(':'));number=f'{major}:{minor}';active.add('b'+number)
  if not Path(device).exists():os.mknod(device,stat.S_IFBLK|0o600,os.makedev(major,minor))
  assert stat.S_ISBLK(os.stat(device).st_mode) and os.stat(device).st_rdev==os.makedev(major,minor)
  result=subprocess.run(['blkid','-p','-o','export',device],capture_output=True,text=True);assert result.returncode in (0,2),result.stderr
  values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
  props={'DEVNAME':device,'DEVTYPE':'partition' if 'p' in source.name[len(name):] else 'disk'}
  for key,value in values.items():
   if key in ('TYPE','UUID','LABEL','USAGE','VERSION'):
    props['ID_FS_'+key]=value
    if key in ('UUID','LABEL'):props['ID_FS_'+key+'_ENC']=''.join(chr(b) if chr(b).isalnum() and b<128 or chr(b) in '#+-.:=@_' else '\\x%02x'%b for b in value.encode())
   elif key.startswith('PART_ENTRY_'):props['ID_'+key]=value
  text='I:123456\n'+''.join('E:'+k+'='+v+'\n' for k,v in props.items())
  cache=Path('/run/udev/data')/('b'+number);cache.write_text(text);cache.chmod(0o644)
 for cache in Path('/run/udev/data').iterdir():
  if cache.name not in active:cache.unlink()
if __name__=='__main__':
 if sys.argv[1:2]==['--namespace']:namespace(*sys.argv[2:])
 else:outer()
