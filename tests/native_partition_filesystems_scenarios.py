#!/usr/bin/env python3
"""Native partition/filesystem acceptance child for native_storage_integration.py.

Requires the scaffold's private PID/mount/network namespace, owned loop, nonce,
synthetic NSS accounts, and pinned packaged helper. Never run directly on a host.
The private inventory/cache adapters do not prove physical hotplug behavior.
"""
import hashlib,json,os,subprocess
from pathlib import Path

def command(*args):
 return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT).strip()
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def invoke(mode,action,params,plan=None,user='admin'):
 body={'action':action,'params':params}
 if plan is not None:body.update(fingerprint=plan['fingerprint'],confirmation=plan['confirmation'])
 result=subprocess.run(['/usr/lib/panasms/panasms-system-helper',mode,user],input=json.dumps(body),capture_output=True,text=True,timeout=300)
 assert result.returncode==0,result.stderr[-4000:]
 data=json.loads(result.stdout)
 return {'ok':not bool(data.get('error')),'data':data,'error':data.get('error')}

def plan(action,params):
 result=invoke('plan',action,params);assert result['ok'],result
 return result['data']
def apply(action,params):
 result=invoke('execute',action,params,plan(action,params));assert result['ok'],result
 return result['data']
def denied(action,params):
 result=invoke('plan',action,params);assert not result['ok'],result

def main():
 assert os.geteuid()==0 and os.getpid()==1
 nonce=os.environ.get('PANASMS_GO09_NONCE','');assert len(nonce)==32 and Path('/fixture/nonce').read_text()==nonce
 uuid=os.environ['PANASMS_ACCEPTANCE_VM_UUID'];assert Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==uuid.lower()
 assert not json.loads(command('ip','-j','route')) and not json.loads(command('ip','-6','-j','route'))
 helper='/usr/lib/panasms/panasms-system-helper';assert digest(helper)==os.environ['PANASMS_GO09_HELPER_SHA256']
 devices=json.loads(Path('/fixture/devices.json').read_text());disk=devices['disk'];first=disk+'p1';second=disk+'p2'
 import re
 assert re.fullmatch(r'/dev/loop[0-9]+',disk)
 for point in ('neighbor','data'):Path('/mnt/'+point).mkdir()
 base_config=Path('/etc/fstab').read_text()
 for action in ('partition.create','partition.delete','partition.resize','filesystem.format','filesystem.remove','filesystem.resize','storage.recover'):
  for mode in ('plan','execute','recover'):
   result=invoke(mode,action,{'target':disk},user='nobody');assert not result['ok'],(action,mode,result)
 unconfirmed=plan('partition.create',{'target':disk,'startMiB':1,'endMiB':97})
 result=invoke('execute','partition.create',{'target':disk,'startMiB':1,'endMiB':97},{**unconfirmed,'confirmation':'wrong-device'})
 assert not result['ok'] and not Path('/sys/class/block/'+Path(first).name).exists()
 print('PASS actual helper member denial and exact target confirmation',flush=True)
 apply('partition.create',{'target':disk,'startMiB':1,'endMiB':97})
 apply('filesystem.format',{'target':first,'format':'ext4'})
 first_uuid=command('blkid','-s','UUID','-o','value',first)
 command('mount',first,'/mnt/neighbor');marker=Path('/mnt/neighbor/retained');marker.write_bytes(b'GO09A neighbor data\n'*4096);first_hash=digest(marker)
 Path('/etc/fstab').write_text(base_config+f'UUID={first_uuid} / ext4 defaults 0 2\n')
 for action in ('partition.delete','filesystem.remove','filesystem.format'):
  denied(action,{'target':first,'format':'ext4'})
 before_first=json.loads(command('sfdisk','--json',disk))['partitiontable']['partitions'][0]
 apply('partition.create',{'target':disk,'startMiB':128,'endMiB':384})
 apply('filesystem.format',{'target':second,'format':'ext4'})
 command('mount',second,'/mnt/data');data=Path('/mnt/data/payload');data.write_bytes(b'GO09A resize data\n'*8192);data_hash=digest(data);command('umount','/mnt/data')
 for action,size in [('partition.resize',128),('partition.resize',320),('filesystem.resize',256),('filesystem.resize',320)]:
  apply(action,{'target':second,'sizeMiB':size})
  command('mount',second,'/mnt/data');assert digest(data)==data_hash;command('umount','/mnt/data')
  current=json.loads(command('sfdisk','--json',disk))['partitiontable']['partitions'][0]
  assert current==before_first and digest(marker)==first_hash
 print('PASS actual GPT creation, protected neighbor, ext shrink/grow and retained data',flush=True)
 params={'target':second,'format':'ext4'};stale=plan('filesystem.format',params)
 config=Path('/etc/fstab');saved=config.read_text();config.write_text(saved+'# foreign edit\n')
 result=invoke('execute','filesystem.format',params,stale);assert not result['ok'] and config.read_text()==saved+'# foreign edit\n'
 config.write_text(saved)
 print('PASS stale plan refuses foreign configuration without destructive replay',flush=True)
 # Only the private executable wrapper logs actual formatter invocations.
 wrapper=Path('/fixture/bin/mkfs.ext4');wrapper.write_text('#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\nwith Path("/fixture/formatter-calls").open("a") as f:f.write("mkfs.ext4\\n")\nos.execv("/usr/sbin/mkfs.ext4",["mkfs.ext4",*sys.argv[1:]])\n');wrapper.chmod(0o755)
 systemctl=Path('/fixture/bin/systemctl');systemctl.write_text('#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\nassert sys.argv[1:]==["daemon-reload"]\nwith Path("/fixture/reloads.log").open("a") as f:f.write("daemon-reload\\n")\nsys.exit(17 if Path("/fixture/fail-reload").exists() else 0)\n');systemctl.chmod(0o755)
 for fault in ('before-config-write','after-config-write'):
  old_uuid=command('blkid','-s','UUID','-o','value',second)
  config.write_text(saved+f'UUID={old_uuid} /mnt/data ext4 defaults 0 2\n')
  if fault=='before-config-write':
   command('mount','--bind','/etc/fstab','/etc/fstab');command('mount','-o','remount,bind,ro','/etc/fstab')
  else:Path('/fixture/fail-reload').touch()
  try:
   result=invoke('execute','filesystem.format',params,plan('filesystem.format',params));assert not result['ok'],result
  finally:
   if fault=='before-config-write':command('umount','/etc/fstab')
   else:Path('/fixture/fail-reload').unlink()
  journal=Path('/var/lib/panasms-agent/storage')/(hashlib.sha256(second.encode()).hexdigest()+'.json')
  state=json.loads(journal.read_text());assert state['phase']=='pending' and state['configOnlyRemaining'] and not state['configReconciled']
  alias=Path('/dev/fixture-recovery-alias')
  if not alias.exists():alias.symlink_to(second)
  alias_params={**params,'target':str(alias)}
  report=invoke('recover','filesystem.format',alias_params)
  assert report['ok'] and report['data']['recoveryAction']=='storage.recover',report
  count=Path('/fixture/formatter-calls').read_text().count('\n')
  interrupted_plan=plan('filesystem.format',params)
  assert 'Interrupted operation: filesystem.format' in interrupted_plan['details']
  assert any('Interrupted writes are never repeated automatically.' in detail for detail in interrupted_plan['details'])
  denied_result=invoke('execute','filesystem.format',params,interrupted_plan);assert not denied_result['ok']
  assert Path('/fixture/formatter-calls').read_text().count('\n')==count
  assert invoke('recover','storage.recover',alias_params)['data']['recoveryAction']=='storage.recover'
  apply('storage.recover',{'target':str(alias)})
  assert Path('/fixture/formatter-calls').read_text().count('\n')==count
  state=json.loads(journal.read_text());assert state['phase']=='complete' and state['configReconciled']
  assert config.read_text()==saved and digest(marker)==first_hash
  report=invoke('recover','storage.recover',{'target':second})
  assert report['ok'] and report['data'].get('recoveryAction') is None,report
 print('PASS actual format then fstab/reload failures recover configuration without repeated formatting',flush=True)
 for filesystem in ('vfat','btrfs','xfs'):
  apply('filesystem.format',{'target':second,'format':filesystem})
  assert command('blkid','-s','TYPE','-o','value',second)==filesystem
  command('mount',second,'/mnt/data');data.write_bytes(b'GO09A mounted resize\n'*4096);mounted_hash=digest(data)
  if filesystem=='btrfs':
   apply('filesystem.resize',{'target':second,'sizeMiB':256});assert digest(data)==mounted_hash
   apply('filesystem.resize',{'target':second,'sizeMiB':0});assert digest(data)==mounted_hash
  elif filesystem=='xfs':
   denied('filesystem.resize',{'target':second,'sizeMiB':256})
   apply('filesystem.resize',{'target':second,'sizeMiB':0});assert digest(data)==mounted_hash
  command('umount','/mnt/data')
  assert digest(marker)==first_hash
 print('PASS actual FAT/Btrfs/XFS formats and mounted Btrfs/XFS resize identity',flush=True)
 apply('filesystem.remove',{'target':second});assert not command('wipefs','--no-act','--output','TYPE','--noheadings',second)
 apply('partition.delete',{'target':second});assert not Path('/sys/class/block/'+Path(second).name).exists()
 assert json.loads(command('sfdisk','--json',disk))['partitiontable']['partitions'][0]==before_first and digest(marker)==first_hash
 command('umount','/mnt/neighbor');config.write_text(base_config)
 apply('filesystem.remove',{'target':first});apply('partition.delete',{'target':first})
 # An existing MBR is fixture setup; native creation still uses its real table.
 command('parted','--script',disk,'mklabel','msdos');command('udevadm','settle')
 apply('partition.create',{'target':disk,'startMiB':1,'endMiB':129})
 assert json.loads(command('sfdisk','--json',disk))['partitiontable']['label']=='dos'
 apply('partition.delete',{'target':first})
 assert config.read_text()==base_config
 print(json.dumps({'result':'PASS','helperSHA256':digest(helper),'stages':7,'scope':'CI packaged native helper plan/execute/recover and real NSS authorization on disposable loop; private inventory/cache adapters; no full package installation/hotplug/boot proof'}),flush=True)

if __name__=='__main__':main()
