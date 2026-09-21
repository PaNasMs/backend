import argparse
import datetime as dt
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
import uuid
from contextlib import contextmanager
from common import Rejected, require, json, fingerprint

ROOT = Path('/var/lib/panasms-updates')
CONFIG = Path('/etc/panasms/updates.json')
KEY = Path('/usr/share/keyrings/panasms-updates.gpg')
BASE = 'https://panasms.github.io/updates/'
ACTIVE = {'queued', 'checking', 'downloading', 'preparing', 'backing-up', 'installing', 'verifying', 'rolling-back'}
CHANGING = {'preparing', 'backing-up', 'installing', 'verifying', 'rolling-back'}
ACTIONS = {'system.update.settings', 'system.update.check', 'system.update.download', 'system.update.install', 'system.update.rollback'}
PACKAGES = {'panasms-prototype'}


def atomic(path, text):
    path=Path(path)
    require(not path.is_symlink(),'Refusing update state through a symbolic link')
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,delete=False) as f:
        temporary=Path(f.name)
        try:
            f.write(text);f.flush();os.fsync(f.fileno())
            temporary.replace(path)
            fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:temporary.unlink(missing_ok=True)


def run(args, *, cwd=None, accepted=(0,), timeout=1800):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                            env={**os.environ,'LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
    if result.returncode not in accepted:
        text=(result.stderr or result.stdout)[-3000:]
        raise Rejected(f'{Path(args[0]).name}: {text.strip()}')
    return result.stdout


def read(name, default):
    path=ROOT/name
    return json.loads(path.read_text()) if path.exists() else default


def save(name, value):
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic(ROOT/name, json.dumps(value,ensure_ascii=False))


def config():
    return json.loads(CONFIG.read_text()) if CONFIG.exists() else {'channel':'stable','mode':'notify','hour':3}


def installed():
    result={}
    for name in PACKAGES:
        p=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status} ${Version}',name],capture_output=True,text=True)
        if p.returncode==0 and p.stdout.startswith('installed '):result[name]=p.stdout.split()[1]
    return result


def greater(a,b):
    return subprocess.run(['dpkg','--compare-versions',a,'gt',b],check=False).returncode==0


def busy():
    state=read('state.json',{})
    return state.get('phase') in ACTIVE


def changing():
    s=read('state.json',{})
    return s.get('phase') in CHANGING or s.get('phase')=='recovery-required' or (s.get('phase')=='queued' and s.get('operation') in ('install','rollback'))


@contextmanager
def locked():
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (ROOT/'lock').open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        yield


def query():
    cache=read('catalog.json',{})
    current=installed()
    releases=cache.get('releases',[]) if cache.get('channel')==config()['channel'] else []
    candidate=releases[0] if releases else None
    state=read('state.json',{})
    return {'settings':config(),'installed':current,'candidate':candidate,'checkedAt':cache.get('checkedAt'),
            'available':bool(candidate and greater(candidate['version'],current.get('panasms-prototype','0'))),
            'state':state,'busy':busy(),'history':read('history.json',[]),
            'rollbackAvailable': bool(read('backup.json',{}).get('complete')) and not busy()}


def settings(p):
    require(p.get('channel') in ('stable','testing'),'Choose stable or testing')
    require(p.get('mode') in ('notify','download','auto'),'Invalid update mode')
    require(type(p.get('hour')) is int and 0<=p['hour']<=23,'Choose an update hour from 0 to 23')
    return {k:p[k] for k in ('channel','mode','hour')}


def plan(action,p,user=None):
    require(not busy(),'A system update operation is already running')
    require(read('state.json',{}).get('phase') != 'recovery-required' or action=='system.update.rollback','Restore the failed update before starting another operation')
    current=query()
    if action=='system.update.settings':
        target=settings(p);details=[target['channel'],target['mode'],str(target['hour'])]
    elif action in ('system.update.install','system.update.download'):
        require(current['available'],'No newer PaNasMs version is available in this channel')
        target=current['candidate']['version'];details=[target,'Only PaNasMs packages are updated. The panel will reconnect automatically.']
        if action.endswith('install'):preflight(target)
    elif action=='system.update.rollback':
        backup=read('backup.json',{})
        require(backup.get('complete'),'No complete rollback backup is available')
        require(backup.get('moduleHash')==module_hash(),'Installed modules changed after the backup; automatic rollback is unavailable')
        require(current['installed'].get('panasms-prototype')==backup.get('toVersion') or read('state.json',{}).get('phase')=='recovery-required','Rollback backup does not match the installed version')
        target=backup['version'];details=[target,'Restore previous PaNasMs packages, settings and databases. User files are not restored.']
    else:target=config()['channel'];details=['Check signed system update catalog']
    return {'target':str(target),'confirmation':str(target),'details':details,
            'fingerprint':fingerprint(action,p,[target,config(),current['installed'],current['candidate']])}


def execute(action,p,user=None):
    with locked():
        plan(action,p,user)
        if action=='system.update.settings':
            atomic(CONFIG,json.dumps(settings(p)))
            publish_status()
            return {'message':'Update preferences saved'}
        operation=action.rsplit('.',1)[1]
        worker=ROOT/'worker';worker.mkdir(exist_ok=True)
        for name in ('system_updates.py','common.py'):shutil.copy2(Path(__file__).parent/name,worker/name)
        save('state.json',{'id':uuid.uuid4().hex,'operation':operation,'phase':'queued','startedAt':dt.datetime.now(dt.timezone.utc).isoformat(),'version':(query()['candidate'] or {}).get('version'),'error':''})
        try:run(['systemctl','start','--no-block','panasms-update.service'],timeout=30)
        except Exception:
            save('state.json',{});raise
    return {'message':'System update operation scheduled'}


def publish_status():
    q=query();s=q['state']
    save('public.json',{'available':q['available'],'version':(q['candidate'] or {}).get('version',''),'phase':s.get('phase',''),'id':s.get('id',''),'error':s.get('error','')})


def phase(value, **extra):
    s=read('state.json',{});s.update(phase=value,**extra);save('state.json',s);publish_status()


def finish(value,error=''):
    phase(value,error=error,finishedAt=dt.datetime.now(dt.timezone.utc).isoformat())
    rows=read('history.json',[]);rows.insert(0,read('state.json',{}));save('history.json',rows[:30])


def fetch(url,limit):
    require(url.startswith(BASE) or url.startswith('https://github.com/PaNasMs/updates/releases/download/'),'Untrusted system update URL')
    with urllib.request.urlopen(url,timeout=60) as response:
        require(response.url.startswith('https://'),'Insecure system update redirect')
        value=response.read(limit+1)
    require(len(value)<=limit,'System update download exceeds size limit')
    return value


def check():
    phase('checking')
    channel=config()['channel']
    with tempfile.TemporaryDirectory(dir=ROOT) as folder:
        p=Path(folder)/'catalog.json';p.write_bytes(fetch(BASE+f'channels/{channel}.json',2*1024*1024))
        sig=p.with_suffix('.asc');sig.write_bytes(fetch(BASE+f'channels/{channel}.json.asc',16384))
        run(['gpgv','--keyring',str(KEY),str(sig),str(p)],timeout=30)
        data=json.loads(p.read_text())
    require(data.get('schemaVersion')==1 and data.get('channel')==channel,'Unsupported update catalog')
    expires=dt.datetime.fromisoformat(data['expiresAt'])
    require(expires>dt.datetime.now(dt.timezone.utc),'Update catalog has expired; installation is blocked')
    previous=read('catalog.json',{})
    if previous.get('channel')==channel:
        require(data['generatedAt']>=previous.get('generatedAt',''),'Update catalog is older than the previously verified catalog')
    data['checkedAt']=dt.datetime.now(dt.timezone.utc).isoformat();save('catalog.json',data)
    return data


def constraints(actual, required):
    v=tuple(map(int,actual.split('~')[0].split('.')))
    for part in required.split(','):
        match=re.fullmatch(r'\s*(>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)\s*',part)
        require(match,'Unsupported module compatibility requirement')
        other=tuple(map(int,match[2].split('.')))
        if not {'>=':v>=other,'<=':v<=other,'>':v>other,'<':v<other,'=':v==other}[match[1] or '=']:return False
    return True


def preflight(version, worker=False):
    require(run(['dpkg','--audit']).strip()=='','Repair the interrupted Debian package operation before updating PaNasMs')
    require(shutil.disk_usage(ROOT if ROOT.exists() else ROOT.parent).free>1024**3,'At least 1 GiB of free space is required for update and rollback')
    require(Path('/etc/os-release').read_text().find('VERSION_ID="13"')>=0 or '\nVERSION_ID=13\n' in Path('/etc/os-release').read_text(),'Updates require Debian 13 or Raspberry Pi OS based on Debian 13')
    registry=Path('/var/lib/panasms-modules/registry.json')
    if registry.exists():
        incompatible=[m.get('title',mid) for mid,m in json.loads(registry.read_text()).items() if not constraints(version,m.get('core','>=0.0.0'))]
        require(not incompatible,'Incompatible installed modules: '+', '.join(incompatible))
    for path in ('/run/panasms-network/change.json','/var/lib/panasms-agent/network-wifi/pending.json','/var/lib/panasms-agent/network-sharing/pending.json'):
        p=Path(path)
        require(not p.exists() or json.loads(p.read_text()).get('status') not in ('pending','applying'),'Confirm or undo pending network changes before updating')
    p=Path('/var/lib/panasms-agent/web-access.json')
    require(not p.exists() or json.loads(p.read_text()).get('phase') not in ('scheduled','applying'),'Wait for the HTTP port change to finish')
    p=Path('/var/lib/panasms-agent/jobs.db')
    if p.exists():
        with sqlite3.connect(f'file:{p}?mode=ro',uri=True) as db:
            rows=db.execute("SELECT action,target FROM jobs WHERE status IN ('running','queued')").fetchall()
        rows=[r for r in rows if worker or not r[0].startswith('system.update.')]
        require(not rows,'Wait for active operations: '+', '.join(f'{a} ({t})' for a,t in rows))


def download(entry):
    phase('downloading',version=entry['version'])
    arch=run(['dpkg','--print-architecture']).strip();current=installed()
    require(arch in ('arm64','amd64'),'Unsupported system architecture')
    packages=entry['packages'][arch]
    require(any(p['name']=='panasms-prototype' for p in packages),'Core package missing from release')
    folder=ROOT/'downloads';folder.mkdir(exist_ok=True)
    paths=[]
    for package in packages:
        require(package['name'] in {'panasms-prototype', 'panasms-cooling'} and re.fullmatch(r'[A-Za-z0-9_.~+-]+\.deb',package['file']),'Invalid update package')
        if package['name'] not in current:continue
        require(type(package['size']) is int and 0<package['size']<=256*1024**2,'Invalid update package size')
        path=folder/package['file']
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest()!=package['sha256']:
            raw=fetch(package['url'],package['size'])
            require(len(raw)==package['size'] and hashlib.sha256(raw).hexdigest()==package['sha256'],'System update checksum mismatch')
            temp=path.with_suffix('.tmp');temp.write_bytes(raw);temp.replace(path)
        require(run(['dpkg-deb','-f',str(path),'Package']).strip()==package['name'] and run(['dpkg-deb','-f',str(path),'Version']).strip()==entry['version'],'Update package identity mismatch')
        require(run(['dpkg-deb','-f',str(path),'Architecture']).strip() in (arch,'all'),'Update package architecture mismatch')
        paths.append(str(path))
    save('downloaded.json',{'version':entry['version'],'paths':paths})
    return paths


def apt_plan(paths):
    text=run(['apt-get','--simulate','--no-remove','install',*paths])
    require(not re.search(r'^Remv ',text,re.M),'The update would remove system packages')
    changes=re.findall(r'^Inst (\S+) \[',text,re.M)
    require(all(name.split(':')[0] in PACKAGES for name in changes),'Update system dependencies separately before installing this PaNasMs version: '+', '.join(changes))


def services():
    units=['panasms-core.service','panasms-agent.service','panasms-sharing.timer','panasms-sharing.service']
    units+=run(['systemctl','list-units','--type=service','--state=running','--no-legend','--plain','panasms-module-*.service']).splitlines()
    units=[u.split()[0] for u in units]
    return [u for u in units if subprocess.run(['systemctl','is-active','--quiet',u],check=False).returncode==0]


def stop(units):
    if units:run(['systemctl','stop',*units],timeout=90)


def start(units):
    run(['systemctl','daemon-reload'],timeout=30)
    if units:run(['systemctl','start',*units],timeout=90)


def healthy():
    port='80';p=Path('/etc/panasms/web.env')
    if p.exists():port=p.read_text().strip().removeprefix('PANASMS_HTTP_PORT=')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(45):
        try:
            with opener.open(f'http://127.0.0.1:{port}/api/v1/health',timeout=2) as r:
                good=json.load(r).get('status')=='ok'
            with opener.open(f'http://127.0.0.1:{port}/',timeout=2) as r:html=r.read(65536)
            assets=re.findall(rb'(?:src|href)="(/assets/[^"]+\.(?:js|css))"',html)
            require(bool(assets),'UI assets are missing')
            for asset in assets:
                with opener.open(f'http://127.0.0.1:{port}'+asset.decode(),timeout=2) as r:
                    require('text/html' not in r.headers.get('Content-Type',''),'UI asset was replaced by an HTML error page')
            if good and b'<html' in html and all(subprocess.run(['systemctl','is-active','--quiet',u],check=False).returncode==0 for u in ('panasms-core','panasms-agent')):
                for p in (Path('/var/lib/panasms/state.db'),Path('/var/lib/panasms-agent/jobs.db')):
                    with sqlite3.connect(f'file:{p}?mode=ro',uri=True) as db:
                        require(db.execute('PRAGMA quick_check').fetchone()[0]=='ok','Database health check failed')
                return
        except (OSError,ValueError,sqlite3.Error):pass
        time.sleep(1)
    raise Rejected('The updated panel did not pass its startup health check')


def module_hash():
    p=Path('/var/lib/panasms-modules/registry.json')
    return hashlib.sha256(p.read_bytes() if p.exists() else b'').hexdigest()


def backup(units):
    phase('backing-up')
    folder=ROOT/'backups'/read('state.json',{})['id'];folder.mkdir(parents=True)
    for name in installed():run(['dpkg-repack',name],cwd=folder,timeout=180)
    items=[p for p in ('etc/panasms','var/lib/panasms','var/lib/panasms-agent/jobs.db','var/lib/panasms-agent/jobs.db-wal','var/lib/panasms-agent/jobs.db-shm','var/lib/panasms-modules/registry.json') if (Path('/')/p).exists()]
    run(['tar','-cpf',str(folder/'data.tar'),'-C','/',*items],timeout=180)
    packages=[str(p) for p in folder.glob('*.deb')]
    require(len(packages)==len(installed()),'Could not create complete rollback packages')
    for path in folder.iterdir():
        with path.open('rb') as file:os.fsync(file.fileno())
    for path in (folder,folder.parent):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    save('backup.json',{'folder':str(folder),'packages':packages,'version':installed()['panasms-prototype'],'units':units,'complete':True,'moduleHash':module_hash(),'toVersion':read('state.json',{})['version']})


def restore(boot=False):
    b=read('backup.json',{});require(b.get('complete'),'No complete rollback backup is available')
    phase('rolling-back')
    stop(services())
    run(['dpkg','--force-confold','-i',*b['packages']],timeout=900)
    for p in (Path('/var/lib/panasms'),Path('/etc/panasms')):
        require(not p.is_symlink(),'Refusing rollback through a symbolic link')
        if p.exists():shutil.rmtree(p)
    for suffix in ('','-wal','-shm'):Path('/var/lib/panasms-agent/jobs.db'+suffix).unlink(missing_ok=True)
    run(['tar','-xpf',str(Path(b['folder'])/'data.tar'),'-C','/'],timeout=180)
    if not boot:start(b['units']);healthy()
    b['complete']=False;save('backup.json',b)


def work():
    with locked():
        s=read('state.json',{})
        if s.get('phase')!='queued':return
        time.sleep(4)
        op=s['operation'];units=[];mutated=False
        try:
            if op=='rollback':
                os.environ['PANASMS_UPDATE_TRANSACTION']=s['id'];restore();finish('rolled-back');return
            data=check()
            if op=='check':finish('checked');return
            require(data['releases'],'No release is available in this channel')
            entry=data['releases'][0]
            require(greater(entry['version'],installed().get('panasms-prototype','0')),'No newer PaNasMs version is available in this channel')
            paths=download(entry)
            if op=='download':finish('downloaded');return
            require(entry.get('rollbackCompatible') is True and not entry.get('requiresReboot'),'This release requires manual maintenance')
            phase('preparing');preflight(entry['version'],worker=True)
            apt_plan(paths)
            run(['apt-get','--download-only','--yes','--no-remove','install',*paths],timeout=1800)
            units=services();save('active-units.json',units)
            stop(units);backup(units)
            phase('installing');mutated=True
            os.environ['PANASMS_UPDATE_TRANSACTION']=s['id']
            run(['apt-get','--yes','--no-remove','-o','Dpkg::Options::=--force-confold','install',*paths],timeout=1800)
            phase('verifying');start(units);healthy()
            require(installed().get('panasms-prototype')==entry['version'],'Installed version does not match the requested update')
            finish('complete')
            try:cleanup()
            except OSError as error:print('Update cache cleanup deferred: '+str(error),file=__import__('sys').stderr)
        except Exception as e:
            if mutated:
                try:restore();finish('rolled-back',str(e))
                except Exception as recovery:finish('recovery-required',str(e)+'; recovery: '+str(recovery))
            else:
                if units:start(units)
                finish('failed',str(e))


def recover(boot=True):
    with locked():
        s=read('state.json',{})
        if s.get('phase') in ('installing','verifying','rolling-back'):
            try:
                os.environ['PANASMS_UPDATE_TRANSACTION']=s['id'];restore(boot=boot)
                finish('rolled-back','Interrupted update restored during boot')
            except Exception as e:finish('recovery-required',str(e));raise
        elif s.get('phase') in ACTIVE:
            if not boot:start(read('active-units.json',[]))
            finish('failed','Update interrupted before package installation; previous version retained')


def cleanup():
    b=read('backup.json',{})
    folders=sorted((ROOT/'backups').glob('*'),key=lambda p:p.stat().st_mtime,reverse=True) if (ROOT/'backups').exists() else []
    for p in folders[2:]:
        if p.is_dir() and not p.is_symlink() and re.fullmatch('[a-f0-9]{32}',p.name) and str(p)!=b.get('folder'):shutil.rmtree(p)
    keep=set(read('downloaded.json',{}).get('paths',[]))
    for p in (ROOT/'downloads').glob('*.deb'):
        if p.is_file() and not p.is_symlink() and str(p) not in keep:p.unlink()


def tick():
    if busy() or read('state.json',{}).get('phase')=='recovery-required':return
    cached=read('catalog.json',{})
    checked=cached.get('checkedAt')
    if cached.get('channel') != config()['channel'] or not checked or (dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(checked)).total_seconds()>86400:
        execute('system.update.check',{})
        return
    q=query();c=config()
    if not q['available'] or c['mode']=='notify':return
    version=q['candidate']['version']
    if any(h.get('operation') in ('install','download','rollback') and h.get('version')==version and h.get('phase') in ('failed','rolled-back','recovery-required') for h in q['history']):return
    if c['mode']=='download':
        if read('downloaded.json',{}).get('version')!=version:execute('system.update.download',{})
    elif dt.datetime.now().hour==c['hour']:
        try:execute('system.update.install',{})
        except Rejected:pass


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['work','recover','recover-runtime','tick']);a=p.parse_args()
    {'work':work,'recover':recover,'recover-runtime':lambda:recover(boot=False),'tick':tick}[a.mode]()
