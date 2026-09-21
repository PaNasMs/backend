import base64
import secrets
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import job_control
import module_sources
from common import *
import module_manager as manager

URL = 'https://panasms.github.io/module-registry/'
MAX_ARCHIVE = 128 * 1024 * 1024
ACTIONS = {'module.catalog-install'}


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            module_sources.url(newurl.split('?', 1)[0])
        except (Rejected, ValueError):
            raise Rejected('Unexpected module download redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, limit, timeout=10):
    module_sources.url(url.split('?', 1)[0])
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'PaNasMs/0.2'})
        with urllib.request.build_opener(Redirects).open(request, timeout=timeout) as response:
            chunks = []
            size = 0
            while size <= limit:
                job_control.checkpoint()
                block = response.read(min(65536, limit + 1 - size))
                if not block: break
                chunks.append(block)
                size += len(block)
            raw = b''.join(chunks)
        require(len(raw) <= limit, 'Module download exceeds size limit')
        return raw
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise Rejected('Module catalog download failed. Check the internet connection and try again.') from error


def verify(raw, envelope, allowed=None, keys=None):
    require(isinstance(envelope, dict), 'Invalid module catalog signature')
    require(envelope.get('algorithm') == 'Ed25519' and envelope.get('signer') in (allowed if allowed is not None else ('panasms-local', 'panasms-ci')),
            'Untrusted module catalog signer')
    try:
        signature = base64.b64decode(envelope['signature'], validate=True)
    except (KeyError, ValueError):
        raise Rejected('Invalid module catalog signature')
    require(len(signature) == 64, 'Invalid module catalog signature')
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / 'data').write_bytes(raw)
        (root / 'signature').write_bytes(signature)
        try:
            command(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
                     str((keys or manager.KEYS) / (envelope['signer'] + '.pem')), '-rawin', '-in',
                     str(root / 'data'), '-sigfile', str(root / 'signature')])
        except Rejected:
            raise Rejected('Invalid module catalog signature')


def read_catalog(source):
    base = source['url']
    raw = download(base + 'catalog.json', 2 * 1024 * 1024)
    verify(raw, json.loads(download(base + 'catalog.sig', 4096)), allowed=source['signers'])
    data = json.loads(raw)
    require(isinstance(data, dict), 'Unsupported module catalog format')
    require(data.get('schemaVersion') == 1 and data.get('id') == source['id'],
            'Unsupported module catalog format')
    releases = {}
    for item in data['modules']:
        mid = manager.identifier(item['id'])
        require(mid not in releases, 'Duplicate module in catalog')
        releases[mid] = []
        for entry in item['releases']:
            m = entry['manifest']
            require(m['id'] == mid, 'Module catalog identity mismatch')
            manager.version(m['version'])
            require(m.get('signer') in source['signers'], 'Module publisher differs from repository publisher')
            module_sources.url(entry['url'])
            if source.get('official'):
                expected = re.escape(f"/{mid}-v{m['version']}/{mid}-{m['version']}-{m['architecture']}.panasms")
                require(re.fullmatch(r'https://github.com/PaNasMs/[a-z][a-z0-9-]*/releases/download' + expected, entry['url']),
                        'Untrusted module download URL')
            entry['repository'] = source['id']
            require(type(entry['size']) is int and 0 < entry['size'] <= MAX_ARCHIVE
                    and re.fullmatch('[a-f0-9]{64}', entry['sha256']), 'Invalid module download metadata')
            if entry['channel'] == 'stable':
                releases[mid].append(entry)
        releases[mid].sort(key=lambda e: manager.version(e['manifest']['version']), reverse=True)
    return releases


def catalog(errors=None):
    result = {}
    for source in module_sources.sources():
        try:
            releases = read_catalog(source)
            for mid, entries in releases.items():
                if mid in result:
                    if errors is not None:
                        errors.append({'repository': source['id'], 'error': 'Duplicate module ID: ' + mid})
                    continue
                result[mid] = entries
        except (Rejected, ValueError, KeyError, TypeError) as error:
            if errors is None:
                raise
            errors.append({'repository': source['id'], 'error': str(error)})
    return result


def compatible(entry):
    try:
        manager.manifest(entry['manifest'])
        return ''
    except Rejected as error:
        return str(error)


def list_available():
    result = []
    installed = manager.registry()
    errors = []
    for mid, releases in catalog(errors).items():
        if not releases:
            continue
        entry = next((e for e in releases if not compatible(e)), releases[0])
        m = entry['manifest']
        reason = compatible(entry)
        current = installed.get(mid)
        if current and current.get('signer') != m.get('signer'):
            reason = 'Installed module belongs to another publisher'
        result.append({**m, 'requiredBy': [], 'enabled': False, 'reason': reason,
                       'repository': entry['repository'],
                       'updateAvailable': bool(current and manager.version(m['version']) > manager.version(current['version']))})
    return {'available': result, 'errors': errors}


def selection(p):
    mid = manager.identifier(p.get('target'))
    requested = p.get('version')
    manager.version(requested)
    releases, installed = catalog([]), manager.registry()
    chosen, visiting = {}, set()

    def visit(name, constraint, root=False):
        require(name not in visiting, 'Dependency cycle: ' + name)
        if name in chosen:
            require(manager.satisfies(chosen[name]['manifest']['version'], constraint),
                    'Conflicting module dependency: ' + name)
            return
        current = installed.get(name)
        if not root and current and manager.satisfies(current['version'], constraint):
            return
        entry = next((e for e in releases.get(name, []) if not compatible(e)
                      and manager.satisfies(e['manifest']['version'], constraint)
                      and (not current or (e['manifest'].get('signer') == current.get('signer') and manager.version(e['manifest']['version']) >= manager.version(current['version'])))), None)
        require(entry, 'No compatible module release: ' + name)
        chosen[name] = entry
        visiting.add(name)
        for dep, required in entry['manifest'].get('dependencies', {}).items():
            visit(dep, required)
        visiting.remove(name)

    visit(mid, '=' + requested, True)
    available = {name: entry['manifest'] for name, entry in chosen.items()}
    order = manager.resolve(mid, available, installed)
    for name in order:
        manager.require_idle(name, installed)
    return chosen, installed


def plan(action, p, user):
    chosen, installed = selection(p)
    return {'target': p['target'], 'confirmation': p['target'],
            'details': ['Install: ' + e['manifest']['title'] + ' ' + e['manifest']['version'] for e in chosen.values()],
            'fingerprint': fingerprint(action, p, [chosen, installed])}


def execute(action, p, user):
    job_control.capability(True)
    job_control.checkpoint()
    chosen, _ = selection(p)
    require(sum(e['size'] for e in chosen.values()) <= MAX_ARCHIVE, 'Combined module download exceeds size limit')
    manager.UPLOADS.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = secrets.token_hex(16)
    bundle = manager.UPLOADS / (user + '-' + token + '.zip')
    try:
        with tempfile.TemporaryDirectory() as folder:
            with bundle.open('xb') as output:
                os.chmod(bundle, 0o600)
                with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as merged:
                    merged.writestr('bundle.json', json.dumps({'root': p['target']}))
                    for mid, entry in chosen.items():
                        print(json.dumps({'stage': 'Downloading module: ' + mid}), file=sys.stderr, flush=True)
                        raw = download(entry['url'], entry['size'], timeout=60)
                        require(len(raw) == entry['size'] and hashlib.sha256(raw).hexdigest() == entry['sha256'],
                                'Module archive checksum mismatch: ' + mid)
                        archive = Path(folder) / (mid + '.zip')
                        archive.write_bytes(raw)
                        root, manifests = manager.inspect_bundle(archive)
                        require(root == mid and manifests == {mid: entry['manifest']}, 'Archive does not match module catalog')
                        with zipfile.ZipFile(archive) as source:
                            for name in source.namelist():
                                if name != 'bundle.json':
                                    merged.writestr(name, source.read(name))
        params = {'upload': token}
        manager.plan('module.install', params, user)
        job_control.capability(False)
        job_control.checkpoint()
        return manager.execute('module.install', params, user)
    finally:
        job_control.capability(False)
        bundle.unlink(missing_ok=True)
