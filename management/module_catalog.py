import base64
import secrets
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from common import *
import module_manager as manager

URL = 'https://panasms.github.io/module-registry/'
MAX_ARCHIVE = 128 * 1024 * 1024
ACTIONS = {'module.catalog-install'}


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == 'https' and parsed.hostname in
                ('github.com', 'release-assets.githubusercontent.com', 'panasms.github.io'),
                'Unexpected module download redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, limit, timeout=10):
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'PaNasMs/0.2'})
        with urllib.request.build_opener(Redirects).open(request, timeout=timeout) as response:
            raw = response.read(limit + 1)
        require(len(raw) <= limit, 'Module download exceeds size limit')
        return raw
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise Rejected('Module catalog download failed. Check the internet connection and try again.') from error


def verify(raw, envelope):
    require(envelope.get('algorithm') == 'Ed25519' and envelope.get('signer') in ('panasms-local', 'panasms-ci'),
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
                     str(manager.KEYS / (envelope['signer'] + '.pem')), '-rawin', '-in',
                     str(root / 'data'), '-sigfile', str(root / 'signature')])
        except Rejected:
            raise Rejected('Invalid module catalog signature')


def catalog():
    raw = download(URL + 'catalog.json', 2 * 1024 * 1024)
    verify(raw, json.loads(download(URL + 'catalog.sig', 4096)))
    data = json.loads(raw)
    require(data.get('schemaVersion') == 1 and data.get('id') == 'panasms-official',
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
            expected = re.escape(f"/{mid}-v{m['version']}/{mid}-{m['version']}-{m['architecture']}.panasms")
            require(re.fullmatch(r'https://github.com/PaNasMs/[a-z][a-z0-9-]*/releases/download' + expected, entry['url']),
                    'Untrusted module download URL')
            require(type(entry['size']) is int and 0 < entry['size'] <= MAX_ARCHIVE
                    and re.fullmatch('[a-f0-9]{64}', entry['sha256']), 'Invalid module download metadata')
            if entry['channel'] == 'stable':
                releases[mid].append(entry)
        releases[mid].sort(key=lambda e: manager.version(e['manifest']['version']), reverse=True)
    return releases


def compatible(entry):
    try:
        manager.manifest(entry['manifest'])
        return ''
    except Rejected as error:
        return str(error)


def list_available():
    result = []
    installed = manager.registry()
    for mid, releases in catalog().items():
        if not releases:
            continue
        entry = next((e for e in releases if not compatible(e)), releases[0])
        m = entry['manifest']
        reason = compatible(entry)
        current = installed.get(mid)
        result.append({**m, 'requiredBy': [], 'enabled': False, 'reason': reason,
                       'updateAvailable': bool(current and manager.version(m['version']) > manager.version(current['version']))})
    return {'available': result}


def selection(p):
    mid = manager.identifier(p.get('target'))
    requested = p.get('version')
    manager.version(requested)
    releases, installed = catalog(), manager.registry()
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
                      and (not current or manager.version(e['manifest']['version']) >= manager.version(current['version']))), None)
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
        return manager.execute('module.install', params, user)
    finally:
        bundle.unlink(missing_ok=True)
