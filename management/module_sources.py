import urllib.parse
from common import *
import module_manager as manager

CONFIG = Path('/etc/panasms/module-sources.json')
OFFICIAL = {'id': 'panasms-official', 'url': 'https://panasms.github.io/module-registry/',
            'signers': ['panasms-local', 'panasms-ci'], 'official': True}
ACTIONS = {'module.source-add', 'module.source-remove'}


def url(value):
    import ipaddress
    require(isinstance(value, str) and len(value) <= 2048, 'Invalid module repository URL')
    p = urllib.parse.urlsplit(value)
    require(p.scheme == 'https' and p.hostname and not p.username and not p.password
            and not p.fragment and not p.query and p.port in (None, 443),
            'Use an HTTPS repository URL without credentials, query or fragment')
    require(p.hostname != 'localhost' and not p.hostname.endswith(('.localhost', '.local')),
            'Use a public HTTPS repository URL')
    try:
        require(ipaddress.ip_address(p.hostname).is_global, 'Use a public HTTPS repository URL')
    except ValueError:
        pass
    return urllib.parse.urlunsplit(('https', p.netloc.lower(), p.path.rstrip('/') + '/', '', ''))


def sources():
    return json.loads(CONFIG.read_text()) if CONFIG.exists() else [OFFICIAL.copy()]


def key_fingerprint(key):
    with tempfile.TemporaryDirectory() as folder:
        p = Path(folder) / 'public.pem'
        p.write_text(key)
        result = subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(p), '-outform', 'DER'], capture_output=True)
        require(result.returncode == 0 and len(result.stdout) == 44
                and result.stdout.startswith(bytes.fromhex('302a300506032b6570032100')),
                'The repository must use an Ed25519 public key')
        return hashlib.sha256(result.stdout).hexdigest()


def discover(value):
    import module_catalog as catalog
    base = url(value)
    if base == OFFICIAL['url']:
        return OFFICIAL.copy(), None
    envelope = json.loads(catalog.download(base + 'catalog.sig', 4096))
    require(isinstance(envelope, dict), 'Invalid module catalog signature')
    signer = envelope.get('signer', '')
    require(isinstance(signer, str) and re.fullmatch('[a-zA-Z0-9_-]{1,64}', signer)
            and not signer.startswith('panasms-'), 'Choose a unique repository publisher ID')
    key = catalog.download(base + 'keys/' + signer + '.pem', 8192).decode('ascii')
    digest = key_fingerprint(key)
    existing = manager.KEYS / (signer + '.pem')
    require(not existing.exists() or key_fingerprint(existing.read_text()) == digest,
            'This publisher ID already uses another public key')
    raw = catalog.download(base + 'catalog.json', 2 * 1024 * 1024)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / (signer + '.pem')
        path.write_text(key)
        catalog.verify(raw, envelope, allowed=[signer], keys=Path(folder))
    data = json.loads(raw)
    require(isinstance(data, dict), 'Unsupported module catalog format')
    require(data.get('schemaVersion') == 1, 'Unsupported module catalog format')
    source_id = manager.identifier(data.get('id'))
    require(source_id != OFFICIAL['id'], 'Choose a unique repository ID')
    return {'id': source_id, 'url': base, 'signers': [signer], 'fingerprint': digest,
            'official': False}, key


def plan(action, p, user=None):
    existing = sources()
    if action == 'module.source-add':
        source, _ = discover(p.get('url'))
        require(len(existing) < 16, 'At most 16 module repositories are supported')
        require(not any(s['url'] == source['url'] or s['id'] == source['id'] for s in existing),
                'This module repository is already configured')
        if p.get('keyFingerprint'):
            require(p['keyFingerprint'] == source.get('fingerprint'), 'Repository signing key changed. Review the repository again.')
        p = {**p, **({'keyFingerprint': source['fingerprint']} if source.get('fingerprint') else {})}
        details = [source['url'], 'Publisher: ' + ', '.join(source['signers'])]
        if source.get('fingerprint'):
            details += ['SHA256: ' + source['fingerprint'], 'Trust this publisher to provide executable NAS modules']
    else:
        source = next((s for s in existing if s['id'] == p.get('target')), None)
        require(source, 'Module repository not found')
        details = [source['url'], 'Installed modules are retained']
    return {'target': source['id'], 'confirmation': source['id'], 'details': details,
            'publisherFingerprint': source.get('fingerprint'),
            'fingerprint': fingerprint(action, p, [existing, source])}


def execute(action, p, user=None):
    existing = sources()
    plan(action, p, user)
    if action == 'module.source-add':
        source, key = discover(p['url'])
        if key:
            require(p.get('keyFingerprint') == source['fingerprint'], 'Repository signing key changed. Review the repository again.')
            manager.KEYS.mkdir(parents=True, exist_ok=True)
            atomic(manager.KEYS / (source['signers'][0] + '.pem'), key, 0o644)
        existing.append(source)
    else:
        removed = next(s for s in existing if s['id'] == p['target'])
        existing = [s for s in existing if s['id'] != p['target']]
        atomic(CONFIG, json.dumps(existing), 0o600)
        for signer in removed['signers']:
            if not signer.startswith('panasms-') and not any(signer in s['signers'] for s in existing):
                (manager.KEYS / (signer + '.pem')).unlink(missing_ok=True)
        return {'message': 'Module repository removed'}
    atomic(CONFIG, json.dumps(existing), 0o600)
    return {'message': 'Module repository added'}
