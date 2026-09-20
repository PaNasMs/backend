import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import module_catalog as c
from common import Rejected

ROOT = Path(__file__).resolve().parents[2]


class Catalog(unittest.TestCase):
    def setUp(self):
        self.key = patch.object(c.manager, 'KEYS', ROOT / 'backend/packaging')
        self.key.start()
        self.addCleanup(self.key.stop)

    def test_published_catalog_signature_and_tampering(self):
        raw = (ROOT / 'backend/tests/fixtures/module-catalog/catalog.json').read_bytes()
        envelope = json.loads((ROOT / 'backend/tests/fixtures/module-catalog/catalog.sig').read_text())
        c.verify(raw, envelope)
        with self.assertRaisesRegex(Rejected, 'signature'):
            c.verify(raw + b' ', envelope)
        with self.assertRaisesRegex(Rejected, 'signer'):
            c.verify(raw, {**envelope, 'signer': 'attacker'})

    def test_ci_signer_uses_separately_pinned_key(self):
        import base64
        import subprocess
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(root / 'private')], check=True)
            subprocess.run(['openssl', 'pkey', '-in', str(root / 'private'), '-pubout', '-out', str(root / 'ostojaos-ci.pem')], check=True)
            raw = b'{"schemaVersion":1}'
            (root / 'data').write_bytes(raw)
            subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(root / 'private'), '-rawin', '-in', str(root / 'data'), '-out', str(root / 'signature')], check=True)
            envelope = {'algorithm': 'Ed25519', 'signer': 'ostojaos-ci', 'signature': base64.b64encode((root / 'signature').read_bytes()).decode()}
            with patch.object(c.manager, 'KEYS', root):
                c.verify(raw, envelope)
                with self.assertRaises(Rejected):
                    c.verify(raw + b' ', envelope)
                with self.assertRaises(Rejected):
                    c.verify(raw, {**envelope, 'signer': '../private'})

    def test_signed_catalog_parser(self):
        with patch.object(c, 'download', side_effect=lambda url, limit: (ROOT / 'backend/tests/fixtures/module-catalog' / url.rsplit('/', 1)[1]).read_bytes()):
            self.assertEqual(set(c.catalog()), {'files', 'terminal'})

    def test_dependencies_and_no_downgrade(self):
        def entry(mid, v, dependencies=None):
            return {'manifest': {'id': mid, 'version': v, 'dependencies': dependencies or {}}}
        releases = {'files': [entry('files', '1.1.0', {'indexer': '>=1.0.0'})],
                    'indexer': [entry('indexer', '1.2.0')]}
        with patch.object(c, 'catalog', return_value=releases), patch.object(c, 'compatible', return_value=''), patch.object(c.manager, 'require_idle'), patch.object(c.manager, 'registry', return_value={}):
            chosen, _ = c.selection({'target': 'files', 'version': '1.1.0'})
            self.assertEqual(set(chosen), {'files', 'indexer'})
        with patch.object(c, 'catalog', return_value=releases), patch.object(c, 'compatible', return_value=''), patch.object(c.manager, 'registry', return_value={'files': {'version': '2.0.0'}}):
            with self.assertRaisesRegex(Rejected, 'No compatible'):
                c.selection({'target': 'files', 'version': '1.1.0'})

    def test_conflicting_dependencies(self):
        releases = {name: [{'manifest': {'id': name, 'version': '1.0.0', 'dependencies': deps}}] for name, deps in
                    [('files', {'indexer': '>=1.0.0', 'viewer': '>=1.0.0'}), ('indexer', {}), ('viewer', {'indexer': '>=2.0.0'})]}
        with patch.object(c, 'catalog', return_value=releases), patch.object(c, 'compatible', return_value=''), patch.object(c.manager, 'registry', return_value={}):
            with self.assertRaisesRegex(Rejected, 'Conflicting'):
                c.selection({'target': 'files', 'version': '1.0.0'})

    def test_download_corruption_never_reaches_installer(self):
        entry = {'size': 3, 'sha256': '0' * 64, 'url': 'https://github.com/unused'}
        with tempfile.TemporaryDirectory() as folder, patch.object(c.manager, 'UPLOADS', Path(folder)), patch.object(c, 'selection', return_value=({'files': entry}, {})), patch.object(c, 'download', return_value=b'bad'), patch.object(c.manager, 'execute') as install:
            with self.assertRaisesRegex(Rejected, 'checksum'):
                c.execute('module.catalog-install', {'target': 'files'}, 'pasha')
            install.assert_not_called()
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_private_redirect_rejected(self):
        with self.assertRaisesRegex(Rejected, 'redirect'):
            c.Redirects().redirect_request(None, None, 302, '', {}, 'http://192.168.1.100/')
