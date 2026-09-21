import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import module_sources as s
import module_catalog as c
from common import Rejected


class Sources(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.keys = self.root / 'keys'
        self.keys.mkdir()
        for obj, name, value in [(s, 'CONFIG', self.root / 'sources.json'), (s.manager, 'KEYS', self.keys)]:
            p = patch.object(obj, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(s, 'atomic', side_effect=lambda path, text, mode=0o600: path.write_text(text))
        p.start(); self.addCleanup(p.stop)
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.root/'private')],check=True)
        subprocess.run(['openssl','pkey','-in',str(self.root/'private'),'-pubout','-out',str(self.assets/'community.pem')],check=True)
        data = {'schemaVersion':1,'id':'community','modules':[]}
        (self.assets/'catalog.json').write_text(json.dumps(data))
        subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(self.root/'private'),'-rawin','-in',str(self.assets/'catalog.json'),'-out',str(self.root/'sig')],check=True)
        (self.assets/'catalog.sig').write_text(json.dumps({'algorithm':'Ed25519','signer':'community','signature':base64.b64encode((self.root/'sig').read_bytes()).decode()}))
        p = patch.object(c, 'download', side_effect=lambda url, limit: (self.assets/url.rsplit('/',1)[1]).read_bytes())
        p.start(); self.addCleanup(p.stop)

    def test_add_requires_exact_reviewed_key_and_remove_keeps_installed_modules(self):
        self.assertEqual(s.sources(), [s.OFFICIAL])
        params = {'url':'https://example.org/modules'}
        plan = s.plan('module.source-add', params)
        with self.assertRaises(Rejected): s.execute('module.source-add', params)
        params['keyFingerprint'] = plan['publisherFingerprint']
        self.assertEqual(plan['fingerprint'], s.plan('module.source-add', params)['fingerprint'])
        s.execute('module.source-add', params)
        self.assertEqual(len(s.sources()),2)
        self.assertTrue((self.keys/'community.pem').exists())
        with self.assertRaises(Rejected):s.plan('module.source-add', params)
        with patch.object(s.manager,'execute') as install:
            s.execute('module.source-remove', {'target':'community'})
            install.assert_not_called()
        self.assertEqual(s.sources(),[s.OFFICIAL])
        s.execute('module.source-remove', {'target':s.OFFICIAL['id']})
        self.assertEqual(s.sources(),[])
        s.execute('module.source-add', {'url':s.OFFICIAL['url']})
        self.assertEqual(s.sources(),[s.OFFICIAL])

    def test_untrusted_urls_and_changed_signature(self):
        for url in ['http://example.org','https://localhost','https://127.0.0.1','https://u:p@example.org','https://example.org/?token=x']:
            with self.subTest(url=url),self.assertRaises(Rejected):s.url(url)
        raw = self.assets/'catalog.json'
        raw.write_text(raw.read_text()+' ')
        with self.assertRaisesRegex(Rejected,'signature'):s.discover('https://example.org')

    def test_source_failure_does_not_hide_other_sources_and_priority_is_stable(self):
        first = {'files':[{'manifest':{'id':'files','version':'1.0.0'}}]}
        second = {'files':[{'manifest':{'id':'files','version':'9.0.0'}}]}
        with patch.object(s,'sources',return_value=[{'id':'official'},{'id':'broken'},{'id':'custom'}]), patch.object(c,'read_catalog',side_effect=[first,Rejected('offline'),second]):
            errors=[]
            self.assertEqual(c.catalog(errors), first)
            self.assertEqual([item['repository'] for item in errors],['broken','custom'])

    def test_custom_catalog_and_installed_publisher_protection(self):
        data = json.loads((Path(__file__).parent/'fixtures/module-catalog/catalog.json').read_text())
        data['id'] = 'community'
        for module in data['modules']:
            for release in module['releases']:
                release['manifest']['signer'] = 'community'
                release['url'] = 'https://example.org/releases/' + module['id'] + '.panasms'
        (self.assets/'catalog.json').write_text(json.dumps(data))
        subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(self.root/'private'),'-rawin','-in',str(self.assets/'catalog.json'),'-out',str(self.root/'sig')],check=True)
        envelope = {'algorithm':'Ed25519','signer':'community','signature':base64.b64encode((self.root/'sig').read_bytes()).decode()}
        (self.assets/'catalog.sig').write_text(json.dumps(envelope))
        s.execute('module.source-remove', {'target':s.OFFICIAL['id']})
        plan = s.plan('module.source-add', {'url':'https://example.org/modules/'})
        s.execute('module.source-add', {'url':'https://example.org/modules/', 'keyFingerprint':plan['publisherFingerprint']})
        self.assertEqual(set(c.catalog()), {'files','terminal'})
        with patch.object(c,'compatible',return_value=''), patch.object(c.manager,'registry',return_value={'files':{'version':'0.2.0','signer':'different-publisher'}}):
            available = c.list_available()['available']
            files = next(item for item in available if item['id']=='files')
            self.assertEqual(files['repository'], 'community')
            self.assertIn('another publisher',files['reason'])
            with self.assertRaisesRegex(Rejected,'No compatible'):
                c.selection({'target':'files','version':'0.2.1'})
