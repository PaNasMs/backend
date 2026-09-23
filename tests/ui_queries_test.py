import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import host
import sharing
from common import Rejected

class PresentationQueriesTest(unittest.TestCase):
    def test_package_version_fields(self):
        row = host.package_detail('Inst firefox [155.0-1] (156.0-1 Raspberry Pi:stable [arm64])')
        self.assertEqual((row['name'], row['installed'], row['available']), ('firefox', '155.0-1', '156.0-1'))
        self.assertEqual(host.package_detail('Remv obsolete [1.0]')['action'], 'remove')
        self.assertEqual(host.package_detail('Inst new (2.0 Debian:stable [arm64])')['installed'], '')

    def test_folder_browser_excludes_remote_root_and_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'media').mkdir()
            (root / 'file').write_text('x')
            (root / 'link').symlink_to('/etc', target_is_directory=True)
            rows = {'filesystems': [
                {'target': '/', 'fstype': 'ext4'},
                {'target': '/srv/remote', 'fstype': 'nfs4'},
                {'target': folder, 'fstype': 'ext4'},
            ]}
            with patch.object(sharing, 'json_command', return_value=rows), patch.object(host, 'export_path', side_effect=lambda value: Path(value)):
                self.assertEqual(sharing.folders('')['roots'], [{'name': root.name, 'path': folder}])
                self.assertEqual([r['name'] for r in sharing.folders(folder)['folders']], ['media'])
                with self.assertRaises(Rejected):
                    sharing.folders('/etc')
