import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import homes


class HomesTest(unittest.TestCase):
    def test_default_and_affected_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'useradd'
            config.write_text('HOME=/srv/data/homes\n')
            users = [SimpleNamespace(pw_dir=p) for p in ('/srv/data/homes/a', '/srv/data/homes/nested/b', '/srv/data/homes-other/a', '/root')]
            with patch.object(homes, 'DEFAULTS', config), patch.object(homes.pwd, 'getpwall', return_value=users):
                self.assertEqual(homes.base(), '/srv/data/homes')
                self.assertEqual(homes.affected(homes.base()), users[:2])

    def test_busy_user_error_identifies_process(self):
        with self.assertRaisesRegex(homes.HomeBusy, r'test-user: .+'):
            homes.idle('/nonexistent', [SimpleNamespace(pw_uid=os.getuid(), pw_name='test-user')])

    def test_cloud_sync_is_named_and_processes_are_grouped(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            for pid in ('900001', '900002'):
                folder = proc / pid; folder.mkdir()
                (folder / 'comm').write_text('python3\n')
                (folder / 'cgroup').write_text('0::/system.slice/ostojaos-cloud-sync-user-1000.service\n')
                (folder / 'cmdline').write_text('must not be included in diagnostics')
            with patch.object(homes, 'PROC', proc), patch.object(homes, 'command') as command:
                rows = homes.blockers('/home/test', [SimpleNamespace(pw_uid=os.getuid(), pw_name='test')])
                command.assert_not_called()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['title'], 'Cloud Sync')
            self.assertEqual(rows[0]['user'], 'test')
            self.assertEqual(rows[0]['reason'], 'session')
            self.assertCountEqual([p['pid'] for p in rows[0]['processes']], [900001, 900002])
            self.assertNotIn('must not', str(rows))

    def test_preflight_exposes_blockers_without_a_plan(self):
        issue = {'title': 'Cloud Sync', 'user': 'test'}
        with patch.object(homes, 'plan', side_effect=homes.HomeBusy([issue])):
            self.assertEqual(homes.preflight('/srv/new'), {'blockers': [issue]})

    def test_recovery_restores_paths_and_preserves_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source'; source.mkdir()
            target = Path(tmp) / 'target'; target.mkdir()
            (target / 'data').write_text('copied')
            backup = Path(tmp) / 'backup'; backup.mkdir()
            journal = Path(tmp) / 'journal'
            state = {'source': str(source), 'target': str(target), 'backup': str(backup), 'phase': 'switching', 'users':[{'name':'test','old':str(source / 'test'),'new':str(target / 'test')}]}
            journal.write_text(homes.json.dumps(state))
            with patch.object(homes, 'mounted', return_value=False), patch.object(homes, 'JOURNAL', journal), patch.object(homes.pwd, 'getpwnam', return_value=SimpleNamespace(pw_dir=str(target / 'test'))), patch.object(homes, 'command') as command:
                homes.recover()
                command.assert_any_call(['usermod','--home',str(source / 'test'),'--','test'])
                command.assert_any_call(['useradd','--defaults','--base-dir',str(source)])
            self.assertTrue(source.exists())
            self.assertTrue((target / 'data').exists())
            self.assertFalse(journal.exists())

    def test_committed_recovery_cleans_only_old_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source'; source.mkdir()
            (source / 'old').write_text('old')
            target = Path(tmp) / 'target'; target.mkdir()
            (target / 'new').write_text('new')
            backup = Path(tmp) / 'backup'; backup.mkdir()
            journal = Path(tmp) / 'journal'
            journal.write_text(homes.json.dumps({'source':str(source),'target':str(target),'backup':str(backup),'phase':'committed','users':[]}))
            with patch.object(homes, 'mounted', return_value=False), patch.object(homes, 'JOURNAL', journal), patch.object(homes, 'command') as command:
                homes.recover()
                command.assert_not_called()
            self.assertFalse(source.exists())
            self.assertEqual((target / 'new').read_text(), 'new')

    def test_unavailable_destination_never_removes_source_after_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source'; source.mkdir()
            journal = Path(tmp) / 'journal'
            journal.write_text(homes.json.dumps({'source':str(source),'target':tmp+'/missing','backup':tmp+'/backup','phase':'committed','users':[]}))
            with patch.object(homes, 'JOURNAL', journal):
                with self.assertRaisesRegex(homes.Rejected, 'unavailable'):
                    homes.recover()
            self.assertTrue(source.exists())
            self.assertTrue(journal.exists())

    def test_nested_destination_and_pending_recovery_rejected(self):
        with patch.object(homes, 'base', return_value='/home'), patch.object(homes, 'JOURNAL') as journal:
            journal.exists.return_value = False
            for destination in ('/home/new', '/home', '/'):
                with self.assertRaises(homes.Rejected):
                    homes.inspect(destination)
            journal.exists.return_value = True
            with self.assertRaisesRegex(homes.Rejected, 'recovered'):
                homes.inspect('/srv/data/homes')


if __name__ == '__main__':
    unittest.main()
