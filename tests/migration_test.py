import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "migration", Path(__file__).resolve().parents[1] / "scripts/migrate-pinas.py"
)
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class MigrationTest(unittest.TestCase):
    def test_move_preserves_content_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            old, new = Path(d) / "old", Path(d) / "new"
            old.mkdir()
            (old / "credential").write_bytes(b"unchanged secret")
            (old / "credential").chmod(0o600)
            new.mkdir()
            with self.assertRaises(RuntimeError):
                migration.move(old, new)
            new.rmdir()
            migration.move(old, new)
            self.assertEqual((new / "credential").read_bytes(), b"unchanged secret")
            self.assertEqual((new / "credential").stat().st_mode & 0o777, 0o600)

    def test_move_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "outside").mkdir()
            (root / "old").symlink_to(root / "outside")
            with self.assertRaises(RuntimeError):
                migration.move(root / "old", root / "new")
            self.assertTrue((root / "outside").is_dir())

    def test_preferences_and_wallpaper_verification(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.db"
            with sqlite3.connect(path) as db:
                db.execute("create table preferences(username text,value text)")
                db.execute("create table wallpapers(username text,version text,image blob)")
                db.execute("insert into preferences values (?,?)", ("pasha", '{"language":"uk"}'))
                db.execute("insert into wallpapers values (?,?,?)", ("pasha", "1", b"image"))
            before = migration.user_state(path)
            self.assertEqual(before, migration.user_state(path))
            with sqlite3.connect(path) as db:
                db.execute("update wallpapers set image=?", (b"changed",))
            self.assertNotEqual(before, migration.user_state(path))
