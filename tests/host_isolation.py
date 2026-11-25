"""Keep unit tests away from host state that differs between machines."""
from pathlib import Path
import tempfile
from unittest.mock import patch

BOOT_ID = '00000000-0000-4000-8000-000000000149'
# Host paths whose contents depend on the machine running the tests.
HOST_PATHS = ('/var/lib/panasms-modules', '/proc/sys/kernel/random/boot_id', '/sys/class/net')
_GUARDED = ('open', 'read_text', 'read_bytes', 'exists', 'is_file', 'is_dir', 'stat', 'glob', 'iterdir', 'resolve')


def private_root(test):
    """Return a private filesystem root with a deterministic boot ID."""
    root = Path(test.enterContext(tempfile.TemporaryDirectory()))
    boot = root / 'proc/sys/kernel/random/boot_id'
    boot.parent.mkdir(parents=True)
    boot.write_text(BOOT_ID + '\n')
    return root


def redirect(root):
    """Build a Path replacement that maps absolute host paths under root."""
    scratch = Path(tempfile.gettempdir())

    def path(value):
        value = Path(value)
        # Test-owned temporary paths are already private; leave them alone.
        if value.is_absolute() and not value.is_relative_to(root) and not value.is_relative_to(scratch):
            return root / value.relative_to('/')
        return value
    return path


def forbid_host_reads(test, prefixes=HOST_PATHS):
    """Fail the test if code under test touches one of the host paths."""
    attempts = []

    def guarded(name):
        original = getattr(Path, name)

        def method(self, *args, **kwargs):
            text = str(self)
            if any(text == prefix or text.startswith(prefix + '/') for prefix in prefixes):
                attempts.append(text)
                raise AssertionError('unit test touched host path ' + text)
            return original(self, *args, **kwargs)
        return method

    for name in _GUARDED:
        test.enterContext(patch.object(Path, name, guarded(name)))
    # Code under test may swallow the AssertionError, so report attempts again.
    test.addCleanup(lambda: test.assertEqual(attempts, [], 'unit test touched host paths'))
