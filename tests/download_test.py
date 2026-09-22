import io
import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2] / "modules/files/backend"))
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "management"))
from transfer import download


class DownloadTest(unittest.TestCase):
    def test_header_describes_opened_file_and_binary_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data"
            for content in (b"", b"\x00\xff\nOK\n" * 10000):
                path.write_bytes(content)
                output = io.BytesIO()
                download(path, output)
                header, actual = output.getvalue().split(b"\n", 1)
                self.assertEqual(header, f"OK {len(content)}".encode())
                self.assertEqual(actual, content)

    def test_symlinks_are_not_downloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_text("test")
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                download(link, io.BytesIO())
