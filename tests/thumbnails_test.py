import sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2] / "modules/files/backend"))
import os, sys, subprocess, tempfile, unittest
from pathlib import Path
from PIL import Image

MODULE = Path(__file__).resolve().parents[2] / "modules/files/backend"


class ThumbnailTest(unittest.TestCase):
    def render(self, path):
        code = "import sys;sys.path.insert(0,sys.argv[1]);from thumbnails import render;sys.stdout.buffer.write(render(sys.argv[2]))"
        return subprocess.run([sys.executable, "-c", code, str(MODULE), str(path)], capture_output=True)

    def test_downsizes_and_strips_metadata(self):
        import io

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.png"
            Image.new("RGBA", (1600, 800), (255, 0, 0, 128)).save(path)
            result = self.render(path)
            self.assertEqual(result.returncode, 0, result.stderr)
            with Image.open(io.BytesIO(result.stdout)) as image:
                self.assertEqual(image.size, (256, 128))
                self.assertEqual(image.format, "JPEG")
                self.assertFalse(image.getexif())
            self.assertLess(len(result.stdout), 20000)

    def test_rejects_symlinks_and_nonimages(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.png"
            Image.new("RGB", (10, 10)).save(path)
            link = Path(tmp) / "link.png"
            link.symlink_to(path)
            self.assertNotEqual(self.render(link).returncode, 0)
            path.write_text("<svg></svg>")
            self.assertNotEqual(self.render(path).returncode, 0)


if __name__ == "__main__":
    unittest.main()
