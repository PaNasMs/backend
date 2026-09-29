import importlib.util
import json
import hashlib
import hmac
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("panasms_link", Path(__file__).with_name("__init__.py"))
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

class RelayTest(TestCase):
    def test_authenticated_payload_and_fixed_destination(self):
        captured = []
        class Response:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *args): pass
        class Opener:
            def open(self, request, timeout):
                captured.append(request)
                return Response()
        with patch.object(plugin, "build_opener", return_value=Opener()):
            self.assertTrue(plugin.relay("http://nas.test", "secret", "a" * 32, SimpleNamespace(id=123, full_name="Паша", username="pasha")))
        request = captured[0]
        self.assertEqual(request.full_url, "http://nas.test/api/v1/notification-telegram-relay")
        body = json.loads(request.data)
        self.assertEqual(body["chatId"], "123")
        self.assertEqual(body["name"], "Паша · @pasha")
        expected = hmac.new(b"secret", b"panasms-telegram-link-v1\n" + request.data, hashlib.sha256).hexdigest()
        self.assertEqual(request.get_header("X-panasms-telegram-signature"), expected)
        self.assertNotIn(b"secret", request.data)

if __name__ == "__main__": main()
