import json
import socket
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'management'))
import web_access as web


class WebAccessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for name, leaf in [('CONFIG', 'web.env'), ('STATE', 'state.json'), ('LOCK', 'lock')]:
            mock = patch.object(web, name, Path(self.tmp.name) / leaf)
            mock.start()
            self.addCleanup(mock.stop)
        def write(path, value, mode=0o600):
            path.write_text(value)
        mock = patch.object(web, 'atomic', side_effect=write)
        mock.start()
        self.addCleanup(mock.stop)

    def test_defaults_and_validation(self):
        self.assertEqual(web.current_port(), 80)
        for value in [0, -1, 65536, True, '8080', 22, 6000]:
            with self.subTest(value=value), self.assertRaises(web.Rejected):
                web.port_number(value)
        web.write_port(8080)
        self.assertEqual(web.current_port(), 8080)
        with patch.object(web, 'healthy', return_value=True):
            self.assertEqual(web.configure(None), 8080)

    def test_listening_socket_is_rejected(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            with self.assertRaises(web.Rejected):
                web.available(listener.getsockname()[1])

    def test_busy_port_changes_nothing(self):
        with patch.object(web, 'available', side_effect=web.Rejected('occupied')):
            with self.assertRaises(web.Rejected):
                web.execute('system.web-port', {'port': 8080})
        self.assertFalse(web.STATE.exists())
        self.assertEqual(web.current_port(), 80)

    def test_schedule_then_apply(self):
        with patch.object(web, 'available'), patch.object(web, 'command') as command:
            web.execute('system.web-port', {'port': 8080})
            self.assertTrue(web.query()['pending'])
            self.assertEqual(web.current_port(), 80)
            with self.assertRaises(web.Rejected):
                web.execute('system.web-port', {'port': 8081})
            with patch.object(web, 'healthy', return_value=True):
                web.apply()
            self.assertEqual(web.current_port(), 8080)
            self.assertFalse(web.query()['pending'])
            self.assertIn(['systemctl', 'restart', 'panasms-core.service'], [call.args[0] for call in command.call_args_list])

    def test_failed_start_restores_previous_port(self):
        web.STATE.write_text(json.dumps({'phase': 'scheduled', 'previous': 80, 'port': 8080}))
        with patch.object(web, 'available'), patch.object(web, 'command'), patch.object(web, 'healthy', return_value=False), patch.object(web.time, 'sleep'):
            with self.assertRaises(web.Rejected):
                web.apply()
        self.assertEqual(web.current_port(), 80)
        self.assertFalse(web.query()['pending'])
        self.assertIn('restored', web.query()['error'])

    def test_failed_schedule_and_interrupted_application(self):
        with patch.object(web, 'available'), patch.object(web, 'command', side_effect=web.Rejected('failed')):
            with self.assertRaises(web.Rejected):
                web.execute('system.web-port', {'port': 8080})
        self.assertFalse(web.STATE.exists())
        web.write_port(8080)
        web.STATE.write_text(json.dumps({'phase': 'applying', 'previous': 80, 'port': 8080}))
        web.recover()
        self.assertEqual(web.current_port(), 80)
        self.assertIn('rolled back', web.query()['error'])
