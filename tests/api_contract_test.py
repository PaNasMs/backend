import ast
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'management'))
import homes
import host
import job_recovery
import module_manager
import system_updates
import web_access

DOCUMENT = yaml.safe_load((ROOT / 'api/openapi.yaml').read_text())


def validate(name, value):
    schema = {'$ref': '#/components/schemas/' + name, 'components': DOCUMENT['components']}
    Draft202012Validator(schema).validate(value)


class ManagementContractTest(unittest.TestCase):
    def test_schema_definitions_and_references_are_valid(self):
        for name, schema in DOCUMENT['components']['schemas'].items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)
        def visit(value):
            if isinstance(value, dict):
                if '$ref' in value:
                    node = DOCUMENT
                    for part in value['$ref'].removeprefix('#/').split('/'):
                        node = node[part]
                for child in value.values(): visit(child)
            elif isinstance(value, list):
                for child in value: visit(child)
        visit(DOCUMENT)

    def test_core_query_dispatch_has_contracts(self):
        supported = set()
        for file in ('main.py', 'host.py', 'storage.py'):
            for node in ast.walk(ast.parse((ROOT / 'management' / file).read_text())):
                if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == 'view':
                    if isinstance(node.ops[0], (ast.Eq, ast.In)):
                        for item in ast.walk(node.comparators[0]):
                            if isinstance(item, ast.Constant) and isinstance(item.value, str): supported.add(item.value)
        declared = DOCUMENT['components']['schemas']['ManagementViews']['properties']
        self.assertEqual(supported, set(declared) - {'job', 'jobs'})

    def test_real_empty_and_recovery_queries_match_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(homes, 'base', return_value='/home'), patch.object(homes, 'affected', return_value=[]), patch.object(homes, 'JOURNAL', root / 'homes.json'):
                validate('HomeLocations', homes.query())
            with patch.object(module_manager, 'registry', return_value={}):
                validate('InstalledModules', module_manager.list_modules())
            with patch.object(web_access, 'state', return_value={}), patch.object(web_access, 'current_port', return_value=80):
                validate('WebAccess', web_access.query())
                validate('JobRecovery', job_recovery.inspect({'action': 'system.web-port'}))
            with patch.object(system_updates, 'ROOT', root), patch.object(system_updates, 'CONFIG', root / 'config.json'), patch.object(system_updates, 'installed', return_value={'panasms-prototype': '0.2.6'}):
                validate('SystemUpdates', system_updates.query())
                system_updates.save('state.json', {'phase':'recovery-required','error':'interrupted'})
                system_updates.save('backup.json', {'complete':True})
                system_updates.save('history.json', [{'phase':'failed','version':None}])
                validate('SystemUpdates', system_updates.query())
                result = job_recovery.inspect({'action':'system.update.install'})
                validate('JobRecovery', result)
                self.assertEqual(result['recoveryAction'], 'system.update.rollback')
                self.assertEqual(result['route'], '/settings/updates')

    def test_native_service_journal_and_package_results(self):
        with patch.object(host, 'json_command', side_effect=[[{'unit':'test.service','load':'loaded','active':'inactive','sub':'dead','description':'Example'}], [{'unit_file':'test.service','state':'disabled'}]]):
            validate('ServicesView', host.query('services', ''))
        with patch.object(host, 'command', return_value=json.dumps({'MESSAGE':'Example'})):
            validate('JournalView', host.query('journal', ''))
        with patch.object(host, 'command', return_value='Inst example [1.0] (2.0 Debian [arm64])'):
            validate('PackageUpdates', host.query('updates', ''))

    def test_unknown_module_recovery_does_not_inspect_unrelated_storage(self):
        with patch.object(job_recovery, 'json_command') as command:
            result = job_recovery.inspect({'action':'custom.operation'})
            command.assert_not_called()
            validate('JobRecovery', result)
            self.assertIsNone(result['recoveryAction'])
