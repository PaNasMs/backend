import ast
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def go_route_inventory():
    """Return the Go dispatcher's exported routing inventory.

    Replaces the former AST scan of main.py: the routing table now lives in Go
    (internal/management/routing.go) and is emitted by the helper's `routes`
    subcommand, so coverage is asserted against the single source of truth
    rather than re-derived from Python control flow. Skips cleanly when the Go
    toolchain is unavailable in the test environment.
    """
    go = shutil.which('go')
    if not go:
        raise unittest.SkipTest('go toolchain not available')
    env = dict(os.environ, GOTOOLCHAIN='local', GOFLAGS='-buildvcs=false')
    out = subprocess.check_output(
        [go, 'run', './cmd/panasms-system-helper', 'routes'], cwd=ROOT, env=env)
    return json.loads(out)
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
        inventory = go_route_inventory()
        declared = DOCUMENT['components']['schemas']['ManagementViews']['properties']
        # Every routed query view must have an OpenAPI contract, and every
        # declared view (except the jobs journal, served directly by the Go
        # manager) must be routed. This keeps the Go routing table, the Python
        # dispatcher and the API schema in lockstep.
        self.assertEqual(set(inventory['views']), set(declared) - {'job', 'jobs'})

    def test_legacy_actions_are_all_in_route_inventory(self):
        actions = set()
        for source in (ROOT / 'management').glob('*.py'):
            for node in ast.walk(ast.parse(source.read_text())):
                if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == 'ACTIONS'
                    for target in node.targets
                ):
                    actions.update(ast.literal_eval(node.value))
        self.assertEqual(set(go_route_inventory()['actions']), actions)

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
