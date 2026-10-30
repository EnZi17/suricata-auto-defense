"""Run with python3 -m unittest discover -s tests -p test_lab_config.py."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest
import yaml

spec = importlib.util.spec_from_file_location(
    'configure_lab', Path(__file__).resolve().parents[1] / 'scripts/configure_lab.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
LOCAL = '/etc/suricata/rules/local.rules'


class LabConfigTests(unittest.TestCase):
    def test_preserves_other_settings_and_rules(self):
        data = {'vars': {'address-groups': {'EXTERNAL_NET': '!$HOME_NET'}},
                'rule-files': ['suricata.rules'], 'flow': {'memcap': '64mb'}}
        out = module.lab_settings(data, LOCAL)
        self.assertEqual(out['flow'], {'memcap': '64mb'})
        self.assertEqual(out['vars']['address-groups']['EXTERNAL_NET'], '!$HOME_NET')
        self.assertEqual(out['rule-files'], ['suricata.rules', LOCAL])
        self.assertEqual(out['af-packet'][0]['interface'], 'suri-host')
        self.assertEqual(out['vars']['address-groups']['HOME_NET'], '[10.203.0.0/30]')

    def test_existing_eve_output_is_enabled_and_keeps_types(self):
        out = module.lab_settings({'outputs': [{'eve-log': {
            'enabled': False, 'filetype': 'unix_stream', 'threaded': True,
            'types': [{'http': {'extended': True}}]}}]}, LOCAL)
        eve = out['outputs'][0]['eve-log']
        self.assertTrue(eve['enabled'])
        self.assertFalse(eve['threaded'])
        self.assertEqual(eve['filetype'], 'regular')
        self.assertIn('alert', eve['types'])
        self.assertIn({'http': {'extended': True}}, eve['types'])

    def test_rerun_and_yaml_roundtrip_are_stable(self):
        out = module.lab_settings({'outputs': [{'eve-log': {
            'types': [{'alert': {'payload': True}}]}}]}, LOCAL)
        first = deepcopy(out)
        module.lab_settings(out, LOCAL)
        self.assertEqual(out, first)
        self.assertEqual(yaml.safe_load(yaml.safe_dump(out)), first)

    def test_missing_outputs_get_alert_file(self):
        out = module.lab_settings({}, LOCAL)
        self.assertEqual(out['outputs'][0]['eve-log']['filename'], 'eve.json')
        self.assertEqual(out['outputs'][0]['eve-log']['types'], ['alert'])


if __name__ == '__main__':
    unittest.main()
