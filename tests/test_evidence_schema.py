"""Fast, dependency-free tests for evidence records and claim discipline."""
import json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class EvidenceSchemaTests(unittest.TestCase):
    def test_protocol_fixture_is_parseable(self):
        p=ROOT/'datasets/protocol_run.json'
        self.assertTrue(p.exists())
        data=json.loads(p.read_text())
        self.assertIsInstance(data, dict)
    def test_build_status_never_claims_unrun_model(self):
        p=ROOT/'BUILD_STATUS.json'
        data=json.loads(p.read_text())
        self.assertIn(data['real_model_inference']['status'], {'NOT_RUN','INCONCLUSIVE','PASS_SMOKE_ONLY'})
        if data['real_model_inference']['status'] != 'PASS_SMOKE_ONLY':
            self.assertFalse(data['real_model_inference'].get('model_tested', False))
    def test_zenodo_reference_is_present(self):
        readme=(ROOT/'README.md').read_text()
        self.assertIn('10.5281/zenodo.23442798', readme)
    def test_no_test_claims_security_proof(self):
        status=json.loads((ROOT/'BUILD_STATUS.json').read_text())
        self.assertNotEqual(status['weight_confidentiality']['status'], 'PASS')
        self.assertNotEqual(status['isolation_enforcement']['status'], 'PASS')
if __name__=='__main__': unittest.main()
