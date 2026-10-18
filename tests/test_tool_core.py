import json
import os
import tempfile
import unittest
from pathlib import Path

from mbl.core import audit_model_directory, audit_pid, runtime_doctor, validate_evidence, SCHEMA_VERSION
from mbl.inference import run_model, run_prompts
from mbl.sandbox import build_bwrap_command, verify_child_boundary


class CoreToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make_model(self):
        model = self.root / "model"
        model.mkdir()
        (model / "config.json").write_text(json.dumps({"model_type":"fixture","architectures":["FixtureLM"],"auto_map":{"AutoModel":"modeling_fixture.FixtureModel"}}))
        (model / "tokenizer_config.json").write_text(json.dumps({"tokenizer_class":"FixtureTokenizer"}))
        (model / "model.safetensors").write_bytes(b"synthetic-fake-file-not-real-weights")
        (model / "pytorch_model.bin").write_bytes(b"synthetic-pickle-placeholder")
        (model / "modeling_fixture.py").write_text("# synthetic source fixture; never executed\n")
        return model

    def test_audit_hashes_files_and_flags_legacy_weights_and_custom_code(self):
        model = self.make_model()
        report = audit_model_directory(model)
        self.assertEqual(report["assessment_type"], "static_model_artifact_audit")
        self.assertEqual(report["security_assessment"]["status"], "NOT_ESTABLISHED")
        ids = {x["id"] for x in report["findings"]}
        self.assertIn("MBL-MODEL-PICKLE-001", ids)
        self.assertIn("MBL-MODEL-AUTOMAP-001", ids)
        self.assertIn("MBL-MODEL-CODE-001", ids)
        self.assertTrue(next(x for x in report["files"] if x["path"] == "model.safetensors").get("sha256"))

    def test_audit_flags_symlink_directory_escape(self):
        model = self.root / "model"
        model.mkdir()
        external = self.root / "outside"
        external.mkdir()
        (external / "hidden.safetensors").write_text("x")
        try:
            (model / "linkdir").symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        report = audit_model_directory(model)
        finding = [x for x in report["findings"] if x["id"] == "MBL-MODEL-SYMLINK-001"]
        self.assertTrue(finding)
        self.assertEqual(finding[0]["path"], "linkdir")

    def test_audit_flags_world_writable(self):
        model = self.root / "model"
        model.mkdir()
        file = model / "config.json"
        file.write_text('{"model_type":"fixture"}')
        file.chmod(0o666)
        report = audit_model_directory(model)
        self.assertIn("MBL-MODEL-PERM-001", {x["id"] for x in report["findings"]})

    def test_audit_invalid_path_is_rejected(self):
        with self.assertRaises(ValueError):
            audit_model_directory(self.root / "does-not-exist")

    def test_doctor_never_claims_sandbox(self):
        report = runtime_doctor()
        self.assertEqual(report["security_assessment"]["status"], "NOT_ESTABLISHED")
        self.assertIn("namespace_ids", report["process_controls"])

    def test_pid_snapshot_for_self(self):
        report = audit_pid(os.getpid())
        self.assertEqual(report["pid"], os.getpid())
        self.assertFalse(report["cmdline_stored"])
        self.assertIsNotNone(report["cmdline_sha256"])

    def test_evidence_schema_rejects_security_overclaim(self):
        good = {"schema_version": SCHEMA_VERSION, "evidence_class":"observed", "security_assessment":{"status":"NOT_ESTABLISHED"}}
        self.assertEqual(validate_evidence(good), [])
        bad = {**good, "security_assessment":{"status":"PROVEN_SECURE"}}
        self.assertTrue(validate_evidence(bad))

    def test_remote_model_requires_network_opt_in_and_full_sha(self):
        with self.assertRaisesRegex(ValueError, "disabled by default"):
            run_model("org/repo", "hello", allow_network=False, output_dir=self.root / "runs")
        with self.assertRaisesRegex(ValueError, "full immutable commit SHA"):
            run_model("org/repo", "hello", allow_network=True, revision="main", output_dir=self.root / "runs")

    def test_report_does_not_store_raw_prompt(self):
        model = self.make_model()
        report = run_model(str(model), "secret test prompt not for storage", output_dir=self.root / "runs", timeout_seconds=30, sandbox="off")
        file = Path(report["report_path"])
        serialized = file.read_text()
        self.assertNotIn("secret test prompt not for storage", serialized)
        self.assertEqual(report["prompt_stored"], False)
        self.assertTrue(report.get("prompt_hashes"))
        # This environment intentionally lacks Transformers; failing gracefully is expected.
        self.assertIn(report["status"], {"NOT_RUN", "PASS_SMOKE_ONLY"})

    def test_bwrap_command_does_not_bind_host_home_and_requires_network_namespace(self):
        model = self.make_model()
        source = Path(__file__).resolve().parents[1] / "src"
        import sys
        command = build_bwrap_command([sys.executable, "-m", "mbl.cli", "_infer-worker", "--model", str(model), "--batch-json"],
                                      model, source, "/usr/bin/bwrap")
        self.assertIn("--unshare-net", command)
        self.assertTrue(any("PR_SET_NO_NEW_PRIVS" in arg for arg in command))
        self.assertIn("--clearenv", command)
        self.assertIn("/model", command)
        self.assertIn(str(model.resolve()), command)
        self.assertNotIn("/home", command)
        self.assertNotIn("/root", command)

    def test_namespace_verifier_reports_partial_evidence_not_security_proof(self):
        host = {k:f"{k}:[1]" for k in ("user","mnt","net","ipc","uts","pid")}
        child = {k:{"status":"OBSERVED","id":f"{k}:[2]"} for k in host}
        result = verify_child_boundary(child, host, "1")
        self.assertEqual(result["status"], "PARTIAL_CONTROLS_OBSERVED")
        self.assertIn("not proof", result["claim_boundary"])

    def test_required_sandbox_fails_closed_before_model_load(self):
        from unittest.mock import patch
        model = self.make_model()
        with patch("mbl.inference.probe_bwrap", return_value={"status":"NOT_SUPPORTED","available":False,"reason":"test fixture"}):
            report = run_model(str(model), "do not store this prompt", output_dir=self.root / "runs", timeout_seconds=30, sandbox="required")
        self.assertEqual(report["status"], "SANDBOX_UNAVAILABLE")
        self.assertFalse(report["model_tested"])
        self.assertEqual(report["security_assessment"]["status"], "NOT_ESTABLISHED")

    def test_resolve_model_requires_network_opt_in(self):
        import subprocess, sys
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run([sys.executable, "-m", "mbl", "resolve-model", "org/model"],
                                text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn("network access is disabled by default", result.stderr)

    def test_benchmark_cases_reject_bad_check_type(self):
        with self.assertRaisesRegex(ValueError, "check type"):
            run_prompts("org/repo", [{"id":"x","prompt":"hi","checks":[{"type":"python","value":"x"}]}],
                        allow_network=True, revision="a"*40, output_dir=self.root / "runs", sandbox="off")


if __name__ == "__main__":
    unittest.main()
