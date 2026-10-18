import tempfile
import unittest
from pathlib import Path

from mbl.gguf_inference import run_gguf


class GGUFBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_required_sandbox_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "only --sandbox off"):
            run_gguf(
                "/not/needed.gguf",
                "test prompt",
                sandbox="required",
                output_dir=self.root / "runs",
            )

    def test_non_gguf_file_is_rejected(self):
        model = self.root / "model.bin"
        model.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "local .gguf"):
            run_gguf(
                str(model),
                "test prompt",
                sandbox="off",
                server="/not/needed/server",
                output_dir=self.root / "runs",
            )

    def test_missing_model_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "local .gguf"):
            run_gguf(
                str(self.root / "missing.gguf"),
                "test prompt",
                sandbox="off",
                server="/not/needed/server",
                output_dir=self.root / "runs",
            )

    def test_empty_prompt_is_rejected(self):
        model = self.root / "fixture.gguf"
        model.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "non-empty"):
            run_gguf(
                str(model),
                "   ",
                sandbox="off",
                server="/not/needed/server",
                output_dir=self.root / "runs",
            )

    def test_token_limit_is_bounded(self):
        model = self.root / "fixture.gguf"
        model.write_bytes(b"fixture")
        with self.assertRaisesRegex(ValueError, "1..128"):
            run_gguf(
                str(model),
                "test",
                max_new_tokens=129,
                sandbox="off",
                server="/not/needed/server",
                output_dir=self.root / "runs",
            )


if __name__ == "__main__":
    unittest.main()
