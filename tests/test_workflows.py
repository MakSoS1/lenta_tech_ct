import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class WorkflowTests(unittest.TestCase):
    def test_workflows_are_least_privilege_and_do_not_upload_artifacts(self):
        for name in ("preflight.yml", "build-ctf-env.yml", "upstream-smoke.yml"):
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            self.assertIn("permissions:\n  contents: read", text)
            self.assertNotIn("upload-artifact", text)
            self.assertNotIn("GITHUB_TOKEN:", text)

    def test_preflight_runs_repository_gate(self):
        text = (WORKFLOWS / "preflight.yml").read_text(encoding="utf-8")
        self.assertIn("./scripts/preflight.sh", text)

    def test_build_workflow_has_fast_default_and_manual_veria_build(self):
        text = (WORKFLOWS / "build-ctf-env.yml").read_text(encoding="utf-8")
        self.assertIn("./scripts/build_images.sh fast", text)
        self.assertIn("build_veria", text)
        self.assertIn("./scripts/build_images.sh veria", text)

    def test_upstream_smoke_clones_all_but_never_runs_reference_installers(self):
        text = (WORKFLOWS / "upstream-smoke.yml").read_text(encoding="utf-8")
        self.assertIn("./scripts/bootstrap.sh --all", text)
        self.assertIn("nus-workstation", text)
        self.assertIn("nyu-dcipher", text)
        self.assertNotIn("setup_dcipher.sh\n", text)
        self.assertNotIn("013_install-skills.sh\n", text)


if __name__ == "__main__":
    unittest.main()
