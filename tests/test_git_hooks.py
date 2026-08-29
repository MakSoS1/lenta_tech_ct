import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class GitHookTests(unittest.TestCase):
    def test_pre_commit_scans_staged_content_and_blocks_private_paths(self):
        text = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
        self.assertIn("--staged", text)
        self.assertIn(".ctf-work/", text)
        self.assertIn(".runtime/", text)

    def test_hook_installer_sets_repository_local_hooks_path(self):
        text = (ROOT / "scripts" / "install_hooks.sh").read_text(encoding="utf-8")
        self.assertIn("git config --local core.hooksPath .githooks", text)

    def test_bootstrap_installs_repository_hooks(self):
        text = (ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn('"$ROOT/scripts/install_hooks.sh"', text)


if __name__ == "__main__":
    unittest.main()
