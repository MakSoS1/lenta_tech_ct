import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ShellcheckRegressionTests(unittest.TestCase):
    def test_bootstrap_consumes_role_column_instead_of_leaving_it_unused(self):
        text = (ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn('[[ "$role" == "runtime" || "$role" == "reference" ]]', text)

    def test_skill_cleanup_uses_nonempty_parameter_guards(self):
        text = (ROOT / "scripts" / "link_skills.sh").read_text(encoding="utf-8")
        self.assertIn('rm -rf "${dest:?}/${skill:?}"', text)

    def test_tmpfs_specs_are_quoted_array_elements(self):
        text = (ROOT / "scripts" / "run_sandbox.sh").read_text(encoding="utf-8")
        self.assertIn('--tmpfs "/tmp:rw,nosuid,nodev,size=1g"', text)
        self.assertIn('--tmpfs "/home/ctf:rw,nosuid,nodev,size=256m"', text)


if __name__ == "__main__":
    unittest.main()
