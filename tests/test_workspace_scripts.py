import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_script(name, *args, work_root):
    env = os.environ.copy()
    env["CTF_WORK_ROOT"] = str(work_root)
    return subprocess.run(
        ["bash", str(ROOT / "scripts" / name), *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class WorkspaceScriptTests(unittest.TestCase):
    def test_new_task_creates_private_workspace_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_script("new_task.sh", "web-01", work_root=pathlib.Path(tmp))
            self.assertEqual(result.returncode, 0, result.stderr)
            task = pathlib.Path(tmp) / "web-01"
            self.assertTrue((task / "brief.md").is_file())
            self.assertTrue((task / "notes.md").is_file())
            self.assertTrue((task / "findings.jsonl").is_file())
            self.assertTrue((task / "targets.txt").is_file())
            for dirname in ("files", "scratch", "output"):
                self.assertTrue((task / dirname).is_dir())

    def test_new_task_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_script("new_task.sh", "../escape", work_root=pathlib.Path(tmp))
            self.assertNotEqual(result.returncode, 0)

    def test_register_target_stores_only_normalized_hostname(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_root = pathlib.Path(tmp)
            created = run_script("new_task.sh", "web-02", work_root=work_root)
            self.assertEqual(created.returncode, 0, created.stderr)
            result = run_script(
                "register_target.sh",
                "web-02",
                "https://Challenge.Example:8443/login",
                work_root=work_root,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = (work_root / "web-02" / "targets.txt").read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines, ["challenge.example"])

    def test_register_target_rejects_embedded_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            work_root = pathlib.Path(tmp)
            self.assertEqual(run_script("new_task.sh", "web-03", work_root=work_root).returncode, 0)
            result = run_script(
                "register_target.sh",
                "web-03",
                "https://user:pass@challenge.example/",
                work_root=work_root,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
