import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ToolboxFileTests(unittest.TestCase):
    def test_fast_dockerfile_has_core_ctf_tools_without_fetch_execute_installers(self):
        dockerfile = (ROOT / "docker" / "Dockerfile.fast").read_text(encoding="utf-8")
        build_script = (ROOT / "scripts" / "build_images.sh").read_text(encoding="utf-8")
        for needle in (
            "gdb",
            "tshark",
            "nmap",
            "binwalk",
            "sleuthkit",
            "pwntools",
            "pycryptodome",
            "z3-solver",
            "scapy",
            "volatility3",
        ):
            self.assertIn(needle, dockerfile)
        self.assertIn("pwn checksec", build_script)
        self.assertIsNone(re.search(r"(?i)(curl|wget)[^\n]*\|\s*(sh|bash)", dockerfile))

    def test_build_script_uses_pinned_veria_runtime_tree(self):
        text = (ROOT / "scripts" / "build_images.sh").read_text(encoding="utf-8")
        self.assertIn(".runtime/upstreams/ctf-agent/sandbox/Dockerfile.sandbox", text)
        self.assertIn("bootstrap.sh", text)
        self.assertNotIn("git clone", text)


if __name__ == "__main__":
    unittest.main()
