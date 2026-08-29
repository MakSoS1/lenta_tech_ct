import pathlib
import subprocess
import tempfile
import unittest

from scripts.secret_scan import scan_staged, scan_text


class SecretScanTests(unittest.TestCase):
    def test_benign_text_is_clean(self):
        self.assertEqual(scan_text("status: solved\nno secret material here\n", "note.md"), [])

    def test_detects_ctf_flag_without_embedding_literal_in_repository(self):
        leaked = "LENTA" + "{" + "unit_test_secret_4821" + "}"
        findings = scan_text("result=" + leaked, "output.txt")
        self.assertTrue(any(f.kind == "ctf_flag" for f in findings))

    def test_detects_unknown_braced_ctf_prefix(self):
        leaked = "ODDCUP26" + "{" + "custom_format_value_7319" + "}"
        findings = scan_text("candidate=" + leaked, "answer.txt")
        self.assertTrue(any(f.kind == "ctf_flag" for f in findings))

    def test_detects_private_key_header(self):
        header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
        findings = scan_text(header, "key.txt")
        self.assertTrue(any(f.kind == "private_key" for f in findings))

    def test_detects_high_risk_token_assignment(self):
        token = "gh" + "p_" + "A" * 40
        findings = scan_text("GITHUB_TOKEN=" + token, "env.txt")
        self.assertTrue(any(f.kind == "token" for f in findings))

    def test_staged_scan_reads_index_even_if_worktree_was_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            path = repo / "answer.txt"
            leaked = "CUSTOMCTF" + "{" + "staged_only_value_5566" + "}"
            path.write_text(leaked + "\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "answer.txt"], check=True)
            path.write_text("sanitized working tree\n", encoding="utf-8")

            findings = scan_staged(repo)
            self.assertTrue(any(f.kind == "ctf_flag" and f.source == "answer.txt" for f in findings))


if __name__ == "__main__":
    unittest.main()
