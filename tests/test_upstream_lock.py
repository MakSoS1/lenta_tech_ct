import json
import pathlib
import unittest

from scripts.validate_upstreams import EXPECTED_UPSTREAMS, validate_lock_data


class UpstreamLockTests(unittest.TestCase):
    def test_lock_contains_exact_four_allowlisted_upstreams(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        data = json.loads((root / "config" / "upstreams.lock.json").read_text(encoding="utf-8"))
        validated = validate_lock_data(data)
        self.assertEqual(set(validated), set(EXPECTED_UPSTREAMS))
        for name, entry in validated.items():
            self.assertEqual(entry["url"], EXPECTED_UPSTREAMS[name]["url"])
            self.assertRegex(entry["sha"], r"^[0-9a-f]{40}$")

    def test_rejects_floating_or_unknown_repository(self):
        bad = {
            "version": 1,
            "upstreams": [
                {
                    "name": "ctf-skills",
                    "url": "https://github.com/attacker/example.git",
                    "sha": "main",
                    "role": "runtime",
                    "expected_paths": ["README.md"],
                }
            ],
        }
        with self.assertRaises(ValueError):
            validate_lock_data(bad)


if __name__ == "__main__":
    unittest.main()
