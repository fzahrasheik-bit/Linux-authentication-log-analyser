import tempfile
import unittest
from pathlib import Path
from analyser import analyse_log, extract_failed_attempt

class AnalyserTests(unittest.TestCase):
    def test_extract_failed_password(self):
        line = "sshd: Failed password for root from 203.0.113.8 port 22 ssh2"
        self.assertEqual(extract_failed_attempt(line), ("root", "203.0.113.8"))

    def test_threshold_flags_repeated_ip(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "auth.log"
            log.write_text(
                "sshd: Failed password for root from 203.0.113.8 port 22 ssh2\n" * 5,
                encoding="utf-8"
            )
            result = analyse_log(log, threshold=5)
            self.assertEqual(len(result["flagged_ips"]), 1)
            self.assertEqual(result["flagged_ips"][0]["failed_attempts"], 5)

if __name__ == "__main__":
    unittest.main()
