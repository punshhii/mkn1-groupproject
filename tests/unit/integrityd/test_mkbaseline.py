import os
import tempfile
import unittest

from fw_integrityd import hasher, mkbaseline

CONFIG = {
    "baseline_path": "/var/lib/fw/baseline.json",
    "backup_dir": "/var/lib/fw/backup/",
    "hmac_key_path": "/etc/fw/hmac.key",
    "check_period_sec": 60,
    "files": ["/etc/fw/config.json", "/usr/lib/fw/bin/fw-filter"],
}


class MkbaselineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        for path, data in (("/etc/fw/config.json", b"{}"), ("/usr/lib/fw/bin/fw-filter", b"\x7fELF")):
            src = mkbaseline.staged(self.root, path)
            os.makedirs(os.path.dirname(src), exist_ok=True)
            with open(src, "wb") as f:
                f.write(data)

    def tearDown(self):
        self.tmp.cleanup()

    def test_build(self):
        mkbaseline.build(self.root, CONFIG)
        key = hasher.load_key(mkbaseline.staged(self.root, CONFIG["hmac_key_path"]))
        self.assertEqual(len(key), mkbaseline.KEY_BYTES)
        baseline = hasher.load_baseline(mkbaseline.staged(self.root, CONFIG["baseline_path"]), key)
        self.assertEqual(set(baseline), set(CONFIG["files"]))
        backup_dir = mkbaseline.staged(self.root, CONFIG["backup_dir"])
        for path in CONFIG["files"]:
            self.assertEqual(hasher.sha256_file(mkbaseline.staged(self.root, path)), baseline[path])
            self.assertEqual(hasher.sha256_file(mkbaseline.staged(backup_dir, path)), baseline[path])

    def test_rebuild_keeps_key(self):
        mkbaseline.build(self.root, CONFIG)
        key_path = mkbaseline.staged(self.root, CONFIG["hmac_key_path"])
        key = hasher.load_key(key_path)
        mkbaseline.build(self.root, CONFIG)
        self.assertEqual(hasher.load_key(key_path), key)

    @unittest.skipIf(os.name == "nt", "права POSIX")
    def test_modes(self):
        mkbaseline.build(self.root, CONFIG)
        mode = lambda p: os.stat(mkbaseline.staged(self.root, p)).st_mode & 0o777
        self.assertEqual(mode(CONFIG["hmac_key_path"]), 0o400)
        self.assertEqual(mode(CONFIG["baseline_path"]), 0o600)
        self.assertEqual(mode(CONFIG["backup_dir"]), 0o700)

    def test_empty_files(self):
        with self.assertRaises(ValueError):
            mkbaseline.build(self.root, dict(CONFIG, files=[]))

    def test_missing_file(self):
        with self.assertRaises(OSError):
            mkbaseline.build(self.root, dict(CONFIG, files=["/etc/fw/nonexistent.json"]))


if __name__ == "__main__":
    unittest.main()
