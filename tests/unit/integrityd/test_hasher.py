import json
import os
import tempfile
import unittest

from fw_integrityd import hasher

KEY = b"k" * 32


class HasherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.baseline = os.path.join(self.dir, "baseline.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_sha256_file(self):
        path = os.path.join(self.dir, "f")
        with open(path, "wb") as f:
            f.write(b"abc")
        self.assertEqual(hasher.sha256_file(path),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_load_key(self):
        path = os.path.join(self.dir, "hmac.key")
        with open(path, "wb") as f:
            f.write(KEY)
        self.assertEqual(hasher.load_key(path), KEY)

    def test_roundtrip(self):
        files = {"/etc/fw/config.json": "a" * 64, "/usr/lib/fw/bin/fw-filter": "b" * 64}
        hasher.save_baseline(self.baseline, files, KEY)
        self.assertEqual(hasher.load_baseline(self.baseline, KEY), files)

    @unittest.skipIf(os.name == "nt", "права POSIX")
    def test_mode_0600(self):
        hasher.save_baseline(self.baseline, {}, KEY)
        self.assertEqual(os.stat(self.baseline).st_mode & 0o777, 0o600)

    def _tamper(self, fn):
        hasher.save_baseline(self.baseline, {"/etc/fw/config.json": "a" * 64}, KEY)
        with open(self.baseline, encoding="utf-8") as f:
            data = json.load(f)
        fn(data)
        with open(self.baseline, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_changed_hash(self):
        self._tamper(lambda d: d["files"].update({"/etc/fw/config.json": "c" * 64}))
        with self.assertRaises(hasher.BaselineError):
            hasher.load_baseline(self.baseline, KEY)

    def test_added_file(self):
        self._tamper(lambda d: d["files"].update({"/etc/fw/x.json": "c" * 64}))
        with self.assertRaises(hasher.BaselineError):
            hasher.load_baseline(self.baseline, KEY)

    def test_changed_hmac(self):
        self._tamper(lambda d: d.update({"hmac": "0" * 64}))
        with self.assertRaises(hasher.BaselineError):
            hasher.load_baseline(self.baseline, KEY)

    def test_wrong_key(self):
        hasher.save_baseline(self.baseline, {}, KEY)
        with self.assertRaises(hasher.BaselineError):
            hasher.load_baseline(self.baseline, b"x" * 32)

    def test_corrupted(self):
        for content in ("", "[]", "{\"files\": {}}", "not json", "{\"files\": [], \"hmac\": \"ж\"}"):
            with open(self.baseline, "w", encoding="utf-8") as f:
                f.write(content)
            with self.assertRaises(hasher.BaselineError, msg=content):
                hasher.load_baseline(self.baseline, KEY)

    def test_missing(self):
        with self.assertRaises(hasher.BaselineError):
            hasher.load_baseline(self.baseline, KEY)


if __name__ == "__main__":
    unittest.main()
