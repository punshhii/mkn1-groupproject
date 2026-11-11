"""Тесты генерации начального accounts.json при сборке ПО МЭ."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from fw_authd import accounts
from fw_authd import mkaccounts as mkaccounts_cli


class MkaccountsTest(unittest.TestCase):
    def test_creates_builtin_admin_with_hash(self):
        password = "Build_Admin_2026"
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "accounts.json")
            generated = accounts.mkaccounts(password, path=path)

            with open(path, "r", encoding="utf-8") as f:
                stored = json.load(f)
            self.assertEqual(stored, generated)
            self.assertEqual(set(stored), {"admin"})

            admin = stored["admin"]
            self.assertEqual(
                set(admin),
                {"role", "password_hash", "salt", "iterations", "algo", "builtin"},
            )
            self.assertEqual(admin["role"], "rw")
            self.assertEqual(admin["algo"], "pbkdf2_sha256")
            self.assertEqual(admin["iterations"], 200000)
            self.assertTrue(admin["builtin"])
            self.assertEqual(len(admin["password_hash"]), 64)
            self.assertEqual(len(admin["salt"]), 32)
            self.assertTrue(
                accounts.verify_password(
                    password,
                    admin["password_hash"],
                    admin["salt"],
                    admin["iterations"],
                )
            )
            with open(path, "r", encoding="utf-8") as f:
                self.assertNotIn(password, f.read())

            second_path = os.path.join(directory, "accounts-second.json")
            second_admin = accounts.mkaccounts(password, path=second_path)["admin"]
            self.assertNotEqual(admin["salt"], second_admin["salt"])
            self.assertNotEqual(admin["password_hash"], second_admin["password_hash"])

    def test_refuses_invalid_password_and_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "accounts.json")
            with self.assertRaises(ValueError):
                accounts.mkaccounts("short", path=path)
            self.assertFalse(os.path.exists(path))

            accounts.mkaccounts("First_password", path=path)
            with open(path, "r", encoding="utf-8") as f:
                original = f.read()
            with self.assertRaises(FileExistsError):
                accounts.mkaccounts("Second_password", path=path)
            with open(path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), original)

    def test_custom_iterations_are_used_for_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "accounts.json")
            generated = accounts.mkaccounts(
                "Custom_iterations",
                path=path,
                iterations=250000,
            )
            admin = generated["admin"]
            self.assertEqual(admin["iterations"], 250000)
            self.assertTrue(
                accounts.verify_password(
                    "Custom_iterations",
                    admin["password_hash"],
                    admin["salt"],
                    admin["iterations"],
                )
            )

    def test_cli_prompts_twice_without_exposing_password(self):
        password = "Interactive_password"
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "accounts.json")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                mkaccounts_cli.getpass,
                "getpass",
                side_effect=[password, password],
            ) as prompt, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = mkaccounts_cli.main(["--output", path])

            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(prompt.call_count, 2)
            self.assertNotIn(password, stdout.getvalue())
            self.assertNotIn(password, stderr.getvalue())
            self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
