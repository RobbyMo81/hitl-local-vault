import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import hitl_vault


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = hitl_vault.VaultPaths(
            directory=self.root / ".local-vault",
            vault_file=self.root / ".local-vault" / "vault.json",
            lock_file=self.root / ".local-vault" / ".vault.lock",
        )
        hitl_vault.ensure_private_directory(self.paths.directory)
        self.passphrase = "correct horse battery staple"

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip_encrypts_metadata_and_value(self):
        payload = hitl_vault.empty_payload()
        payload["entries"]["vps"] = {"value": "secret-passphrase", "note": "prod", "updated_at": 1}
        document = hitl_vault.build_document(payload, self.passphrase)
        hitl_vault.write_document_atomic(self.paths, document)

        raw = self.paths.vault_file.read_text(encoding="utf-8")
        self.assertNotIn("vps", raw)
        self.assertNotIn("secret-passphrase", raw)
        self.assertNotIn("prod", raw)

        loaded = hitl_vault.decrypt_payload(json.loads(raw), self.passphrase)
        self.assertEqual(loaded["entries"]["vps"]["value"], "secret-passphrase")

    def test_wrong_passphrase_fails(self):
        document = hitl_vault.build_document(hitl_vault.empty_payload(), self.passphrase)
        with self.assertRaises(hitl_vault.VaultError):
            hitl_vault.decrypt_payload(document, "wrong passphrase")

    def test_private_permissions_created(self):
        document = hitl_vault.build_document(hitl_vault.empty_payload(), self.passphrase)
        hitl_vault.write_document_atomic(self.paths, document)
        dir_mode = stat.S_IMODE(self.paths.directory.stat().st_mode)
        file_mode = stat.S_IMODE(self.paths.vault_file.stat().st_mode)
        self.assertEqual(dir_mode, 0o700)
        self.assertEqual(file_mode, 0o600)

    def test_rejects_world_readable_directory(self):
        os.chmod(self.paths.directory, 0o755)
        with self.assertRaises(hitl_vault.VaultError):
            hitl_vault.ensure_private_directory(self.paths.directory)

    def test_atomic_write_replaces_valid_document(self):
        first = hitl_vault.build_document(hitl_vault.empty_payload(), self.passphrase)
        hitl_vault.write_document_atomic(self.paths, first)

        payload = hitl_vault.empty_payload()
        payload["entries"]["api"] = {"value": "token", "note": "", "updated_at": 1}
        second = hitl_vault.build_document(payload, self.passphrase)
        hitl_vault.write_document_atomic(self.paths, second)

        document = json.loads(self.paths.vault_file.read_text(encoding="utf-8"))
        loaded = hitl_vault.decrypt_payload(document, self.passphrase)
        self.assertEqual(loaded["entries"]["api"]["value"], "token")
        self.assertFalse(list(self.paths.directory.glob(".vault.*.tmp")))

    def test_run_injects_only_requested_child_environment(self):
        payload = hitl_vault.empty_payload()
        payload["entries"]["api-token"] = {"value": "token-123", "note": "", "updated_at": 1}
        document = hitl_vault.build_document(payload, self.passphrase)
        hitl_vault.write_document_atomic(self.paths, document)

        args = type("Args", (), {})()
        args.vault = str(self.paths.vault_file)
        args.secret = ["api-token:API_TOKEN"]
        args.command = [
            sys.executable,
            "-c",
            "import os, sys; sys.exit(0 if os.environ.get('API_TOKEN') == 'token-123' else 3)",
        ]

        original_prompt = hitl_vault.prompt_passphrase
        try:
            hitl_vault.prompt_passphrase = lambda: self.passphrase
            rc = hitl_vault.cmd_run(args)
        finally:
            hitl_vault.prompt_passphrase = original_prompt
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
