# Contributing

Contributions should preserve the main security boundary: agents do not receive the vault master passphrase.

Before opening a pull request:

```bash
python3 -m py_compile hitl_vault.py test_hitl_vault.py
python3 -m unittest -v
```

Guidelines:

- Keep the CLI small and auditable.
- Do not add non-interactive master-passphrase input without a clear threat model.
- Do not log secrets, passphrases, decrypted payloads, or command environments.
- Prefer standard-library behavior and well-maintained cryptography primitives.
- Add tests for storage format, permissions, and leak-prone workflows.
