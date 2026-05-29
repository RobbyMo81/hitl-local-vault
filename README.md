# HITL Local Vault

An open-source local encrypted vault for human-in-the-loop agent workflows. It replaces plaintext files like `note.txt` with an encrypted single-file vault.

## Threat Model

This protects secrets at rest from casual disclosure, accidental sync, and copied folders. It does not protect secrets after the human unlocks the vault, and it does not defeat malware or an attacker already running as the same OS user.

Agents should not receive the vault master passphrase. The intended pattern is:

1. The agent asks for a secret-backed action.
2. The HITL unlocks the vault in an interactive terminal.
3. The vault runs the requested command with selected secrets injected into that subprocess only.

## Install

From this repository:

```bash
python3 -m pip install .
hitl-vault init
```

For direct script use:

```bash
chmod +x hitl_vault.py
./hitl_vault.py init
```

## Setup

```bash
./hitl_vault.py init
./hitl_vault.py add vps-ssh-passphrase
./hitl_vault.py list
```

The default vault file is:

```text
.local-vault/vault.json
```

Only encrypted data is written there. Secret names and notes are encrypted inside the payload too.

## Agent-Friendly Run Mode

Use `run` when an agent needs a command to use a secret without pasting that secret into the chat or logs.

```bash
./hitl_vault.py run --secret vps-ssh-passphrase:SSH_KEY_PASSPHRASE -- ./some-tool
```

The selected secret is available only to the child process as `SSH_KEY_PASSPHRASE`. The command can still leak the secret if it prints its environment or logs sensitive values.

## Direct Retrieval

`get` prints plaintext to stdout. Use it only when a human explicitly needs to read a value.

```bash
./hitl_vault.py get vps-ssh-passphrase
```

## Backup

Back up the encrypted vault file, then test that the backup opens before deleting old plaintext notes.

```bash
./hitl_vault.py export-encrypted-copy /path/to/backup/vault.json
```

Keep the master passphrase and recovery instructions somewhere separate. If the passphrase is lost, the vault cannot be recovered.

## Cleanup From Plaintext Notes

After moving values from `note.txt`, rotate the highest-value secrets first: VPS credentials, SSH key passphrases, root/sudo passwords, cloud credentials, and email recovery codes. Plaintext may remain in editor backups, shell history, snapshots, cloud sync history, or SSD remnants.

## Security Notes

- The vault uses `cryptography.Fernet` with a key derived by `PBKDF2HMAC-SHA256`.
- Each vault gets a random 32-byte salt.
- The KDF iteration count is `1,200,000`.
- Writes use a lock file plus atomic replace.
- Directory permissions must be `700`; vault files must be `600`.
- The tool refuses master-passphrase input without an interactive TTY.

## Development

```bash
python3 -m py_compile hitl_vault.py test_hitl_vault.py
python3 -m unittest -v
```

## License

MIT
