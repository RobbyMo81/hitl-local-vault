# Security Policy

## Supported Versions

This project is an early MVP. Security fixes target the latest commit on the default branch until release tags exist.

## Reporting a Vulnerability

Do not open a public issue with live secrets, private keys, vault files, or exploit details that expose an active system.

Report suspected security problems privately to the repository owner through GitHub. Include:

- affected commit or version
- operating system and Python version
- clear reproduction steps using test secrets only
- expected behavior and actual behavior

## Scope

This tool protects secrets at rest in a local encrypted vault. It does not protect against malware, a compromised OS user account, malicious subprocesses, shell history leaks, terminal capture, or commands that intentionally print their environment.
