# KeePassXC SSH Agent - Claude Code Instructions

## Project Overview

Standalone Python tool - an SSH IdentityAgent proxy for macOS that triggers KeePassXC database unlock (via TouchID) when SSH keys are needed.

## Architecture

- **Proxy pattern**: SSH Client → keepassxc-ssh-agent (Unix socket) → System ssh-agent
- **Unlock trigger**: Uses KeePassXC's browser extension protocol (NaCl-encrypted JSON over Unix socket)
- **No signing**: The proxy does NOT implement SSH key signing. KeePassXC pushes keys to the system ssh-agent on unlock, and the proxy forwards requests there.
- **SSH_AUTH_SOCK interception**: Renames the real ssh-agent socket to `.system` suffix and symlinks the original path to the proxy socket. Restores on shutdown.

### Key Files

- `keepassxc_ssh_agent/server.py` - SSH agent proxy server (threading-based, Unix socket)
- `keepassxc_ssh_agent/browser_client.py` - KeePassXC browser extension protocol client (NaCl crypto)
- `keepassxc_ssh_agent/ssh_agent_protocol.py` - SSH agent wire format (4-byte length prefix + message)
- `keepassxc_ssh_agent/config.py` - Config persistence (`~/.keepassxc/ssh-agent.json`)
- `keepassxc_ssh_agent/__main__.py` - CLI with subcommands: install, run, status, uninstall

### KeePassXC Browser Protocol Details

- Socket: `$TMPDIR/org.keepassxc.KeePassXC.BrowserServer` (macOS), `$XDG_RUNTIME_DIR/app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer` (Linux)
- Every JSON message MUST include a `clientID` field (KeePassXC silently drops messages without it)
- Key exchange via `change-public-keys` (unencrypted), all subsequent messages use NaCl `crypto_box`
- `openDatabase(triggerUnlock=true)` is NON-BLOCKING - returns immediately, must poll for unlock
- `test-associate` only works when DB is unlocked
- Relevant KeePassXC source files (in KeePassXC repo): `src/browser/BrowserAction.cpp`, `src/browser/BrowserService.cpp`

## Commands

```shell
# Install
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=keepassxc_ssh_agent

# Lint
ruff check --ignore=E501 --exclude=__init__.py ./keepassxc_ssh_agent
```

## Conventions

- Python >= 3.10, no async (threading-based for simplicity)
- `from __future__ import annotations` in all source files for modern type syntax (`X | None`)
- PyNaCl for NaCl crypto (not raw libsodium)
- Config files use 0600 permissions (owner-only)
- Tests use `short_tmp` fixture for Unix socket paths (macOS `tmp_path` is too long for AF_UNIX)
- LaunchAgent label: `org.keepassxc.ssh-agent`

## Known Limitations

- macOS only (browser extension socket path is platform-specific)
- If DB is unlocked but ssh-agent is cleared (`ssh-add -D`), keys won't reload without lock/unlock cycle
- `triggerUnlock` only works for the active database tab in KeePassXC

## CI

- `lint_and_test.yml` - Unit tests + ruff lint across Python 3.10-3.14
- `pypi.yml` - Build & publish on release
- `auto-release.yml` - Auto-create patch release on dependabot merge
- `auto-merge-dependabot.yml` - Auto-merge dependabot PRs
