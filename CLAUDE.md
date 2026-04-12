# KeePassXC SSH Agent - Claude Code Instructions

## Project Overview

Standalone Python tool — an SSH IdentityAgent proxy for macOS that triggers KeePassXC database unlock (via TouchID) when SSH keys are needed.

## Architecture

- **Proxy pattern**: SSH Client → keepassxc-ssh-agent (Unix socket) → System ssh-agent
- **Unlock trigger**: Uses the [`keepassxc-browser-api`](https://github.com/mietzen/keepassxc-browser-api) library, which implements the NaCl-encrypted browser extension protocol
- **No signing**: The proxy does NOT implement SSH key signing. KeePassXC pushes keys to the system ssh-agent on unlock, and the proxy forwards requests there.
- **SSH_AUTH_SOCK interception**: Renames the real ssh-agent socket to `.system` suffix and symlinks the original path to the proxy socket. Restores on shutdown.

### Key Files

- `keepassxc_ssh_agent/server.py` — SSH agent proxy server (threading-based, Unix socket); `SSHAgentProxy(config, browser_config)`
- `keepassxc_ssh_agent/ssh_agent_protocol.py` — SSH agent wire format (4-byte length prefix + message)
- `keepassxc_ssh_agent/config.py` — Agent-only config persistence (`~/.keepassxc/ssh-agent.json`); fields: `socket_path`, `system_agent_path`, `browser_api_config_path`
- `keepassxc_ssh_agent/__main__.py` — CLI: `install`, `run`, `status`, `uninstall`

### Config Files

| File | Class | Contents |
|---|---|---|
| `~/.keepassxc/ssh-agent.json` | `Config` | `socket_path`, `system_agent_path`, `browser_api_config_path` |
| `~/.keepassxc/browser-api.json` | `BrowserConfig` (from library) | Keypair, associations, unlock timeout — shared with `keepassxc-cli` |

`BrowserConfig` is owned by `keepassxc-browser-api`. Associate once, both tools benefit.

### Dependencies

- [`keepassxc-browser-api`](https://github.com/mietzen/keepassxc-browser-api) — handles all KeePassXC browser extension protocol communication (NaCl crypto, association, unlock)

### KeePassXC Browser Protocol

- Socket: `$TMPDIR/org.keepassxc.KeePassXC.BrowserServer` (macOS), `$XDG_RUNTIME_DIR/.../org.keepassxc.KeePassXC.BrowserServer` (Linux)
- See `keepassxc-browser-api` CLAUDE.md for full protocol details
- Relevant KeePassXC source: `src/browser/BrowserAction.cpp`, `src/browser/BrowserService.cpp`

## Commands

```shell
# Install with dev dependencies
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
- `from __future__ import annotations` in all source files
- Config files use 0600 permissions (owner-only)
- Tests use `short_tmp` fixture for Unix socket paths (macOS `tmp_path` is too long for AF_UNIX)
- LaunchAgent label: `org.keepassxc.ssh-agent`

## Known Limitations

- macOS only (browser extension socket path is platform-specific)
- If DB is unlocked but ssh-agent is cleared (`ssh-add -D`), keys won't reload without lock/unlock cycle
- `triggerUnlock` only works for the active database tab in KeePassXC

## Homebrew

- Tap repo: `mietzen/homebrew-tap` (access locally via `cd $(brew --repository mietzen/homebrew-tap)`)
- Formula: `Formula/keepassxc-ssh-agent.rb` — uses `Language::Python::Virtualenv`, depends on python@3.13, libsodium
- Service managed via `brew services` (not the tool's own LaunchAgent when installed via Homebrew)
- Formula auto-updated on new PyPI releases via `repository_dispatch` from `pypi.yml`

## CI

- `lint_and_test.yml` — Unit tests + ruff lint across Python 3.10–3.14
- `pypi.yml` — Build & publish on release, then dispatch to homebrew-tap to update the formula
- `auto-release.yml` — Auto-create patch release on dependabot merge
- `auto-merge-dependabot.yml` — Auto-merge dependabot PRs

