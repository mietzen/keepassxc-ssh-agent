# KeePassXC SSH Agent

`keepassxc-ssh-agent` is an SSH `IdentityAgent` proxy for macOS that automatically triggers KeePassXC database unlock (via TouchID / Quick Unlock) when an SSH key is needed.

Similar to how [Strongbox](https://strongboxsafe.com/) handles SSH keys, this tool sits between your SSH client and the system `ssh-agent`. When SSH requests a key that isn't loaded (because the KeePassXC database is locked), the proxy triggers KeePassXC's unlock dialog. After you authenticate with TouchID, KeePassXC pushes the keys to `ssh-agent`, and the SSH operation continues seamlessly.

## Prerequisites

- **macOS** (uses Unix sockets and KeePassXC's browser extension socket)
- **Python >= 3.10**
- **KeePassXC** with:
  - **Browser Integration** enabled (Settings > Browser Integration > Enable browser integration)
  - **SSH Agent Integration** enabled (Settings > SSH Agent > Enable SSH Agent integration)
  - SSH keys configured with "Add key to agent when database is opened/unlocked"
- A running **ssh-agent** (`SSH_AUTH_SOCK` must be set)

## Usage

```
usage: keepassxc-ssh-agent [-h] [--socket SOCKET] [--config CONFIG]
                           [--timeout TIMEOUT] [-v]
                           {install,run,status,uninstall} ...

SSH IdentityAgent proxy that triggers KeePassXC database unlock via TouchID

positional arguments:
  {install,run,status,uninstall}
    install             Associate with KeePassXC and install LaunchAgent
    run                 Start the SSH agent proxy (default command)
    status              Check connection status with KeePassXC
    uninstall           Remove LaunchAgent and restore SSH_AUTH_SOCK

options:
  -h, --help          show this help message and exit
  --socket SOCKET     Path for the agent Unix socket
                      (default: ~/.keepassxc/agent.sock)
  --config CONFIG     Path to config file
                      (default: ~/.keepassxc/ssh-agent.json)
  --timeout TIMEOUT   Timeout in seconds for unlock prompt (default: 30)
  -v, --verbose       Enable verbose logging
```

## Install

```shell
pipx install keepassxc-ssh-agent
```

## How It Works

```
SSH Client ──► SSH agent protocol ──► keepassxc-ssh-agent (proxy)
                                             │
                                             ├─► SSH agent protocol ──► System ssh-agent
                                             │   (forward requests / replay after unlock)
                                             │
                                             └─► Browser extension protocol ──► KeePassXC
                                                 (trigger unlock when keys missing)
```

1. SSH client connects to the proxy socket and requests identities or a signature
2. Proxy forwards the request to the system `ssh-agent`
3. If `ssh-agent` returns keys/signature, proxy passes it through (no delay)
4. If `ssh-agent` returns empty/failure (DB is locked, keys not loaded):
   - Proxy connects to KeePassXC via the browser extension protocol
   - Sends `get-databasehash` with `triggerUnlock` to show the unlock dialog
   - Polls until the database is unlocked or timeout expires
   - KeePassXC pushes SSH keys to `ssh-agent` on unlock
   - Proxy retries the original request and returns the result


## Setup

### One-Time Setup

Make sure KeePassXC is running with browser integration enabled, then:

```shell
keepassxc-ssh-agent install
```

This will:
- Generate encryption keys for the browser protocol
- Request association with KeePassXC (you'll need to approve it in the KeePassXC window)
- Save the configuration to `~/.keepassxc/ssh-agent.json`
- Optionally create a LaunchAgent for auto-start

#### Install Options

- `-y` / `--yes` — Auto-accept all prompts (non-interactive, creates the LaunchAgent automatically)
- `--register-only` — Only register with KeePassXC, skip LaunchAgent creation

Example for scripted/non-interactive install:

```shell
keepassxc-ssh-agent install -y
```

### Manual Setup

If you skipped the interactive setup prompts, here are the manual steps:

#### 1. Auto-Start the Agent on Login

Create a LaunchAgent to run `keepassxc-ssh-agent` on login:

```shell
cat << 'EOF' > ~/Library/LaunchAgents/org.keepassxc.ssh-agent.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>org.keepassxc.ssh-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/path/to/keepassxc-ssh-agent</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/keepassxc-ssh-agent.out.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/keepassxc-ssh-agent.err.log</string>
</dict>
</plist>
EOF
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.keepassxc.ssh-agent.plist
```

Replace `/path/to/keepassxc-ssh-agent` with the actual path (find it with `which keepassxc-ssh-agent`).

Or start manually:

```shell
keepassxc-ssh-agent run
```

#### 2. SSH_AUTH_SOCK Interception

The proxy automatically intercepts `SSH_AUTH_SOCK` on startup by renaming the system ssh-agent socket (e.g. `/tmp/com.apple.launchd.XXX/Listeners`) to a `.system` backup and placing a symlink from the original path to the proxy socket. All SSH clients then connect to the proxy transparently. The proxy forwards requests to the renamed `.system` socket.

On shutdown, the proxy restores the original socket. No separate LaunchAgent or SSH config is needed — the `run` command handles everything.

## Uninstall

The easiest way to uninstall is:

```shell
keepassxc-ssh-agent uninstall
```

This will stop and remove the LaunchAgent, restore the original SSH_AUTH_SOCK socket, and optionally remove the config directory (`~/.keepassxc/`). Use `-y` to skip confirmation prompts.

Then remove the package itself:

```shell
pipx uninstall keepassxc-ssh-agent
```

### Manual Uninstall

If you prefer to uninstall manually:

#### 1. Stop and remove the LaunchAgent

```shell
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/org.keepassxc.ssh-agent.plist 2>/dev/null
rm -f ~/Library/LaunchAgents/org.keepassxc.ssh-agent.plist
```

#### 2. Restore SSH_AUTH_SOCK

If the agent was running, it restores the original socket on shutdown automatically. If the system socket is still symlinked (e.g. after a crash), reboot or restore manually:

```shell
# Find the original socket path
SYSTEM_AGENT=$(cat ~/.keepassxc/ssh-agent.json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("system_agent_path",""))')
# Remove the symlink and restore the backup
rm -f "$SYSTEM_AGENT"
mv "${SYSTEM_AGENT}.system" "$SYSTEM_AGENT"
```

#### 3. Remove config and socket

```shell
rm -rf ~/.keepassxc
```

#### 4. Uninstall the package

```shell
pipx uninstall keepassxc-ssh-agent
```

## Known Limitations

- **macOS only**: Uses KeePassXC's browser extension Unix socket at `$TMPDIR/org.keepassxc.KeePassXC.BrowserServer`
- **DB unlocked but agent cleared**: If the database is already unlocked but `ssh-agent` keys were manually removed (`ssh-add -D`), the proxy detects empty keys and triggers "unlock", but KeePassXC reports "already unlocked" without reloading keys. Workaround: lock and re-unlock the database in KeePassXC.
- **Multiple databases**: `triggerUnlock` only works for the currently active database tab in KeePassXC.

## Development

```shell
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=keepassxc_ssh_agent
```
