"""Auto-start service management.

Abstracts the platform-specific "start on login" mechanism:

- macOS: a launchd LaunchAgent (plist + ``launchctl``)
- Linux: a systemd user unit (``systemctl --user``)

The rest of the tool is platform-neutral; this module is the only place that
knows about launchd vs systemd.
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

# macOS LaunchAgent label / Linux systemd unit name
LAUNCHAGENT_RUN_LABEL = "org.keepassxc.ssh-agent"
SYSTEMD_UNIT_NAME = "keepassxc-ssh-agent.service"


def _find_agent_bin() -> str:
    """Find the keepassxc-ssh-agent binary path."""
    path = shutil.which("keepassxc-ssh-agent")
    if path:
        return path
    return sys.executable


def _agent_argv(agent_bin: str) -> list[str]:
    """Build the argv that runs the proxy.

    When ``agent_bin`` is a plain Python interpreter (no console script on
    PATH), fall back to ``python -m keepassxc_ssh_agent run``.
    """
    if agent_bin == sys.executable:
        return [agent_bin, "-m", "keepassxc_ssh_agent", "run"]
    return [agent_bin, "run"]


# --------------------------------------------------------------------------- #
# Public API (dispatches on platform)
# --------------------------------------------------------------------------- #


def install_service(agent_bin: str, *, ssh_auth_sock: str | None = None) -> bool:
    """Install and start the auto-start service. Returns True on success.

    Only macOS and Linux are supported. On any other platform, nothing is
    written and the function returns False with a warning.
    """
    if sys.platform == "darwin":
        return _create_launchagent(LAUNCHAGENT_RUN_LABEL, _get_run_plist(agent_bin))
    if sys.platform.startswith("linux"):
        return _create_systemd_service(agent_bin, ssh_auth_sock)
    print(f"  Warning: auto-start service not supported on {sys.platform}")
    return False


def remove_service() -> bool:
    """Stop and remove the auto-start service. Returns True if removed.

    Only macOS and Linux are supported. On any other platform, nothing is
    changed and the function returns False with a warning.
    """
    if sys.platform == "darwin":
        return _remove_launchagent(LAUNCHAGENT_RUN_LABEL)
    if sys.platform.startswith("linux"):
        return _remove_systemd_service()
    print(f"  Warning: auto-start service not supported on {sys.platform}")
    return False


# --------------------------------------------------------------------------- #
# macOS: launchd LaunchAgent
# --------------------------------------------------------------------------- #


def _launchagent_path(label: str) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def _get_run_plist(agent_bin: str) -> str:
    """Generate LaunchAgent plist that starts keepassxc-ssh-agent run on login."""
    log_dir = Path.home() / ".keepassxc" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(log_dir), stat.S_IRWXU)

    args_block = "\n".join(f"    <string>{arg}</string>" for arg in _agent_argv(agent_bin))
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHAGENT_RUN_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args_block}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log_dir / "out.log"}</string>
  <key>StandardErrorPath</key>
  <string>{log_dir / "err.log"}</string>
</dict>
</plist>
"""


def _create_launchagent(label: str, content: str) -> bool:
    """Create and load a single LaunchAgent plist. Returns True on success."""
    plist_path = _launchagent_path(label)

    if plist_path.exists():
        print(f"  {plist_path} already exists, skipping.")
        return True

    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(content)
    print(f"  Created {plist_path}")

    uid = os.getuid()
    try:
        subprocess.run(
            ["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
            check=True,
            capture_output=True,
        )
        print(f"  Loaded {label}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        detail = e.stderr.decode().strip() if isinstance(e, subprocess.CalledProcessError) else str(e)
        print(f"  Warning: Failed to load: {detail}")
        print(f"  You can load it manually: launchctl bootstrap gui/{uid} {plist_path}")
        return False


def _remove_launchagent(label: str) -> bool:
    """Stop and remove a LaunchAgent plist. Returns True if removed."""
    plist_path = _launchagent_path(label)

    if not plist_path.exists():
        print(f"  {plist_path} does not exist, skipping.")
        return False

    uid = os.getuid()
    try:
        subprocess.run(
            ["launchctl", "bootout", f"gui/{uid}", str(plist_path)],
            check=True,
            capture_output=True,
        )
        print(f"  Stopped {label}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass  # May not be running

    plist_path.unlink()
    print(f"  Removed {plist_path}")
    return True


# --------------------------------------------------------------------------- #
# Linux: systemd user unit
# --------------------------------------------------------------------------- #


def _systemd_unit_path() -> Path:
    config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(config_home) / "systemd" / "user" / SYSTEMD_UNIT_NAME


def _get_systemd_unit(agent_bin: str, ssh_auth_sock: str | None = None) -> str:
    """Generate the systemd user unit that runs the proxy on login.

    ``ssh_auth_sock`` is baked into the unit because a systemd --user service
    runs with a clean environment and would otherwise not see the login shell's
    SSH_AUTH_SOCK, which the proxy needs to intercept the system agent socket.
    """
    # shlex.join() escapes each arg so paths with spaces survive systemd's
    # ExecStart word-splitting.
    exec_start = shlex.join(_agent_argv(agent_bin))
    env_line = f"Environment=SSH_AUTH_SOCK={ssh_auth_sock}\n" if ssh_auth_sock else ""
    return f"""\
[Unit]
Description=KeePassXC SSH Agent proxy
After=ssh-agent.service

[Service]
Type=simple
ExecStart={exec_start}
{env_line}Restart=on-failure

[Install]
WantedBy=default.target
"""


def _create_systemd_service(agent_bin: str, ssh_auth_sock: str | None = None) -> bool:
    """Write and start the systemd user unit. Returns True on success."""
    unit_path = _systemd_unit_path()

    # Always (re)write the unit so a repeat install picks up the current binary
    # path / SSH_AUTH_SOCK, then enable and restart so the latest is running.
    existed = unit_path.exists()
    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(_get_systemd_unit(agent_bin, ssh_auth_sock))
    print(f"  {'Updated' if existed else 'Created'} {unit_path}")

    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True)
        subprocess.run(
            ["systemctl", "--user", "enable", SYSTEMD_UNIT_NAME],
            check=True,
            capture_output=True,
        )
        # restart (not just start) so a re-install reloads the new unit/binary
        subprocess.run(
            ["systemctl", "--user", "restart", SYSTEMD_UNIT_NAME],
            check=True,
            capture_output=True,
        )
        print(f"  Enabled and started {SYSTEMD_UNIT_NAME}")
        _print_systemd_help()
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        detail = e.stderr.decode().strip() if isinstance(e, subprocess.CalledProcessError) else str(e)
        print(f"  Warning: Failed to start: {detail}")
        print(f"  You can start it manually: systemctl --user enable --now {SYSTEMD_UNIT_NAME}")
        return False


def _print_systemd_help() -> None:
    """Print the systemctl/journalctl commands to manage the service."""
    name = "keepassxc-ssh-agent"
    print()
    print("  Manage the service with:")
    print(f"    systemctl --user status {name}      # check status")
    print(f"    systemctl --user stop {name}        # stop")
    print(f"    systemctl --user start {name}       # start")
    print(f"    systemctl --user restart {name}     # restart")
    print(f"    journalctl --user -u {name} -f      # follow logs")


def _remove_systemd_service() -> bool:
    """Stop and remove the systemd user unit. Returns True if removed."""
    unit_path = _systemd_unit_path()

    if not unit_path.exists():
        print(f"  {unit_path} does not exist, skipping.")
        return False

    try:
        subprocess.run(
            ["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT_NAME],
            check=True,
            capture_output=True,
        )
        print(f"  Stopped {SYSTEMD_UNIT_NAME}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass  # May not be running

    unit_path.unlink()
    print(f"  Removed {unit_path}")

    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return True
