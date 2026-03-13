"""CLI entry point for keepassxc-ssh-agent."""

import argparse
import logging
import sys

from .config import Config, DEFAULT_CONFIG_PATH, DEFAULT_SOCKET_PATH


def main():
    # Common arguments shared by all subcommands
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--socket",
        default=str(DEFAULT_SOCKET_PATH),
        help=f"Path for the agent Unix socket (default: {DEFAULT_SOCKET_PATH})",
    )
    common.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to config file (default: {DEFAULT_CONFIG_PATH})",
    )
    common.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for unlock prompt (default: 30)",
    )
    common.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    parser = argparse.ArgumentParser(
        prog="keepassxc-ssh-agent",
        description="SSH IdentityAgent proxy that triggers KeePassXC database unlock via TouchID",
        parents=[common],
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "setup",
        parents=[common],
        help="Associate with KeePassXC (one-time setup)",
    )

    subparsers.add_parser(
        "run",
        parents=[common],
        help="Start the SSH agent proxy (default command)",
    )

    subparsers.add_parser(
        "status",
        parents=[common],
        help="Check connection status with KeePassXC",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    from pathlib import Path

    config = Config.load(Path(args.config))
    config.socket_path = args.socket
    config.unlock_timeout = args.timeout

    command = args.command or "run"

    if command == "setup":
        _cmd_setup(config, Path(args.config))
    elif command == "status":
        _cmd_status(config)
    elif command == "run":
        _cmd_run(config, Path(args.config))


def _ask_yes_no(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question and return the answer."""
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not answer:
        return default
    return answer in ("y", "yes")


LAUNCHAGENT_RUN_LABEL = "org.keepassxc.ssh-agent"


def _find_agent_bin() -> str:
    """Find the keepassxc-ssh-agent binary path."""
    import shutil

    path = shutil.which("keepassxc-ssh-agent")
    if path:
        return path
    return sys.executable


def _get_run_plist(agent_bin: str) -> str:
    """LaunchAgent plist that starts keepassxc-ssh-agent run on login."""
    args_block = f"    <string>{agent_bin}</string>\n    <string>run</string>"
    if agent_bin == sys.executable:
        args_block = (
            f"    <string>{agent_bin}</string>\n"
            "    <string>-m</string>\n"
            "    <string>keepassxc_ssh_agent</string>\n"
            "    <string>run</string>"
        )
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
  <string>/tmp/keepassxc-ssh-agent.out.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/keepassxc-ssh-agent.err.log</string>
</dict>
</plist>
"""


def _create_launchagent(label: str, content: str) -> bool:
    """Create and load a single LaunchAgent plist. Returns True on success."""
    import os
    import subprocess
    from pathlib import Path

    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"

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
    except subprocess.CalledProcessError as e:
        print(f"  Warning: Failed to load: {e.stderr.decode().strip()}")
        print(f"  You can load it manually: launchctl bootstrap gui/{uid} {plist_path}")
        return False


def _cmd_setup(config: Config, config_path):
    """Run the setup/association flow."""
    import os

    from .browser_client import BrowserClient

    if not os.environ.get("SSH_AUTH_SOCK"):
        print("WARNING: SSH_AUTH_SOCK is not set. The proxy needs a running ssh-agent to forward to.")
        print("Make sure ssh-agent is running before using 'run' command.")
        print()

    print("KeePassXC SSH Agent - Setup")
    print("=" * 40)
    print()
    print("Prerequisites:")
    print("  1. KeePassXC must be running")
    print("  2. Browser integration must be enabled in KeePassXC settings")
    print()
    print("Connecting to KeePassXC...")

    client = BrowserClient(config)
    if client.setup():
        config.save(config_path)
        print()
        print("Setup complete!")

        # Auto-start agent on login
        print()
        if _ask_yes_no("Create a LaunchAgent to start keepassxc-ssh-agent on login?"):
            agent_bin = _find_agent_bin()
            _create_launchagent(LAUNCHAGENT_RUN_LABEL, _get_run_plist(agent_bin))
            print()
            print("  The agent will set SSH_AUTH_SOCK automatically on startup")
            print("  via 'launchctl setenv' so all new processes use the proxy.")
        else:
            print()
            print("  To start manually: keepassxc-ssh-agent run")

        print()
        print("To start the agent now:")
        print("  keepassxc-ssh-agent run")
    else:
        print()
        print("Setup failed. Make sure KeePassXC is running with browser integration enabled.")
        sys.exit(1)


def _cmd_status(config: Config):
    """Check connection status."""
    import os
    from pathlib import Path

    from .browser_client import BrowserClient

    print("KeePassXC SSH Agent - Status")
    print("=" * 40)

    # Check system ssh-agent
    agent_sock = os.environ.get("SSH_AUTH_SOCK", "")
    if agent_sock:
        if Path(agent_sock).exists():
            print(f"  System ssh-agent: OK ({agent_sock})")
        else:
            print(f"  System ssh-agent: NOT FOUND ({agent_sock})")
    else:
        print("  System ssh-agent: SSH_AUTH_SOCK not set")

    # Check proxy socket
    sock_path = Path(config.socket_path)
    if sock_path.exists():
        print(f"  Proxy socket: EXISTS ({sock_path})")
    else:
        print(f"  Proxy socket: NOT RUNNING ({sock_path})")

    # Check KeePassXC connection
    print("  KeePassXC: ", end="")
    client = BrowserClient(config)
    if client.connect():
        if client.change_public_keys():
            # Test any stored association
            found = False
            for _hash, assoc in config.associations.items():
                if client.test_associate(assoc):
                    print(f"CONNECTED (association: {assoc.id})")
                    found = True
                    break
            if not found:
                if config.associations:
                    print("CONNECTED but associations expired (run 'setup' again)")
                else:
                    print("CONNECTED but not associated (run 'setup')")
        else:
            print("CONNECTED but key exchange failed")
        client.disconnect()
    else:
        print("NOT AVAILABLE (is KeePassXC running with browser integration?)")


def _resolve_system_agent(config: Config, config_path) -> str:
    """Resolve the real system ssh-agent socket path, avoiding our own socket.

    On first boot, SSH_AUTH_SOCK points to the real agent (e.g.
    /tmp/com.apple.launchd.XXX/Listeners). We save this path to config.
    On restart (KeepAlive), SSH_AUTH_SOCK may point to our own socket
    (if launchctl setenv was used), so we fall back to the saved path.
    """
    import os
    from pathlib import Path

    ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK", "")
    our_socket = str(Path(config.socket_path).resolve())

    if ssh_auth_sock:
        resolved = str(Path(ssh_auth_sock).resolve())
        if resolved != our_socket:
            # SSH_AUTH_SOCK points to the real agent - save it
            if config.system_agent_path != ssh_auth_sock:
                config.system_agent_path = ssh_auth_sock
                config.save(config_path)
            return ssh_auth_sock

    # SSH_AUTH_SOCK points to our socket or is unset - use saved path
    if config.system_agent_path:
        return config.system_agent_path

    return ""


def _setenv_ssh_auth_sock(socket_path: str) -> bool:
    """Set SSH_AUTH_SOCK for all new launchd-spawned processes.

    Uses 'launchctl setenv' which only affects processes spawned by launchd
    AFTER this call. Already-running terminals/apps are not affected.
    """
    import logging
    import subprocess

    logger = logging.getLogger(__name__)
    try:
        subprocess.run(
            ["launchctl", "setenv", "SSH_AUTH_SOCK", socket_path],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.warning("launchctl setenv failed: %s", e.stderr.decode().strip() if e.stderr else str(e))
        return False
    except FileNotFoundError:
        logger.debug("launchctl not found (not macOS?)")
        return False


def _cmd_run(config: Config, config_path=None):
    """Start the agent proxy."""
    import logging

    from .server import SSHAgentProxy

    logger = logging.getLogger(__name__)

    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    system_agent = _resolve_system_agent(config, config_path)
    if not system_agent:
        print("ERROR: Cannot determine system ssh-agent path.")
        print("SSH_AUTH_SOCK is not set and no saved agent path in config.")
        print("Start ssh-agent first, e.g.: eval $(ssh-agent)")
        sys.exit(1)

    if not config.associations:
        print("ERROR: No KeePassXC association found. Run 'keepassxc-ssh-agent setup' first.")
        sys.exit(1)

    # Redirect SSH_AUTH_SOCK for all new processes to our proxy socket
    _setenv_ssh_auth_sock(config.socket_path)
    logger.info("Set SSH_AUTH_SOCK=%s via launchctl setenv", config.socket_path)

    proxy = SSHAgentProxy(config, system_agent_path=system_agent)
    try:
        proxy.start()
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
