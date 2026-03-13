"""CLI entry point for keepassxc-ssh-agent."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .config import Config, DEFAULT_CONFIG_PATH, DEFAULT_SOCKET_PATH


def main() -> None:
    """Parse arguments and dispatch to the appropriate subcommand."""
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

    install_parser = subparsers.add_parser(
        "install",
        parents=[common],
        help="Associate with KeePassXC and install LaunchAgent",
    )
    install_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Auto-accept all prompts (non-interactive)",
    )
    install_parser.add_argument(
        "--register-only",
        action="store_true",
        help="Only register with KeePassXC, skip LaunchAgent creation",
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

    uninstall_parser = subparsers.add_parser(
        "uninstall",
        parents=[common],
        help="Remove LaunchAgent and restore SSH_AUTH_SOCK",
    )
    uninstall_parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Auto-accept all prompts (non-interactive)",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    config = Config.load(Path(args.config))
    config.socket_path = args.socket
    config.unlock_timeout = args.timeout

    command = args.command or "run"

    if command == "install":
        _cmd_install(config, Path(args.config), yes=args.yes, register_only=args.register_only)
    elif command == "status":
        _cmd_status(config)
    elif command == "uninstall":
        _cmd_uninstall(config, Path(args.config), yes=args.yes)
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
    """Generate LaunchAgent plist that starts keepassxc-ssh-agent run on login."""
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


def _remove_launchagent(label: str) -> bool:
    """Stop and remove a LaunchAgent plist. Returns True if removed."""
    import os
    import subprocess
    from pathlib import Path

    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"

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
    except subprocess.CalledProcessError:
        pass  # May not be running

    plist_path.unlink()
    print(f"  Removed {plist_path}")
    return True


def _cmd_install(config: Config, config_path: Path, *, yes: bool = False, register_only: bool = False) -> None:
    """Run the install/association flow."""
    import os

    from .browser_client import BrowserClient

    if not os.environ.get("SSH_AUTH_SOCK"):
        print("WARNING: SSH_AUTH_SOCK is not set. The proxy needs a running ssh-agent to forward to.")
        print("Make sure ssh-agent is running before using 'run' command.")
        print()

    print("KeePassXC SSH Agent - Install")
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
        print("Registration complete!")

        if not register_only:
            # Auto-start agent on login
            print()
            if yes or _ask_yes_no("Create a LaunchAgent to start keepassxc-ssh-agent on login?"):
                agent_bin = _find_agent_bin()
                _create_launchagent(LAUNCHAGENT_RUN_LABEL, _get_run_plist(agent_bin))
                print()
                print("  The agent will intercept SSH_AUTH_SOCK automatically on startup")
                print("  so all SSH clients use the proxy transparently.")
            else:
                print()
                print("  To start manually: keepassxc-ssh-agent run")

        print()
        print("To start the agent now:")
        print("  keepassxc-ssh-agent run")
    else:
        print()
        print("Install failed. Make sure KeePassXC is running with browser integration enabled.")
        sys.exit(1)


def _cmd_status(config: Config) -> None:
    """Check connection status."""
    import os

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
                    print("CONNECTED but associations expired (run 'install' again)")
                else:
                    print("CONNECTED but not associated (run 'install')")
        else:
            print("CONNECTED but key exchange failed")
        client.disconnect()
    else:
        print("NOT AVAILABLE (is KeePassXC running with browser integration?)")


SYSTEM_SOCKET_SUFFIX = ".system"


def _intercept_ssh_auth_sock(config: Config, config_path: Path) -> str:
    """Intercept SSH_AUTH_SOCK by replacing the system socket with a symlink.

    Renames the real ssh-agent socket to <path>.system and creates a symlink
    from the original path to our proxy socket. All SSH clients then connect
    to our proxy transparently.

    Handles three cases:
    - Normal startup: rename real socket, symlink ours, forward to renamed
    - KeepAlive restart: symlink already in place, backup exists, just forward
    - Crash recovery: backup exists but symlink is stale/missing, re-create

    Returns the path to forward requests to (the renamed real agent socket).
    """
    import os

    ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK", "")
    our_socket = str(Path(config.socket_path).resolve())

    if not ssh_auth_sock:
        # No SSH_AUTH_SOCK - use saved path if available
        if config.system_agent_path:
            backup = config.system_agent_path + SYSTEM_SOCKET_SUFFIX
            if Path(backup).exists():
                return backup
            return config.system_agent_path
        return ""

    sock_path = Path(ssh_auth_sock)
    backup_path = Path(ssh_auth_sock + SYSTEM_SOCKET_SUFFIX)

    # Case 1: Our symlink is already in place (KeepAlive restart)
    if sock_path.is_symlink():
        link_target = str(Path(os.readlink(str(sock_path))).resolve())
        if link_target == our_socket and backup_path.exists():
            return str(backup_path)
        # Stale or foreign symlink - remove it
        sock_path.unlink()

    # Case 2: Backup exists but symlink is gone (crash recovery)
    if backup_path.exists() and not sock_path.exists():
        os.symlink(our_socket, str(sock_path))
        return str(backup_path)

    # Case 3: Normal startup - real socket exists
    if sock_path.exists() and not sock_path.is_symlink():
        # Save the original SSH_AUTH_SOCK path
        if config.system_agent_path != ssh_auth_sock:
            config.system_agent_path = ssh_auth_sock
            config.save(config_path)

        # Clean up any stale backup
        if backup_path.exists():
            backup_path.unlink()

        os.rename(str(sock_path), str(backup_path))
        os.symlink(our_socket, str(sock_path))
        return str(backup_path)

    # Fallback to saved path
    if config.system_agent_path:
        backup = config.system_agent_path + SYSTEM_SOCKET_SUFFIX
        if Path(backup).exists():
            return backup
        return config.system_agent_path

    return ""


def _restore_ssh_auth_sock(ssh_auth_sock: str) -> None:
    """Restore the original ssh-agent socket on shutdown."""
    if not ssh_auth_sock:
        return

    sock_path = Path(ssh_auth_sock)
    backup_path = Path(ssh_auth_sock + SYSTEM_SOCKET_SUFFIX)

    # Remove our symlink
    if sock_path.is_symlink():
        try:
            sock_path.unlink()
        except OSError:
            pass

    # Restore the real socket to its original path
    if backup_path.exists():
        try:
            backup_path.rename(sock_path)
        except OSError:
            pass


def _cmd_uninstall(config: Config, config_path: Path, *, yes: bool = False) -> None:
    """Remove LaunchAgent, restore SSH_AUTH_SOCK, and optionally clean up config."""
    import shutil

    print("KeePassXC SSH Agent - Uninstall")
    print("=" * 40)
    print()

    # Step 1: Stop and remove the LaunchAgent
    print("LaunchAgent:")
    _remove_launchagent(LAUNCHAGENT_RUN_LABEL)

    # Step 2: Restore SSH_AUTH_SOCK
    print()
    print("SSH_AUTH_SOCK:")
    if config.system_agent_path:
        _restore_ssh_auth_sock(config.system_agent_path)
        print(f"  Restored {config.system_agent_path}")
    else:
        print("  No saved system agent path, nothing to restore.")

    # Step 3: Remove proxy socket
    proxy_sock = Path(config.socket_path)
    if proxy_sock.exists() or proxy_sock.is_symlink():
        proxy_sock.unlink()
        print(f"  Removed proxy socket {proxy_sock}")

    # Step 4: Remove config directory
    print()
    print("Config:")
    config_dir = Path(config_path).parent
    if config_dir.exists():
        if yes or _ask_yes_no(f"Remove config directory {config_dir}?"):
            shutil.rmtree(config_dir)
            print(f"  Removed {config_dir}")
        else:
            print(f"  Kept {config_dir}")
    else:
        print(f"  {config_dir} does not exist, nothing to remove.")

    print()
    print("Uninstall complete.")
    print("To remove the package itself: pipx uninstall keepassxc-ssh-agent")


def _cmd_run(config: Config, config_path: Path | None = None) -> None:
    """Start the agent proxy."""
    import logging
    import os

    from .server import SSHAgentProxy

    logger = logging.getLogger(__name__)

    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK", "")

    if not config.associations:
        print("ERROR: No KeePassXC association found. Run 'keepassxc-ssh-agent install' first.")
        sys.exit(1)

    system_agent = _intercept_ssh_auth_sock(config, config_path)
    if not system_agent:
        print("ERROR: Cannot determine system ssh-agent path.")
        print("SSH_AUTH_SOCK is not set and no saved agent path in config.")
        print("Start ssh-agent first, e.g.: eval $(ssh-agent)")
        sys.exit(1)

    logger.info("Intercepted SSH_AUTH_SOCK=%s, forwarding to %s", ssh_auth_sock, system_agent)

    proxy = SSHAgentProxy(config, system_agent_path=system_agent)
    try:
        proxy.start()
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    finally:
        _restore_ssh_auth_sock(ssh_auth_sock)


if __name__ == "__main__":
    main()
