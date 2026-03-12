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
        _cmd_run(config)


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
        print("Setup complete! To use the agent:")
        print()
        print("  1. Start the agent:")
        print(f"     keepassxc-ssh-agent run --socket {config.socket_path}")
        print()
        print("  2. Add to your ~/.ssh/config:")
        print(f'     Host *')
        print(f'         IdentityAgent "{config.socket_path}"')
        print()
        print("  3. (Optional) Add a LaunchAgent for auto-start")
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


def _cmd_run(config: Config):
    """Start the agent proxy."""
    import os

    from .server import SSHAgentProxy

    if not os.environ.get("SSH_AUTH_SOCK"):
        print("ERROR: SSH_AUTH_SOCK is not set. Cannot forward to system ssh-agent.")
        print("Start ssh-agent first, e.g.: eval $(ssh-agent)")
        sys.exit(1)

    if not config.associations:
        print("ERROR: No KeePassXC association found. Run 'keepassxc-ssh-agent setup' first.")
        sys.exit(1)

    proxy = SSHAgentProxy(config)
    try:
        proxy.start()
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
