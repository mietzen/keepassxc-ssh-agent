"""SSH agent proxy server.

Listens on a Unix socket for SSH agent protocol connections.
Forwards requests to the system ssh-agent. When keys are unavailable
(agent failure or empty identity list), triggers KeePassXC unlock
and retries.
"""

import logging
import os
import signal
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Optional

from . import ssh_agent_protocol as proto
from .browser_client import BrowserClient
from .config import Config

logger = logging.getLogger(__name__)


class SSHAgentProxy:
    """SSH agent proxy that triggers KeePassXC unlock on demand."""

    def __init__(self, config: Config, system_agent_path: str = ""):
        self.config = config
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._system_agent_path = system_agent_path or os.environ.get("SSH_AUTH_SOCK", "")
        # Lock to prevent concurrent unlock attempts
        self._unlock_lock = threading.Lock()
        # Track recent unlock to avoid spamming KeePassXC
        self._last_unlock_attempt = 0.0
        self._unlock_cooldown = 3.0  # seconds

    def start(self) -> None:
        """Start the proxy server."""
        if not self._system_agent_path:
            logger.error("SSH_AUTH_SOCK is not set. Cannot forward to system agent.")
            raise RuntimeError("SSH_AUTH_SOCK not set")

        sock_path = Path(self.config.socket_path)

        # Remove stale socket file
        if sock_path.exists():
            sock_path.unlink()

        sock_path.parent.mkdir(parents=True, exist_ok=True)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(str(sock_path))
        # Set socket permissions to owner only
        os.chmod(str(sock_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  # Allow periodic check for shutdown
        self._running = True

        logger.info("SSH agent proxy listening on %s", sock_path)
        logger.info("Forwarding to system agent at %s", self._system_agent_path)

        # Handle graceful shutdown (only works in main thread)
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except ValueError:
            pass  # Not in main thread (e.g. during tests)

        try:
            while self._running:
                try:
                    client_sock, _ = self._server_socket.accept()
                    # Handle each client in a separate thread
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock,),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the proxy server."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

        # Clean up socket file
        sock_path = Path(self.config.socket_path)
        if sock_path.exists():
            try:
                sock_path.unlink()
            except OSError:
                pass

        logger.info("SSH agent proxy stopped")

    def _signal_handler(self, signum: int, frame) -> None:
        logger.info("Received signal %d, shutting down...", signum)
        self._running = False

    def _handle_client(self, client_sock: socket.socket) -> None:
        """Handle a single SSH agent client connection."""
        client_sock.settimeout(30.0)
        try:
            while True:
                request = proto.read_message(client_sock)
                if request is None:
                    break  # Client disconnected

                msg_type = proto.get_message_type(request)
                response = self._process_request(request, msg_type)

                if response is None:
                    response = proto.make_failure_response()

                if not proto.write_message(client_sock, response):
                    break
        except Exception:
            logger.debug("Client connection error", exc_info=True)
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    def _process_request(self, request: bytes, msg_type: Optional[int]) -> Optional[bytes]:
        """Process an SSH agent request, potentially triggering unlock."""
        # Forward to system agent
        response = proto.forward_to_agent(self._system_agent_path, request)

        if response is None:
            # System agent not available, return failure
            logger.debug("System agent not available")
            return proto.make_failure_response()

        # Check if we should try to unlock
        should_unlock = False

        if msg_type == proto.SSH_AGENTC_REQUEST_IDENTITIES and proto.is_empty_identities(response):
            # No identities - might need to unlock DB so keys get loaded
            should_unlock = True
            logger.debug("Empty identity list from system agent, may need unlock")

        elif msg_type == proto.SSH_AGENTC_SIGN_REQUEST and proto.is_failure_response(response):
            # Sign request failed - key might not be loaded
            should_unlock = True
            logger.debug("Sign request failed, may need unlock")

        if should_unlock:
            if self._try_unlock():
                # Retry the request after unlock
                retry_response = proto.forward_to_agent(self._system_agent_path, request)
                if retry_response is not None:
                    return retry_response

        return response

    def _try_unlock(self) -> bool:
        """Attempt to unlock KeePassXC, with rate limiting."""
        now = time.monotonic()

        with self._unlock_lock:
            if now - self._last_unlock_attempt < self._unlock_cooldown:
                logger.debug("Unlock attempt rate-limited")
                return False

            self._last_unlock_attempt = now

            logger.info("Triggering KeePassXC database unlock...")
            client = BrowserClient(self.config)
            result = client.ensure_unlocked()

            if result:
                logger.info("Database unlocked, keys should now be available")
                # Give KeePassXC a moment to push keys to ssh-agent
                time.sleep(0.5)
            else:
                logger.warning("Database unlock failed or was cancelled")

            return result
