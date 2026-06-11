"""SSH agent proxy server.

Listens on a Unix socket for SSH agent protocol connections.
Forwards requests to the system ssh-agent. When keys are unavailable
(agent failure or empty identity list), triggers KeePassXC unlock
and retries.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import stat
import threading
import time
import types
from pathlib import Path

from keepassxc_browser_api import BrowserClient, BrowserConfig
from keepassxc_browser_api.exceptions import KeePassXCError

from . import ssh_agent_protocol as proto
from .config import Config

logger = logging.getLogger(__name__)


class SSHAgentProxy:
    """SSH agent proxy that triggers KeePassXC unlock on demand."""

    def __init__(self, config: Config, browser_config: BrowserConfig, system_agent_path: str = ""):
        self.config = config
        self.browser_config = browser_config
        self._server_socket: socket.socket | None = None
        self._running = False
        self._system_agent_path = system_agent_path or os.environ.get("SSH_AUTH_SOCK", "")
        # Lock to prevent concurrent unlock attempts
        self._unlock_lock = threading.Lock()
        # Track recent unlock to avoid spamming KeePassXC
        self._last_unlock_attempt = 0.0
        self._unlock_cooldown = 3.0  # seconds
        # After unlock, KeePassXC loads keys into ssh-agent asynchronously.
        # Poll the agent until the key shows up instead of a single fixed wait.
        self._key_load_timeout = 5.0  # seconds, overall deadline
        self._key_poll_interval = 0.2  # seconds between polls

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
        os.chmod(str(sock_path.parent), stat.S_IRWXU)

        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Set restrictive umask before bind to avoid a window where the
        # socket is world-accessible between bind() and chmod().
        old_umask = os.umask(0o077)
        try:
            self._server_socket.bind(str(sock_path))
        finally:
            os.umask(old_umask)
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
                except TimeoutError:
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

    def _signal_handler(self, signum: int, frame: types.FrameType | None) -> None:
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

    def _process_request(self, request: bytes, msg_type: int | None) -> bytes | None:
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

        if should_unlock and self._try_unlock():
            # KeePassXC loads keys asynchronously after unlock; poll the
            # agent until the key appears rather than retrying just once.
            retry_response = self._poll_after_unlock(request, msg_type)
            if retry_response is not None:
                return retry_response

        return response

    def _poll_after_unlock(self, request: bytes, msg_type: int | None) -> bytes | None:
        """Poll the system agent after unlock until the key is available.

        Returns as soon as the agent reports a non-empty identity list (for a
        REQUEST_IDENTITIES) or a successful signature (for a SIGN_REQUEST), or
        the last response received once the deadline expires.
        """
        deadline = time.monotonic() + self._key_load_timeout
        last_response: bytes | None = None

        while True:
            response = proto.forward_to_agent(self._system_agent_path, request)
            if response is not None:
                last_response = response
                if msg_type == proto.SSH_AGENTC_REQUEST_IDENTITIES and not proto.is_empty_identities(response):
                    return response
                if msg_type == proto.SSH_AGENTC_SIGN_REQUEST and not proto.is_failure_response(response):
                    return response

            if time.monotonic() >= deadline:
                return last_response

            time.sleep(self._key_poll_interval)

    def _try_unlock(self) -> bool:
        """Attempt to unlock KeePassXC, with rate limiting."""
        now = time.monotonic()

        with self._unlock_lock:
            if now - self._last_unlock_attempt < self._unlock_cooldown:
                logger.debug("Unlock attempt rate-limited")
                return False

            self._last_unlock_attempt = now

            logger.info("Triggering KeePassXC database unlock...")
            client = BrowserClient(self.browser_config)
            try:
                # In keepassxc-browser-api >= 1.5, ensure_unlocked() returns None
                # and signals failure by raising a KeePassXCError subclass.
                client.ensure_unlocked()
            except KeePassXCError as e:
                logger.warning("Database unlock failed or was cancelled: %s", e)
                return False

            logger.info("Database unlocked, waiting for keys to load into ssh-agent")
            return True
