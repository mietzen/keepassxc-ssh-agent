"""Integration tests against a real KeePassXC instance.

These tests require KeePassXC to be running with browser integration enabled.
They are skipped in normal test runs and only executed in CI with the
--run-integration flag or when KEEPASSXC_INTEGRATION_TEST=1 is set.

These tests validate that the browser extension protocol still works with
the current version of KeePassXC (change-public-keys handshake).
"""

import os
import socket
import tempfile

import pytest

# Skip unless explicitly enabled
pytestmark = pytest.mark.skipif(
    os.environ.get("KEEPASSXC_INTEGRATION_TEST") != "1",
    reason="Integration tests require KEEPASSXC_INTEGRATION_TEST=1 and a running KeePassXC",
)


def _get_keepassxc_socket_path() -> str:
    """Get the KeePassXC browser extension socket path."""
    # On Linux CI (Ubuntu), the path differs from macOS
    if os.environ.get("XDG_RUNTIME_DIR"):
        xdg = os.environ["XDG_RUNTIME_DIR"]
        # New-style path (KeePassXC >= 2.7.x)
        new_path = os.path.join(xdg, "app", "org.keepassxc.KeePassXC", "org.keepassxc.KeePassXC.BrowserServer")
        if os.path.exists(new_path):
            return new_path
        # Legacy path
        legacy_path = os.path.join(xdg, "org.keepassxc.KeePassXC.BrowserServer")
        if os.path.exists(legacy_path):
            return legacy_path
    # macOS
    tmpdir = tempfile.gettempdir()
    return os.path.join(tmpdir, "org.keepassxc.KeePassXC.BrowserServer")


class TestKeePassXCConnection:
    """Tests that require a running KeePassXC with browser integration."""

    def test_socket_exists(self):
        """Verify that the KeePassXC browser socket exists."""
        path = _get_keepassxc_socket_path()
        assert os.path.exists(path), (
            f"KeePassXC browser socket not found at {path}. "
            "Is KeePassXC running with browser integration enabled?"
        )

    def test_can_connect(self):
        """Verify that we can connect to the browser socket."""
        path = _get_keepassxc_socket_path()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(path)
        finally:
            sock.close()

    def test_key_exchange(self):
        """Test the NaCl key exchange (change-public-keys) with KeePassXC.

        This is the most fundamental protocol operation and validates that:
        1. KeePassXC accepts connections on the browser socket
        2. The JSON message format is correct
        3. The NaCl key exchange succeeds
        4. KeePassXC responds with a valid public key
        """
        from keepassxc_ssh_agent.browser_client import BrowserClient
        from keepassxc_ssh_agent.config import Config

        config = Config()
        client = BrowserClient(config)

        # Connect directly using the detected path
        path = _get_keepassxc_socket_path()
        client._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client._socket.settimeout(5.0)
        client._socket.connect(path)

        try:
            result = client.change_public_keys()
            assert result is True, "Key exchange with KeePassXC failed"
            assert client._server_public_key is not None
        finally:
            client.disconnect()

    def test_get_databasehash_locked(self):
        """Test get-databasehash against a locked database.

        With the test database locked, this should return an error
        (DATABASE_NOT_OPENED), which validates the encrypted message flow.
        """
        from keepassxc_ssh_agent.browser_client import BrowserClient
        from keepassxc_ssh_agent.config import Config

        config = Config()
        client = BrowserClient(config)

        path = _get_keepassxc_socket_path()
        client._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client._socket.settimeout(5.0)
        client._socket.connect(path)

        try:
            assert client.change_public_keys() is True

            # Send get-databasehash without triggerUnlock
            # If DB is locked: returns errorCode "1"
            # If DB is unlocked: returns the hash
            # Either way, if we get a response the protocol works
            response = client._send_get_databasehash(trigger_unlock=False)
            assert response is not None, "No response from KeePassXC"

            # We should get either a success (hash) or DATABASE_NOT_OPENED error
            if "errorCode" in response:
                assert response["errorCode"] == "1", (
                    f"Unexpected error: {response.get('error')}"
                )
            # If no error, we got a valid hash response
        finally:
            client.disconnect()
