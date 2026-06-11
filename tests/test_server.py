"""Tests for the SSH agent proxy server."""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from unittest.mock import patch, MagicMock

from keepassxc_ssh_agent import ssh_agent_protocol as proto
from keepassxc_ssh_agent.config import Config
from keepassxc_ssh_agent.server import SSHAgentProxy
from keepassxc_browser_api import BrowserConfig
from keepassxc_browser_api.config import Association


def _make_browser_config() -> BrowserConfig:
    """Return a BrowserConfig with a fake association for testing."""
    bc = BrowserConfig()
    bc.associations["hash"] = Association(id="id", id_key="ipk", key="isk")
    return bc


def _make_mock_agent(sock_path: str, responses: dict):
    """Create a mock ssh-agent that returns canned responses.

    responses: dict mapping request message type (int) to response bytes.
    """
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(5)
    server.settimeout(5.0)

    def run():
        while True:
            try:
                conn, _ = server.accept()
                conn.settimeout(2.0)
            except socket.timeout:
                break
            try:
                msg = proto.read_message(conn)
                if msg is not None:
                    msg_type = proto.get_message_type(msg)
                    response = responses.get(msg_type, proto.make_failure_response())
                    proto.write_message(conn, response)
                conn.close()
            except OSError:
                pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return server, t


class TestSSHAgentProxy:
    def test_proxy_forwards_identities(self, short_tmp, monkeypatch):
        """Test that proxy forwards REQUEST_IDENTITIES to system agent."""
        agent_sock = short_tmp + "/a.sock"
        proxy_sock = short_tmp + "/p.sock"

        # Create mock system agent with some identities
        identities_response = (
            bytes([proto.SSH_AGENT_IDENTITIES_ANSWER])
            + struct.pack(">I", 1)  # 1 key
            + struct.pack(">I", 4) + b"key1"  # key blob
            + struct.pack(">I", 5) + b"test1"  # comment
        )
        agent_server, agent_thread = _make_mock_agent(
            agent_sock,
            {proto.SSH_AGENTC_REQUEST_IDENTITIES: identities_response},
        )

        monkeypatch.setenv("SSH_AUTH_SOCK", agent_sock)

        config = Config(
            socket_path=proxy_sock,
        )
        browser_config = _make_browser_config()
        proxy = SSHAgentProxy(config, browser_config)

        # Start proxy in a thread
        proxy_thread = threading.Thread(target=proxy.start, daemon=True)
        proxy_thread.start()
        time.sleep(0.3)  # Wait for proxy to start

        try:
            # Connect as SSH client
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(proxy_sock)

            # Send REQUEST_IDENTITIES
            request = bytes([proto.SSH_AGENTC_REQUEST_IDENTITIES])
            proto.write_message(client, request)

            response = proto.read_message(client)
            assert response is not None
            assert response[0] == proto.SSH_AGENT_IDENTITIES_ANSWER
            count = struct.unpack(">I", response[1:5])[0]
            assert count == 1

            client.close()
        finally:
            proxy.stop()
            agent_server.close()

    def test_proxy_returns_failure_when_agent_unavailable(self, short_tmp, monkeypatch):
        """Test proxy returns failure when system agent is not available."""
        proxy_sock = short_tmp + "/p.sock"

        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/nonexistent-agent.sock")

        config = Config(
            socket_path=proxy_sock,
        )
        browser_config = _make_browser_config()
        proxy = SSHAgentProxy(config, browser_config)
        proxy_thread = threading.Thread(target=proxy.start, daemon=True)
        proxy_thread.start()
        time.sleep(0.3)

        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect(proxy_sock)

            request = bytes([proto.SSH_AGENTC_REQUEST_IDENTITIES])
            proto.write_message(client, request)

            response = proto.read_message(client)
            assert response is not None
            assert proto.is_failure_response(response)

            client.close()
        finally:
            proxy.stop()

    def test_proxy_stop_cleans_socket(self, short_tmp, monkeypatch):
        """Test that stop() removes the socket file."""
        agent_sock = short_tmp + "/a.sock"
        proxy_sock = short_tmp + "/p.sock"

        monkeypatch.setenv("SSH_AUTH_SOCK", agent_sock)

        # Create a dummy agent socket so the env var is valid
        _make_mock_agent(agent_sock, {})

        config = Config(
            socket_path=proxy_sock,
        )
        browser_config = _make_browser_config()
        proxy = SSHAgentProxy(config, browser_config)
        proxy_thread = threading.Thread(target=proxy.start, daemon=True)
        proxy_thread.start()
        time.sleep(0.3)

        assert os.path.exists(proxy_sock)
        proxy.stop()
        time.sleep(0.3)
        assert not os.path.exists(proxy_sock)


class TestUnlockRateLimit:
    def test_rate_limiting(self, monkeypatch):
        """Test that unlock attempts are rate-limited."""
        from keepassxc_browser_api.exceptions import DatabaseLockedError

        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/test-agent.sock")

        config = Config(
            socket_path="/tmp/test-proxy.sock",
        )
        browser_config = _make_browser_config()
        proxy = SSHAgentProxy(config, browser_config)
        proxy._unlock_cooldown = 1.0

        # ensure_unlocked() raises on failure (lib >= 1.5)
        with patch("keepassxc_ssh_agent.server.BrowserClient") as MockBC:
            mock_client = MagicMock()
            mock_client.ensure_unlocked.side_effect = DatabaseLockedError("timeout")
            MockBC.return_value = mock_client

            # First attempt should proceed (exception caught -> False)
            result1 = proxy._try_unlock()
            assert result1 is False
            assert mock_client.ensure_unlocked.call_count == 1

            # Second attempt immediately should be rate-limited (no call to ensure_unlocked)
            result2 = proxy._try_unlock()
            assert result2 is False
            assert mock_client.ensure_unlocked.call_count == 1  # Not called again

    def test_success_returns_true(self, monkeypatch):
        """ensure_unlocked() returning None (no exception) means success."""
        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/test-agent.sock")

        config = Config(socket_path="/tmp/test-proxy.sock")
        proxy = SSHAgentProxy(config, _make_browser_config())

        with patch("keepassxc_ssh_agent.server.BrowserClient") as MockBC:
            mock_client = MagicMock()
            mock_client.ensure_unlocked.return_value = None
            MockBC.return_value = mock_client

            result = proxy._try_unlock()
            assert result is True
            assert mock_client.ensure_unlocked.call_count == 1


def _identities_response(count: int = 1) -> bytes:
    return (
        bytes([proto.SSH_AGENT_IDENTITIES_ANSWER])
        + struct.pack(">I", count)
        + struct.pack(">I", 4) + b"key1"
        + struct.pack(">I", 5) + b"test1"
    )


def _make_proxy() -> SSHAgentProxy:
    config = Config(socket_path="/tmp/test-proxy.sock")
    proxy = SSHAgentProxy(config, _make_browser_config(), system_agent_path="/tmp/agent.sock")
    proxy._key_poll_interval = 0.0  # don't actually sleep in tests
    return proxy


class TestPollAfterUnlock:
    def test_waits_for_identities_to_appear(self):
        """Polls until the agent returns a non-empty identity list."""
        proxy = _make_proxy()
        empty = proto.make_empty_identities_response()
        loaded = _identities_response()

        request = bytes([proto.SSH_AGENTC_REQUEST_IDENTITIES])
        with patch("keepassxc_ssh_agent.server.proto.forward_to_agent",
                   side_effect=[empty, empty, loaded]) as mock_fwd, \
                patch("keepassxc_ssh_agent.server.time.sleep"):
            result = proxy._poll_after_unlock(request, proto.SSH_AGENTC_REQUEST_IDENTITIES)

        assert result == loaded
        assert mock_fwd.call_count == 3

    def test_returns_last_response_on_deadline(self):
        """If the key never loads, return the last (empty) response and stop."""
        proxy = _make_proxy()
        empty = proto.make_empty_identities_response()

        request = bytes([proto.SSH_AGENTC_REQUEST_IDENTITIES])
        # monotonic: start at 0, then jump past the 5s deadline on the 2nd check
        with patch("keepassxc_ssh_agent.server.proto.forward_to_agent",
                   return_value=empty) as mock_fwd, \
                patch("keepassxc_ssh_agent.server.time.sleep"), \
                patch("keepassxc_ssh_agent.server.time.monotonic", side_effect=[0.0, 0.0, 99.0]):
            result = proxy._poll_after_unlock(request, proto.SSH_AGENTC_REQUEST_IDENTITIES)

        assert result == empty
        assert mock_fwd.call_count == 2

    def test_waits_for_successful_signature(self):
        """For a SIGN_REQUEST, polls until the agent stops returning failure."""
        proxy = _make_proxy()
        failure = proto.make_failure_response()
        sign_ok = bytes([proto.SSH_AGENT_SIGN_RESPONSE]) + struct.pack(">I", 3) + b"sig"

        request = bytes([proto.SSH_AGENTC_SIGN_REQUEST])
        with patch("keepassxc_ssh_agent.server.proto.forward_to_agent",
                   side_effect=[failure, sign_ok]) as mock_fwd, \
                patch("keepassxc_ssh_agent.server.time.sleep"):
            result = proxy._poll_after_unlock(request, proto.SSH_AGENTC_SIGN_REQUEST)

        assert result == sign_ok
        assert mock_fwd.call_count == 2
