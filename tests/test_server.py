"""Tests for the SSH agent proxy server."""

import os
import socket
import struct
import threading
import time
from unittest.mock import patch, MagicMock

from keepassxc_ssh_agent import ssh_agent_protocol as proto
from keepassxc_ssh_agent.config import Association, Config
from keepassxc_ssh_agent.server import SSHAgentProxy


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
            associations={"hash": Association("id", "ipk", "isk")},
        )
        proxy = SSHAgentProxy(config)

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
            associations={"hash": Association("id", "ipk", "isk")},
        )
        proxy = SSHAgentProxy(config)
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
            associations={"hash": Association("id", "ipk", "isk")},
        )
        proxy = SSHAgentProxy(config)
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
        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/test-agent.sock")

        config = Config(
            socket_path="/tmp/test-proxy.sock",
            associations={"hash": Association("id", "ipk", "isk")},
        )
        proxy = SSHAgentProxy(config)
        proxy._unlock_cooldown = 1.0

        # Mock BrowserClient.ensure_unlocked to return False (no KeePassXC)
        with patch("keepassxc_ssh_agent.server.BrowserClient") as MockBC:
            mock_client = MagicMock()
            mock_client.ensure_unlocked.return_value = False
            MockBC.return_value = mock_client

            # First attempt should proceed
            result1 = proxy._try_unlock()
            assert result1 is False
            assert mock_client.ensure_unlocked.call_count == 1

            # Second attempt immediately should be rate-limited (no call to ensure_unlocked)
            result2 = proxy._try_unlock()
            assert result2 is False
            assert mock_client.ensure_unlocked.call_count == 1  # Not called again
