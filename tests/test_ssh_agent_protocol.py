"""Tests for SSH agent protocol wire format parsing."""

import socket
import struct
import threading

from keepassxc_ssh_agent import ssh_agent_protocol as proto


class TestMessageTypes:
    def test_get_message_type(self):
        assert proto.get_message_type(bytes([11])) == 11
        assert proto.get_message_type(bytes([5])) == 5

    def test_get_message_type_empty(self):
        assert proto.get_message_type(b"") is None


class TestFailureResponse:
    def test_make_failure_response(self):
        resp = proto.make_failure_response()
        assert resp == bytes([proto.SSH_AGENT_FAILURE])

    def test_is_failure_response(self):
        assert proto.is_failure_response(bytes([proto.SSH_AGENT_FAILURE]))
        assert not proto.is_failure_response(bytes([proto.SSH_AGENT_SUCCESS]))
        assert not proto.is_failure_response(b"")


class TestEmptyIdentities:
    def test_make_empty_identities(self):
        resp = proto.make_empty_identities_response()
        assert resp[0] == proto.SSH_AGENT_IDENTITIES_ANSWER
        assert struct.unpack(">I", resp[1:5]) == (0,)

    def test_is_empty_identities(self):
        empty = proto.make_empty_identities_response()
        assert proto.is_empty_identities(empty)

    def test_is_empty_identities_with_keys(self):
        # Identities answer with count=1 (not empty)
        data = bytes([proto.SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 1)
        assert not proto.is_empty_identities(data)

    def test_is_empty_identities_wrong_type(self):
        data = bytes([proto.SSH_AGENT_FAILURE]) + struct.pack(">I", 0)
        assert not proto.is_empty_identities(data)

    def test_is_empty_identities_too_short(self):
        assert not proto.is_empty_identities(bytes([proto.SSH_AGENT_IDENTITIES_ANSWER]))


class TestReadWriteMessage:
    """Test read_message/write_message over a real Unix socket pair."""

    def _socket_pair(self):
        """Create a connected pair of Unix sockets."""
        s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        s1.settimeout(2.0)
        s2.settimeout(2.0)
        return s1, s2

    def test_roundtrip(self):
        s1, s2 = self._socket_pair()
        try:
            payload = b"\x0b"  # REQUEST_IDENTITIES
            assert proto.write_message(s1, payload)
            result = proto.read_message(s2)
            assert result == payload
        finally:
            s1.close()
            s2.close()

    def test_roundtrip_large_message(self):
        s1, s2 = self._socket_pair()
        try:
            payload = bytes([proto.SSH_AGENTC_SIGN_REQUEST]) + b"\x00" * 4096
            assert proto.write_message(s1, payload)
            result = proto.read_message(s2)
            assert result == payload
        finally:
            s1.close()
            s2.close()

    def test_read_closed_socket(self):
        s1, s2 = self._socket_pair()
        s1.close()
        result = proto.read_message(s2)
        assert result is None
        s2.close()

    def test_read_invalid_length(self):
        s1, s2 = self._socket_pair()
        try:
            # Send a zero-length message (invalid)
            s1.sendall(struct.pack(">I", 0))
            result = proto.read_message(s2)
            assert result is None
        finally:
            s1.close()
            s2.close()

    def test_read_oversized_length(self):
        s1, s2 = self._socket_pair()
        try:
            # Send length > 256KB (rejected)
            s1.sendall(struct.pack(">I", 512 * 1024))
            result = proto.read_message(s2)
            assert result is None
        finally:
            s1.close()
            s2.close()


class TestForwardToAgent:
    """Test forwarding to a mock SSH agent."""

    def test_forward_roundtrip(self, short_tmp):
        """Spawn a simple echo agent and forward a message to it."""
        sock_path = short_tmp + "/a.sock"

        # Create a mock agent that echoes back an identities answer
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)
        server.settimeout(2.0)

        response_data = proto.make_empty_identities_response()

        def mock_agent():
            conn, _ = server.accept()
            conn.settimeout(2.0)
            msg = proto.read_message(conn)
            if msg is not None:
                proto.write_message(conn, response_data)
            conn.close()

        t = threading.Thread(target=mock_agent, daemon=True)
        t.start()

        request = bytes([proto.SSH_AGENTC_REQUEST_IDENTITIES])
        result = proto.forward_to_agent(sock_path, request)
        assert result == response_data

        t.join(timeout=2.0)
        server.close()

    def test_forward_to_nonexistent_socket(self):
        result = proto.forward_to_agent("/tmp/nonexistent-agent.sock", b"\x0b")
        assert result is None
