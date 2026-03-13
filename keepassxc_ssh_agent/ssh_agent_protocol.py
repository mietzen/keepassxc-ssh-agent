"""SSH agent protocol wire format parsing and serialization.

Implements the client/server side of the SSH agent protocol as described in
draft-miller-ssh-agent. Messages are framed as:
    [4 bytes big-endian length][message bytes]

The first byte of the message is the message type.
"""

from __future__ import annotations

import logging
import socket
import struct

logger = logging.getLogger(__name__)

# SSH agent message types
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_ADD_IDENTITY = 17
SSH_AGENTC_REMOVE_IDENTITY = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
SSH_AGENTC_ADD_ID_CONSTRAINED = 25
SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6


def read_message(sock: socket.socket) -> bytes | None:
    """Read a length-prefixed SSH agent message from a socket.

    Returns the message bytes (without the length prefix), or None on error.
    """
    # Read 4-byte length header
    header = _recv_exact(sock, 4)
    if header is None:
        return None

    (length,) = struct.unpack(">I", header)
    if length == 0 or length > 256 * 1024:
        logger.warning("Invalid message length: %d", length)
        return None

    data = _recv_exact(sock, length)
    return data


def write_message(sock: socket.socket, data: bytes) -> bool:
    """Write a length-prefixed SSH agent message to a socket.

    Returns True on success.
    """
    header = struct.pack(">I", len(data))
    try:
        sock.sendall(header + data)
        return True
    except OSError as e:
        logger.error("Failed to write message: %s", e)
        return False


def make_failure_response() -> bytes:
    """Create an SSH_AGENT_FAILURE message."""
    return bytes([SSH_AGENT_FAILURE])


def make_empty_identities_response() -> bytes:
    """Create an SSH_AGENT_IDENTITIES_ANSWER with zero keys."""
    # type byte + 4-byte count (0)
    return bytes([SSH_AGENT_IDENTITIES_ANSWER]) + struct.pack(">I", 0)


def get_message_type(data: bytes) -> int | None:
    """Get the message type byte from a message."""
    if not data:
        return None
    return data[0]


def forward_to_agent(agent_sock_path: str, request: bytes) -> bytes | None:
    """Forward a message to the system SSH agent and return the response.

    Returns None if the agent is not available.
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(agent_sock_path)
        try:
            if not write_message(sock, request):
                return None
            return read_message(sock)
        finally:
            sock.close()
    except OSError as e:
        logger.debug("Cannot connect to system SSH agent at %s: %s", agent_sock_path, e)
        return None


def is_failure_response(data: bytes) -> bool:
    """Check if a response is SSH_AGENT_FAILURE."""
    return len(data) >= 1 and data[0] == SSH_AGENT_FAILURE


def is_empty_identities(data: bytes) -> bool:
    """Check if a response is an identities answer with zero keys."""
    if len(data) < 5 or data[0] != SSH_AGENT_IDENTITIES_ANSWER:
        return False
    (count,) = struct.unpack(">I", data[1:5])
    return count == 0


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes from a socket."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)
