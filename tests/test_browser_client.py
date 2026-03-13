"""Tests for the KeePassXC browser protocol client."""

import base64
import json
import socket
import threading

import nacl.public
import nacl.utils

from keepassxc_ssh_agent.browser_client import (
    BrowserClient,
    _b64encode,
    _b64decode,
    _increment_nonce,
    CLIENT_ID,
)
from keepassxc_ssh_agent.config import Association, Config


class TestHelpers:
    def test_b64_roundtrip(self):
        data = b"\x00\x01\x02\xff"
        assert _b64decode(_b64encode(data)) == data

    def test_b64encode_ascii(self):
        result = _b64encode(b"hello")
        assert isinstance(result, str)
        assert result == base64.b64encode(b"hello").decode("ascii")

    def test_increment_nonce_simple(self):
        nonce = b"\x00" * 24
        result = _increment_nonce(nonce)
        assert result[0] == 1
        assert result[1:] == b"\x00" * 23

    def test_increment_nonce_carry(self):
        nonce = b"\xff" + b"\x00" * 23
        result = _increment_nonce(nonce)
        assert result[0] == 0
        assert result[1] == 1
        assert result[2:] == b"\x00" * 22

    def test_increment_nonce_all_ff(self):
        nonce = b"\xff" * 24
        result = _increment_nonce(nonce)
        assert result == b"\x00" * 24


class TestBrowserClientInit:
    def test_generates_keypair(self):
        config = Config()
        client = BrowserClient(config)
        assert config.client_public_key != ""
        assert config.client_secret_key != ""

    def test_loads_existing_keypair(self):
        sk = nacl.public.PrivateKey.generate()
        pk = sk.public_key
        config = Config(
            client_public_key=_b64encode(bytes(pk)),
            client_secret_key=_b64encode(bytes(sk)),
        )
        client = BrowserClient(config)
        assert bytes(client._public_key) == bytes(pk)

    def test_keypair_consistency(self):
        config = Config()
        client1 = BrowserClient(config)
        pk1 = config.client_public_key
        sk1 = config.client_secret_key

        # Creating a second client with same config should use same keys
        client2 = BrowserClient(config)
        assert config.client_public_key == pk1
        assert config.client_secret_key == sk1


class TestBrowserClientConnect:
    def test_connect_nonexistent_socket(self):
        config = Config()
        client = BrowserClient(config)
        # Monkey-patch to use a nonexistent path
        import keepassxc_ssh_agent.browser_client as bc
        original = bc._get_keepassxc_socket_path
        bc._get_keepassxc_socket_path = lambda: "/tmp/nonexistent-keepassxc-test.sock"
        try:
            assert client.connect() is False
        finally:
            bc._get_keepassxc_socket_path = original

    def test_disconnect_when_not_connected(self):
        config = Config()
        client = BrowserClient(config)
        # Should not raise
        client.disconnect()


class MockKeePassXC:
    """A minimal mock of KeePassXC's browser extension socket server.

    Handles change-public-keys and responds to encrypted messages.
    """

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(sock_path)
        self._server.listen(1)
        self._server.settimeout(5.0)
        self._sk = nacl.public.PrivateKey.generate()
        self._pk = self._sk.public_key
        self._client_pk = None
        self._thread = None
        self.received_messages = []
        self.responses = []  # Queue of response dicts to send

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            conn, _ = self._server.accept()
            conn.settimeout(5.0)
            while True:
                try:
                    data = conn.recv(1024 * 1024)
                    if not data:
                        break
                    msg = json.loads(data)
                    self.received_messages.append(msg)

                    if msg.get("action") == "change-public-keys":
                        self._client_pk = nacl.public.PublicKey(
                            _b64decode(msg["publicKey"])
                        )
                        response = {
                            "action": "change-public-keys",
                            "publicKey": _b64encode(bytes(self._pk)),
                            "nonce": msg["nonce"],
                            "version": "2.7.0",
                            "success": "true",
                        }
                        conn.sendall(json.dumps(response).encode())
                    elif self.responses:
                        response = self.responses.pop(0)
                        conn.sendall(json.dumps(response).encode())
                    else:
                        conn.sendall(json.dumps({"error": "no mock response"}).encode())
                except (OSError, json.JSONDecodeError):
                    break
            conn.close()
        except socket.timeout:
            pass
        finally:
            self._server.close()

    def stop(self):
        self._server.close()
        if self._thread:
            self._thread.join(timeout=2.0)


class TestKeyExchange:
    def test_change_public_keys(self, short_tmp):
        sock_path = short_tmp + "/kp.sock"
        mock = MockKeePassXC(sock_path)
        mock.start()

        config = Config()
        client = BrowserClient(config)

        # Connect directly to the mock socket
        client._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client._socket.settimeout(5.0)
        client._socket.connect(sock_path)

        assert client.change_public_keys() is True
        assert client._server_public_key is not None

        # Verify clientID was sent
        assert mock.received_messages[0].get("clientID") == CLIENT_ID

        client.disconnect()

    def test_change_public_keys_error_response(self, short_tmp):
        sock_path = short_tmp + "/kp.sock"

        # Create a server that returns an error
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(1)
        server.settimeout(5.0)

        def error_server():
            conn, _ = server.accept()
            conn.settimeout(2.0)
            conn.recv(65536)
            conn.sendall(json.dumps({"errorCode": "1", "error": "test error"}).encode())
            conn.close()
            server.close()

        t = threading.Thread(target=error_server, daemon=True)
        t.start()

        config = Config()
        client = BrowserClient(config)
        client._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client._socket.settimeout(5.0)
        client._socket.connect(sock_path)

        assert client.change_public_keys() is False
        client.disconnect()
        t.join(timeout=2.0)


class TestEncryptDecrypt:
    def test_encrypt_decrypt_roundtrip(self):
        # Set up two clients to test crypto
        server_sk = nacl.public.PrivateKey.generate()
        server_pk = server_sk.public_key

        config = Config()
        client = BrowserClient(config)
        client._server_public_key = server_pk

        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        message = {"action": "test", "data": "hello"}

        encrypted = client._encrypt(message, nonce)
        assert isinstance(encrypted, str)  # base64

        # Decrypt with the server's key
        box = nacl.public.Box(server_sk, client._public_key)
        ciphertext = _b64decode(encrypted)
        plaintext = box.decrypt(ciphertext, nonce)
        decrypted = json.loads(plaintext)
        assert decrypted == message

    def test_decrypt_from_server(self):
        server_sk = nacl.public.PrivateKey.generate()
        server_pk = server_sk.public_key

        config = Config()
        client = BrowserClient(config)
        client._server_public_key = server_pk

        # Server encrypts a message
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        box = nacl.public.Box(server_sk, client._public_key)
        message = {"hash": "abc123", "id": "test"}
        plaintext = json.dumps(message).encode()
        encrypted = box.encrypt(plaintext, nonce)
        encrypted_b64 = _b64encode(encrypted.ciphertext)

        result = client._decrypt(encrypted_b64, nonce)
        assert result == message

    def test_encrypt_without_server_key_raises(self):
        config = Config()
        client = BrowserClient(config)
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        try:
            client._encrypt({"test": True}, nonce)
            assert False, "Should have raised RuntimeError"
        except RuntimeError:
            pass

    def test_decrypt_without_server_key(self):
        config = Config()
        client = BrowserClient(config)
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        assert client._decrypt("dGVzdA==", nonce) is None

    def test_decrypt_invalid_ciphertext(self):
        server_sk = nacl.public.PrivateKey.generate()
        config = Config()
        client = BrowserClient(config)
        client._server_public_key = server_sk.public_key
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        assert client._decrypt("aW52YWxpZA==", nonce) is None
