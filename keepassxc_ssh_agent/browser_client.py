"""KeePassXC browser extension protocol client.

Implements the NaCl-encrypted protocol used by the KeePassXC browser extension
to communicate with the KeePassXC application. Used to trigger database unlock.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
import tempfile

import nacl.exceptions
import nacl.public
import nacl.utils

from .config import Association, Config

logger = logging.getLogger(__name__)

# Unique client ID for this agent (KeePassXC requires this in every message)
CLIENT_ID = "keepassxc-ssh-agent"


def _get_keepassxc_socket_path() -> str:
    """Get the KeePassXC browser extension socket path (macOS)."""
    tmpdir = tempfile.gettempdir()
    return os.path.join(tmpdir, "org.keepassxc.KeePassXC.BrowserServer")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data)


def _increment_nonce(nonce: bytes) -> bytes:
    """Increment a nonce by 1 (little-endian), matching sodium_increment()."""
    n = bytearray(nonce)
    for i in range(len(n)):
        n[i] = (n[i] + 1) & 0xFF
        if n[i] != 0:
            break
    return bytes(n)


class BrowserClient:
    """Client for KeePassXC browser extension protocol."""

    def __init__(self, config: Config):
        self.config = config
        self._socket: socket.socket | None = None
        self._server_public_key: nacl.public.PublicKey | None = None

        # Load or generate client keypair
        if config.client_public_key and config.client_secret_key:
            sk_bytes = _b64decode(config.client_secret_key)
            self._secret_key = nacl.public.PrivateKey(sk_bytes)
            self._public_key = self._secret_key.public_key
        else:
            self._secret_key = nacl.public.PrivateKey.generate()
            self._public_key = self._secret_key.public_key
            config.client_public_key = _b64encode(bytes(self._public_key))
            config.client_secret_key = _b64encode(bytes(self._secret_key))

    def connect(self) -> bool:
        """Connect to KeePassXC browser extension socket."""
        path = _get_keepassxc_socket_path()
        try:
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.settimeout(5.0)
            self._socket.connect(path)
            logger.debug("Connected to KeePassXC at %s", path)
            return True
        except OSError as e:
            logger.error("Cannot connect to KeePassXC browser socket at %s: %s", path, e)
            self._socket = None
            return False

    def disconnect(self) -> None:
        """Close the connection and clear session state."""
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
            self._server_public_key = None

    def _send_json(self, msg: dict) -> dict | None:
        """Send a JSON message and read the JSON response."""
        if not self._socket:
            return None

        # KeePassXC requires clientID in every message
        msg["clientID"] = CLIENT_ID

        data = json.dumps(msg).encode("utf-8")
        try:
            self._socket.sendall(data)
        except OSError as e:
            logger.error("Failed to send message: %s", e)
            return None

        # Read response
        try:
            # Set a longer timeout for responses that may involve user interaction
            self._socket.settimeout(self.config.unlock_timeout)
            response_data = self._socket.recv(1024 * 1024)
            if not response_data:
                return None
            return json.loads(response_data)
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Failed to read response: %s", e)
            return None

    def _encrypt(self, message: dict, nonce: bytes) -> str:
        """Encrypt a JSON message using NaCl crypto_box."""
        if not self._server_public_key:
            raise RuntimeError("No server public key (call change_public_keys first)")

        box = nacl.public.Box(self._secret_key, self._server_public_key)
        plaintext = json.dumps(message).encode("utf-8")
        encrypted = box.encrypt(plaintext, nonce)
        # crypto_box_easy output is nonce + ciphertext, but we pass nonce separately
        # Box.encrypt returns nonce + mac + ciphertext; we need just mac + ciphertext
        ciphertext = encrypted.ciphertext  # This is mac + ciphertext (no nonce prefix)
        return _b64encode(ciphertext)

    def _decrypt(self, encrypted_b64: str, nonce: bytes) -> dict | None:
        """Decrypt a NaCl-encrypted message."""
        if not self._server_public_key:
            return None

        box = nacl.public.Box(self._secret_key, self._server_public_key)
        try:
            ciphertext = _b64decode(encrypted_b64)
            plaintext = box.decrypt(ciphertext, nonce)
            return json.loads(plaintext)
        except (nacl.exceptions.CryptoError, json.JSONDecodeError, ValueError) as e:
            logger.error("Failed to decrypt message: %s", e)
            return None

    def change_public_keys(self) -> bool:
        """Perform NaCl key exchange with KeePassXC."""
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        msg = {
            "action": "change-public-keys",
            "publicKey": _b64encode(bytes(self._public_key)),
            "nonce": _b64encode(nonce),
        }

        response = self._send_json(msg)
        if not response:
            logger.error("No response to change-public-keys")
            return False

        if "errorCode" in response:
            logger.error("Key exchange failed: %s", response.get("error"))
            return False

        server_pk_b64 = response.get("publicKey")
        if not server_pk_b64:
            logger.error("No server public key in response")
            return False

        self._server_public_key = nacl.public.PublicKey(_b64decode(server_pk_b64))
        logger.debug("Key exchange successful")
        return True

    def associate(self) -> Association | None:
        """Associate with KeePassXC (one-time, requires user approval).

        Returns the Association on success, or None on failure.
        """
        # Generate an identity keypair for this association
        id_key = nacl.public.PrivateKey.generate()
        id_public_key = id_key.public_key

        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        inner = {
            "action": "associate",
            "key": _b64encode(bytes(self._public_key)),
            "idKey": _b64encode(bytes(id_public_key)),
        }

        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": "associate",
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }

        # Longer timeout for user approval
        old_timeout = self._socket.gettimeout() if self._socket else 30
        if self._socket:
            self._socket.settimeout(120)

        response = self._send_json(msg)

        if self._socket:
            self._socket.settimeout(old_timeout)

        if not response or "errorCode" in response:
            logger.error("Association failed: %s", response.get("error") if response else "no response")
            return None

        # Decrypt the response
        resp_nonce = _b64decode(response.get("nonce", ""))
        resp_message = response.get("message", "")
        if not resp_message:
            logger.error("No encrypted message in associate response")
            return None

        decrypted = self._decrypt(resp_message, resp_nonce)
        if not decrypted:
            logger.error("Failed to decrypt associate response")
            return None

        assoc_id = decrypted.get("id")
        db_hash = decrypted.get("hash")
        if not assoc_id:
            logger.error("No association ID in response")
            return None

        association = Association(
            id=assoc_id,
            id_key=_b64encode(bytes(id_public_key)),
            key=_b64encode(bytes(id_key)),
        )

        # Store keyed by database hash
        if db_hash:
            self.config.associations[db_hash] = association

        logger.info("Associated with KeePassXC (id=%s)", assoc_id)
        return association

    def test_associate(self, association: Association) -> bool:
        """Test if an existing association is still valid."""
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        inner = {
            "action": "test-associate",
            "id": association.id,
            "key": association.id_key,
        }

        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": "test-associate",
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }

        response = self._send_json(msg)
        if not response or "errorCode" in response:
            logger.debug("test-associate failed: %s", response.get("error") if response else "no response")
            return False

        return True

    def _send_get_databasehash(self, trigger_unlock: bool = False) -> dict | None:
        """Send a get-databasehash request.

        Returns the response dict, or None on communication error.
        """
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        inner = {"action": "get-databasehash"}

        encrypted = self._encrypt(inner, nonce)
        msg = {
            "action": "get-databasehash",
            "message": encrypted,
            "nonce": _b64encode(nonce),
        }
        if trigger_unlock:
            msg["triggerUnlock"] = "true"

        return self._send_json(msg)

    def trigger_unlock(self) -> bool:
        """Trigger KeePassXC database unlock via get-databasehash with triggerUnlock.

        The first request triggers the unlock dialog and returns immediately with
        DATABASE_NOT_OPENED. We then poll with regular get-databasehash requests
        until the DB is unlocked or the timeout expires.

        Returns True if the database is now unlocked.
        """
        import time

        # First request: trigger the unlock dialog
        logger.debug("Sending get-databasehash with triggerUnlock=true")
        response = self._send_get_databasehash(trigger_unlock=True)

        if not response:
            logger.error("No response to unlock trigger")
            return False

        # Check if DB was already unlocked
        if "errorCode" not in response:
            logger.info("Database was already unlocked")
            return True

        error_code = response.get("errorCode")
        if error_code != "1":
            # Unexpected error (not DATABASE_NOT_OPENED)
            logger.error("Unlock failed: %s (code %s)", response.get("error"), error_code)
            return False

        # DB is locked, unlock dialog should now be showing.
        # Poll until the DB is unlocked or timeout.
        logger.info("Unlock dialog triggered, waiting for user to authenticate...")
        deadline = time.monotonic() + self.config.unlock_timeout
        poll_interval = 1.0

        while time.monotonic() < deadline:
            time.sleep(poll_interval)

            # Reconnect for each poll since the previous connection's
            # BrowserAction state may be stale
            self.disconnect()
            if not self.connect():
                continue
            if not self.change_public_keys():
                continue

            response = self._send_get_databasehash(trigger_unlock=False)
            if not response:
                continue

            if "errorCode" not in response:
                logger.info("Database unlocked successfully")
                return True

            # Still locked, keep waiting
            logger.debug("Still locked, polling...")

        logger.warning("Timeout waiting for database unlock")
        return False

    def ensure_unlocked(self) -> bool:
        """Connect to KeePassXC and ensure the database is unlocked.

        Handles the full flow: connect, key exchange, trigger unlock.
        Returns True if the database is now unlocked.
        """
        if not self.config.associations:
            logger.warning("No associations configured. Run 'keepassxc-ssh-agent setup' first.")
            return False

        if not self.connect():
            return False

        try:
            # Step 1: Key exchange (always needed for a new connection)
            if not self.change_public_keys():
                return False

            # Step 2: Trigger unlock directly via get-databasehash with triggerUnlock.
            # We skip test_associate here because when the DB is locked,
            # KeePassXC requires the DB to be open before it can verify
            # an association (it checks the stored key in the database).
            # get-databasehash with triggerUnlock will prompt for TouchID/unlock
            # and only requires the key exchange to be done.
            return self.trigger_unlock()
        finally:
            self.disconnect()

    def setup(self) -> bool:
        """Perform initial setup: connect, key exchange, and associate.

        Returns True on success.
        """
        if not self.connect():
            return False

        try:
            if not self.change_public_keys():
                return False

            print("Requesting association with KeePassXC...")
            print("Please approve the association in the KeePassXC window.")

            association = self.associate()
            if not association:
                return False

            print(f"Association successful! ID: {association.id}")
            return True
        finally:
            self.disconnect()
