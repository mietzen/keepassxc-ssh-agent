"""Tests for configuration persistence."""

import json
import os
import stat
from pathlib import Path

from keepassxc_ssh_agent.config import (
    Association,
    Config,
    DEFAULT_SOCKET_PATH,
    DEFAULT_UNLOCK_TIMEOUT,
)


class TestAssociation:
    def test_to_dict(self):
        a = Association(id="test-id", id_key="pubkey-b64", key="seckey-b64")
        d = a.to_dict()
        assert d == {"id": "test-id", "id_key": "pubkey-b64", "key": "seckey-b64"}

    def test_from_dict(self):
        d = {"id": "test-id", "id_key": "pubkey-b64", "key": "seckey-b64"}
        a = Association.from_dict(d)
        assert a.id == "test-id"
        assert a.id_key == "pubkey-b64"
        assert a.key == "seckey-b64"

    def test_roundtrip(self):
        a = Association(id="myid", id_key="pk", key="sk")
        a2 = Association.from_dict(a.to_dict())
        assert a == a2


class TestConfig:
    def test_defaults(self):
        c = Config()
        assert c.socket_path == str(DEFAULT_SOCKET_PATH)
        assert c.unlock_timeout == DEFAULT_UNLOCK_TIMEOUT
        assert c.client_public_key == ""
        assert c.client_secret_key == ""
        assert c.associations == {}

    def test_to_dict(self):
        c = Config(
            socket_path="/tmp/test.sock",
            unlock_timeout=60,
            client_public_key="pk",
            client_secret_key="sk",
            associations={"hash1": Association("id1", "ipk1", "isk1")},
        )
        d = c.to_dict()
        assert d["socket_path"] == "/tmp/test.sock"
        assert d["unlock_timeout"] == 60
        assert d["associations"]["hash1"]["id"] == "id1"

    def test_from_dict(self):
        d = {
            "socket_path": "/tmp/test.sock",
            "unlock_timeout": 45,
            "client_public_key": "pk",
            "client_secret_key": "sk",
            "associations": {
                "hash1": {"id": "id1", "id_key": "ipk1", "key": "isk1"},
            },
        }
        c = Config.from_dict(d)
        assert c.socket_path == "/tmp/test.sock"
        assert c.unlock_timeout == 45
        assert "hash1" in c.associations
        assert c.associations["hash1"].id == "id1"

    def test_from_dict_defaults(self):
        c = Config.from_dict({})
        assert c.socket_path == str(DEFAULT_SOCKET_PATH)
        assert c.unlock_timeout == DEFAULT_UNLOCK_TIMEOUT
        assert c.associations == {}

    def test_roundtrip(self):
        c = Config(
            socket_path="/tmp/x.sock",
            unlock_timeout=10,
            client_public_key="cpk",
            client_secret_key="csk",
            associations={"h": Association("i", "ip", "is")},
        )
        c2 = Config.from_dict(c.to_dict())
        assert c2.socket_path == c.socket_path
        assert c2.unlock_timeout == c.unlock_timeout
        assert c2.client_public_key == c.client_public_key
        assert c2.associations["h"].id == "i"


class TestConfigPersistence:
    def test_save_and_load(self, tmp_path):
        config_path = tmp_path / "test-config.json"
        c = Config(
            socket_path="/tmp/test.sock",
            client_public_key="pk",
            client_secret_key="sk",
            associations={"hash": Association("id", "ipk", "isk")},
        )
        c.save(config_path)

        loaded = Config.load(config_path)
        assert loaded.socket_path == "/tmp/test.sock"
        assert loaded.client_public_key == "pk"
        assert "hash" in loaded.associations

    def test_save_permissions(self, tmp_path):
        config_path = tmp_path / "test-config.json"
        Config().save(config_path)
        mode = os.stat(config_path).st_mode
        # Should be owner read/write only (0o600)
        assert mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR

    def test_load_nonexistent(self, tmp_path):
        config_path = tmp_path / "nonexistent.json"
        c = Config.load(config_path)
        # Should return defaults
        assert c.socket_path == str(DEFAULT_SOCKET_PATH)
        assert c.associations == {}

    def test_save_creates_parent_dirs(self, tmp_path):
        config_path = tmp_path / "sub" / "dir" / "config.json"
        Config().save(config_path)
        assert config_path.exists()

    def test_save_valid_json(self, tmp_path):
        config_path = tmp_path / "test.json"
        Config(client_public_key="test").save(config_path)
        with open(config_path) as f:
            data = json.load(f)
        assert data["client_public_key"] == "test"
