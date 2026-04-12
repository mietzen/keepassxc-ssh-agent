"""Tests for configuration persistence."""

import json
import os
import stat
from pathlib import Path

from keepassxc_ssh_agent.config import (
    Config,
    DEFAULT_SOCKET_PATH,
    DEFAULT_BROWSER_API_CONFIG_PATH,
)


class TestConfig:
    def test_defaults(self):
        c = Config()
        assert c.socket_path == str(DEFAULT_SOCKET_PATH)
        assert c.system_agent_path == ""
        assert c.browser_api_config_path == str(DEFAULT_BROWSER_API_CONFIG_PATH)

    def test_to_dict(self):
        c = Config(
            socket_path="/tmp/test.sock",
            system_agent_path="/tmp/sys.sock",
            browser_api_config_path="/tmp/browser-api.json",
        )
        d = c.to_dict()
        assert d["socket_path"] == "/tmp/test.sock"
        assert d["system_agent_path"] == "/tmp/sys.sock"
        assert d["browser_api_config_path"] == "/tmp/browser-api.json"

    def test_to_dict_omits_empty_system_path(self):
        c = Config(socket_path="/tmp/test.sock")
        d = c.to_dict()
        assert "system_agent_path" not in d

    def test_from_dict(self):
        d = {
            "socket_path": "/tmp/test.sock",
            "system_agent_path": "/tmp/sys.sock",
            "browser_api_config_path": "/tmp/browser.json",
        }
        c = Config.from_dict(d)
        assert c.socket_path == "/tmp/test.sock"
        assert c.system_agent_path == "/tmp/sys.sock"
        assert c.browser_api_config_path == "/tmp/browser.json"

    def test_from_dict_defaults(self):
        c = Config.from_dict({})
        assert c.socket_path == str(DEFAULT_SOCKET_PATH)
        assert c.system_agent_path == ""

    def test_roundtrip(self):
        c = Config(
            socket_path="/tmp/x.sock",
            system_agent_path="/tmp/sys.sock",
        )
        c2 = Config.from_dict(c.to_dict())
        assert c2.socket_path == c.socket_path
        assert c2.system_agent_path == c.system_agent_path


class TestConfigPersistence:
    def test_save_and_load(self, tmp_path):
        config_path = tmp_path / "test-config.json"
        c = Config(
            socket_path="/tmp/test.sock",
            system_agent_path="/tmp/sys.sock",
        )
        c.save(config_path)

        loaded = Config.load(config_path)
        assert loaded.socket_path == "/tmp/test.sock"
        assert loaded.system_agent_path == "/tmp/sys.sock"

    def test_save_permissions(self, tmp_path):
        config_path = tmp_path / "test-config.json"
        Config().save(config_path)
        mode = os.stat(config_path).st_mode
        assert mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR

    def test_load_nonexistent(self, tmp_path):
        config_path = tmp_path / "nonexistent.json"
        c = Config.load(config_path)
        assert c.socket_path == str(DEFAULT_SOCKET_PATH)

    def test_save_creates_parent_dirs(self, tmp_path):
        config_path = tmp_path / "sub" / "dir" / "config.json"
        Config().save(config_path)
        assert config_path.exists()

    def test_save_valid_json(self, tmp_path):
        config_path = tmp_path / "test.json"
        Config(socket_path="/tmp/s.sock").save(config_path)
        with open(config_path) as f:
            data = json.load(f)
        assert data["socket_path"] == "/tmp/s.sock"

