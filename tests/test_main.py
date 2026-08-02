"""Tests for CLI entry point."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from keepassxc_ssh_agent.__main__ import (
    _ask_yes_no,
    _intercept_ssh_auth_sock,
    _restore_ssh_auth_sock,
    SYSTEM_SOCKET_SUFFIX,
)


class TestAskYesNo:
    def test_default_yes(self):
        with patch("builtins.input", return_value=""):
            assert _ask_yes_no("test?", default=True) is True

    def test_default_no(self):
        with patch("builtins.input", return_value=""):
            assert _ask_yes_no("test?", default=False) is False

    def test_explicit_yes(self):
        for answer in ("y", "Y", "yes", "YES", "Yes"):
            with patch("builtins.input", return_value=answer):
                assert _ask_yes_no("test?", default=False) is True

    def test_explicit_no(self):
        for answer in ("n", "N", "no", "NO", "anything"):
            with patch("builtins.input", return_value=answer):
                assert _ask_yes_no("test?", default=True) is False

    def test_eof_returns_default(self):
        with patch("builtins.input", side_effect=EOFError):
            assert _ask_yes_no("test?", default=True) is True
        with patch("builtins.input", side_effect=EOFError):
            assert _ask_yes_no("test?", default=False) is False

    def test_keyboard_interrupt_returns_default(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            assert _ask_yes_no("test?", default=True) is True


class TestInterceptSSHAuthSock:
    def test_normal_startup_renames_and_symlinks(self, short_tmp, monkeypatch):
        """Case 3: Real socket exists - rename to .system, symlink ours."""
        import socket as sock_mod

        from keepassxc_ssh_agent.config import Config

        real_sock = Path(short_tmp) / "Listeners"
        # Create a real Unix socket (not just a regular file)
        s = sock_mod.socket(sock_mod.AF_UNIX, sock_mod.SOCK_STREAM)
        s.bind(str(real_sock))
        s.close()
        proxy_sock = Path(short_tmp) / "proxy.sock"

        config = Config(socket_path=str(proxy_sock))
        config_path = Path(short_tmp) / "config.json"

        monkeypatch.setenv("SSH_AUTH_SOCK", str(real_sock))

        result = _intercept_ssh_auth_sock(config, config_path)

        backup = Path(str(real_sock) + SYSTEM_SOCKET_SUFFIX)
        assert result == str(backup)
        assert backup.exists()
        assert real_sock.is_symlink()
        assert Path(os.readlink(str(real_sock))).resolve() == proxy_sock.resolve()
        assert config.system_agent_path == str(real_sock)

    def test_keepalive_restart_symlink_already_in_place(self, tmp_path, monkeypatch):
        """Case 1: Our symlink is already in place, backup exists."""
        from keepassxc_ssh_agent.config import Config

        proxy_sock = tmp_path / "proxy.sock"
        real_sock = tmp_path / "Listeners"
        backup = Path(str(real_sock) + SYSTEM_SOCKET_SUFFIX)
        backup.touch()

        os.symlink(str(proxy_sock), str(real_sock))

        config = Config(socket_path=str(proxy_sock))
        config_path = tmp_path / "config.json"

        monkeypatch.setenv("SSH_AUTH_SOCK", str(real_sock))

        result = _intercept_ssh_auth_sock(config, config_path)

        assert result == str(backup)
        assert real_sock.is_symlink()

    def test_crash_recovery_backup_exists_no_symlink(self, tmp_path, monkeypatch):
        """Case 2: Backup exists but symlink is gone."""
        from keepassxc_ssh_agent.config import Config

        proxy_sock = tmp_path / "proxy.sock"
        real_sock = tmp_path / "Listeners"
        backup = Path(str(real_sock) + SYSTEM_SOCKET_SUFFIX)
        backup.touch()

        config = Config(socket_path=str(proxy_sock))
        config_path = tmp_path / "config.json"

        monkeypatch.setenv("SSH_AUTH_SOCK", str(real_sock))

        result = _intercept_ssh_auth_sock(config, config_path)

        assert result == str(backup)
        assert real_sock.is_symlink()
        assert Path(os.readlink(str(real_sock))).resolve() == proxy_sock.resolve()

    def test_no_ssh_auth_sock_uses_saved_path(self, tmp_path, monkeypatch):
        """When SSH_AUTH_SOCK is unset, fall back to saved path."""
        from keepassxc_ssh_agent.config import Config

        config = Config(
            socket_path=str(tmp_path / "proxy.sock"),
            system_agent_path="/tmp/com.apple.launchd.XXX/Listeners",
        )
        config_path = tmp_path / "config.json"

        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

        result = _intercept_ssh_auth_sock(config, config_path)
        assert result == "/tmp/com.apple.launchd.XXX/Listeners"

    def test_no_ssh_auth_sock_uses_backup_if_exists(self, tmp_path, monkeypatch):
        """When SSH_AUTH_SOCK is unset but .system backup exists, use that."""
        from keepassxc_ssh_agent.config import Config

        saved_path = str(tmp_path / "Listeners")
        backup_path = Path(saved_path + SYSTEM_SOCKET_SUFFIX)
        backup_path.touch()

        config = Config(
            socket_path=str(tmp_path / "proxy.sock"),
            system_agent_path=saved_path,
        )
        config_path = tmp_path / "config.json"

        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

        result = _intercept_ssh_auth_sock(config, config_path)
        assert result == str(backup_path)

    def test_returns_empty_when_no_agent_available(self, tmp_path, monkeypatch):
        """When SSH_AUTH_SOCK is unset and no saved path, return empty."""
        from keepassxc_ssh_agent.config import Config

        config = Config(socket_path=str(tmp_path / "proxy.sock"))
        config_path = tmp_path / "config.json"

        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

        result = _intercept_ssh_auth_sock(config, config_path)
        assert result == ""


class TestRestoreSSHAuthSock:
    def test_restores_original_socket(self, tmp_path):
        """Remove symlink and rename backup back."""
        real_sock = tmp_path / "Listeners"
        backup = Path(str(real_sock) + SYSTEM_SOCKET_SUFFIX)
        backup.touch()

        os.symlink("/tmp/proxy.sock", str(real_sock))

        _restore_ssh_auth_sock(str(real_sock))

        assert not real_sock.is_symlink()
        assert real_sock.exists()
        assert not backup.exists()

    def test_noop_when_empty(self):
        """No-op when ssh_auth_sock is empty."""
        _restore_ssh_auth_sock("")

    def test_handles_missing_backup(self, tmp_path):
        """Handles case where backup doesn't exist."""
        real_sock = tmp_path / "Listeners"
        os.symlink("/tmp/proxy.sock", str(real_sock))

        _restore_ssh_auth_sock(str(real_sock))

        assert not real_sock.exists()
