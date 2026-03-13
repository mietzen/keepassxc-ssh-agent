"""Tests for CLI entry point."""

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from keepassxc_ssh_agent.__main__ import (
    _ask_yes_no,
    _create_launchagent,
    _remove_launchagent,
    _get_run_plist,
    _find_agent_bin,
    _intercept_ssh_auth_sock,
    _restore_ssh_auth_sock,
    LAUNCHAGENT_RUN_LABEL,
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


class TestPlistGeneration:
    def test_run_plist_with_binary(self):
        plist = _get_run_plist("/usr/local/bin/keepassxc-ssh-agent")
        assert LAUNCHAGENT_RUN_LABEL in plist
        assert "/usr/local/bin/keepassxc-ssh-agent" in plist
        assert "<string>run</string>" in plist
        assert "KeepAlive" in plist

    def test_run_plist_with_python_fallback(self):
        import sys
        plist = _get_run_plist(sys.executable)
        assert sys.executable in plist
        assert "keepassxc_ssh_agent" in plist
        assert "<string>-m</string>" in plist


class TestCreateLaunchAgent:
    def test_creates_plist(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = _create_launchagent(
                LAUNCHAGENT_RUN_LABEL,
                _get_run_plist("/usr/local/bin/keepassxc-ssh-agent"),
            )

        assert result is True
        plist_path = tmp_path / "Library" / "LaunchAgents" / f"{LAUNCHAGENT_RUN_LABEL}.plist"
        assert plist_path.exists()
        content = plist_path.read_text()
        assert LAUNCHAGENT_RUN_LABEL in content

    def test_skips_if_exists(self, tmp_path, monkeypatch, capsys):
        la_dir = tmp_path / "Library" / "LaunchAgents"
        la_dir.mkdir(parents=True)
        plist_path = la_dir / f"{LAUNCHAGENT_RUN_LABEL}.plist"
        plist_path.write_text("existing")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        _create_launchagent(LAUNCHAGENT_RUN_LABEL, "new content")

        output = capsys.readouterr().out
        assert "already exists" in output
        assert plist_path.read_text() == "existing"

    def test_handles_launchctl_failure(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        import subprocess
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
            1, "launchctl", stderr=b"some error"
        )):
            result = _create_launchagent(LAUNCHAGENT_RUN_LABEL, "<plist/>")

        assert result is False
        output = capsys.readouterr().out
        assert "Warning" in output or "manually" in output


class TestRemoveLaunchAgent:
    def test_removes_plist(self, tmp_path, monkeypatch, capsys):
        la_dir = tmp_path / "Library" / "LaunchAgents"
        la_dir.mkdir(parents=True)
        plist_path = la_dir / f"{LAUNCHAGENT_RUN_LABEL}.plist"
        plist_path.write_text("<plist/>")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = _remove_launchagent(LAUNCHAGENT_RUN_LABEL)

        assert result is True
        assert not plist_path.exists()
        output = capsys.readouterr().out
        assert "Stopped" in output
        assert "Removed" in output

    def test_skips_if_not_exists(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        result = _remove_launchagent(LAUNCHAGENT_RUN_LABEL)

        assert result is False
        output = capsys.readouterr().out
        assert "does not exist" in output

    def test_handles_bootout_failure(self, tmp_path, monkeypatch, capsys):
        """Still removes plist even if launchctl bootout fails."""
        la_dir = tmp_path / "Library" / "LaunchAgents"
        la_dir.mkdir(parents=True)
        plist_path = la_dir / f"{LAUNCHAGENT_RUN_LABEL}.plist"
        plist_path.write_text("<plist/>")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        import subprocess
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
            1, "launchctl", stderr=b"not running"
        )):
            result = _remove_launchagent(LAUNCHAGENT_RUN_LABEL)

        assert result is True
        assert not plist_path.exists()


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


class TestFindAgentBin:
    def test_finds_binary_on_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/keepassxc-ssh-agent"):
            assert _find_agent_bin() == "/usr/local/bin/keepassxc-ssh-agent"

    def test_falls_back_to_python(self):
        import sys
        with patch("shutil.which", return_value=None):
            assert _find_agent_bin() == sys.executable
