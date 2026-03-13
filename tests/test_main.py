"""Tests for CLI entry point."""

from pathlib import Path
from unittest.mock import patch, MagicMock

from keepassxc_ssh_agent.__main__ import (
    _ask_yes_no,
    _create_launchagent,
    _get_run_plist,
    _find_agent_bin,
    _resolve_system_agent,
    _setenv_ssh_auth_sock,
    LAUNCHAGENT_RUN_LABEL,
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


class TestResolveSystemAgent:
    def test_uses_ssh_auth_sock_when_not_our_socket(self, tmp_path, monkeypatch):
        """When SSH_AUTH_SOCK points to the real agent, use and save it."""
        from keepassxc_ssh_agent.config import Config

        config = Config(socket_path=str(tmp_path / "proxy.sock"))
        config_path = tmp_path / "config.json"

        monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/com.apple.launchd.XXX/Listeners")

        result = _resolve_system_agent(config, config_path)
        assert result == "/tmp/com.apple.launchd.XXX/Listeners"
        assert config.system_agent_path == "/tmp/com.apple.launchd.XXX/Listeners"

    def test_uses_saved_path_when_ssh_auth_sock_is_our_socket(self, tmp_path, monkeypatch):
        """When SSH_AUTH_SOCK points to our socket, fall back to saved path."""
        from keepassxc_ssh_agent.config import Config

        proxy_sock = str(tmp_path / "proxy.sock")
        config = Config(
            socket_path=proxy_sock,
            system_agent_path="/tmp/com.apple.launchd.XXX/Listeners",
        )
        config_path = tmp_path / "config.json"

        monkeypatch.setenv("SSH_AUTH_SOCK", proxy_sock)

        result = _resolve_system_agent(config, config_path)
        assert result == "/tmp/com.apple.launchd.XXX/Listeners"

    def test_returns_empty_when_no_agent_available(self, tmp_path, monkeypatch):
        """When SSH_AUTH_SOCK is unset and no saved path, return empty."""
        from keepassxc_ssh_agent.config import Config

        config = Config(socket_path=str(tmp_path / "proxy.sock"))
        config_path = tmp_path / "config.json"

        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

        result = _resolve_system_agent(config, config_path)
        assert result == ""


class TestSetenvSSHAuthSock:
    def test_calls_launchctl_setenv(self):
        with patch("subprocess.run") as mock_run:
            result = _setenv_ssh_auth_sock("/tmp/proxy.sock")
            assert result is True
            mock_run.assert_called_once_with(
                ["launchctl", "setenv", "SSH_AUTH_SOCK", "/tmp/proxy.sock"],
                check=True,
                capture_output=True,
            )

    def test_handles_failure_gracefully(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "launchctl", stderr=b"error")):
            result = _setenv_ssh_auth_sock("/tmp/proxy.sock")
            assert result is False

    def test_handles_missing_launchctl(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = _setenv_ssh_auth_sock("/tmp/proxy.sock")
            assert result is False


class TestFindAgentBin:
    def test_finds_binary_on_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/keepassxc-ssh-agent"):
            assert _find_agent_bin() == "/usr/local/bin/keepassxc-ssh-agent"

    def test_falls_back_to_python(self):
        import sys
        with patch("shutil.which", return_value=None):
            assert _find_agent_bin() == sys.executable
