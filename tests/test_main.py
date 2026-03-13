"""Tests for CLI entry point."""

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from keepassxc_ssh_agent.__main__ import (
    _ask_yes_no,
    _setup_ssh_config,
    _create_launchagent,
    _get_run_plist,
    _get_sock_plist,
    _find_agent_bin,
    LAUNCHAGENT_RUN_LABEL,
    LAUNCHAGENT_SOCK_LABEL,
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


class TestSetupSSHConfig:
    def test_creates_ssh_config(self, tmp_path, monkeypatch):
        ssh_dir = tmp_path / ".ssh"
        ssh_config = ssh_dir / "config"

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        _setup_ssh_config("/tmp/agent.sock")

        assert ssh_config.exists()
        content = ssh_config.read_text()
        assert "Host *" in content
        assert 'IdentityAgent "/tmp/agent.sock"' in content

    def test_appends_to_existing_config(self, tmp_path, monkeypatch):
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        ssh_config = ssh_dir / "config"
        ssh_config.write_text("Host example.com\n    User admin\n")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        _setup_ssh_config("/tmp/agent.sock")

        content = ssh_config.read_text()
        assert "Host example.com" in content
        assert "Host *" in content
        assert 'IdentityAgent "/tmp/agent.sock"' in content

    def test_skips_if_already_configured(self, tmp_path, monkeypatch, capsys):
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        ssh_config = ssh_dir / "config"
        ssh_config.write_text('Host *\n    IdentityAgent "/tmp/agent.sock"\n')

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        _setup_ssh_config("/tmp/agent.sock")

        output = capsys.readouterr().out
        assert "already contains" in output


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

    def test_sock_plist(self):
        plist = _get_sock_plist("/home/user/.keepassxc/agent.sock")
        assert LAUNCHAGENT_SOCK_LABEL in plist
        assert "ln -sf /home/user/.keepassxc/agent.sock" in plist
        assert "$SSH_AUTH_SOCK" in plist


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

    def test_creates_sock_plist(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = _create_launchagent(
                LAUNCHAGENT_SOCK_LABEL,
                _get_sock_plist("/tmp/agent.sock"),
            )

        assert result is True
        plist_path = tmp_path / "Library" / "LaunchAgents" / f"{LAUNCHAGENT_SOCK_LABEL}.plist"
        assert plist_path.exists()
        content = plist_path.read_text()
        assert "ln -sf" in content

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


class TestFindAgentBin:
    def test_finds_binary_on_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/keepassxc-ssh-agent"):
            assert _find_agent_bin() == "/usr/local/bin/keepassxc-ssh-agent"

    def test_falls_back_to_python(self):
        import sys
        with patch("shutil.which", return_value=None):
            assert _find_agent_bin() == sys.executable
