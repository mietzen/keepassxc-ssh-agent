"""Tests for the auto-start service abstraction (launchd / systemd)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from keepassxc_ssh_agent import service
from keepassxc_ssh_agent.service import (
    LAUNCHAGENT_RUN_LABEL,
    SYSTEMD_UNIT_NAME,
    _agent_argv,
    _create_launchagent,
    _create_systemd_service,
    _find_agent_bin,
    _get_run_plist,
    _get_systemd_unit,
    _remove_launchagent,
    _remove_systemd_service,
)


class TestFindAgentBin:
    def test_finds_binary_on_path(self):
        with patch("shutil.which", return_value="/usr/local/bin/keepassxc-ssh-agent"):
            assert _find_agent_bin() == "/usr/local/bin/keepassxc-ssh-agent"

    def test_falls_back_to_python(self):
        with patch("shutil.which", return_value=None):
            assert _find_agent_bin() == sys.executable


class TestAgentArgv:
    def test_binary(self):
        assert _agent_argv("/usr/local/bin/keepassxc-ssh-agent") == [
            "/usr/local/bin/keepassxc-ssh-agent",
            "run",
        ]

    def test_python_fallback(self):
        assert _agent_argv(sys.executable) == [
            sys.executable,
            "-m",
            "keepassxc_ssh_agent",
            "run",
        ]


# --------------------------------------------------------------------------- #
# macOS: launchd LaunchAgent
# --------------------------------------------------------------------------- #


class TestPlistGeneration:
    def test_run_plist_with_binary(self):
        plist = _get_run_plist("/usr/local/bin/keepassxc-ssh-agent")
        assert LAUNCHAGENT_RUN_LABEL in plist
        assert "/usr/local/bin/keepassxc-ssh-agent" in plist
        assert "<string>run</string>" in plist
        assert "KeepAlive" in plist

    def test_run_plist_with_python_fallback(self):
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
        assert LAUNCHAGENT_RUN_LABEL in plist_path.read_text()

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

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
            1, "launchctl", stderr=b"some error"
        )):
            result = _create_launchagent(LAUNCHAGENT_RUN_LABEL, "<plist/>")

        assert result is False
        output = capsys.readouterr().out
        assert "Warning" in output or "manually" in output

    def test_handles_missing_launchctl(self, tmp_path, monkeypatch, capsys):
        """launchctl absent (e.g. running on Linux) is handled gracefully."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run", side_effect=FileNotFoundError("launchctl")):
            result = _create_launchagent(LAUNCHAGENT_RUN_LABEL, "<plist/>")

        assert result is False
        assert "manually" in capsys.readouterr().out


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
        assert "does not exist" in capsys.readouterr().out

    def test_handles_bootout_failure(self, tmp_path, monkeypatch):
        """Still removes plist even if launchctl bootout fails."""
        la_dir = tmp_path / "Library" / "LaunchAgents"
        la_dir.mkdir(parents=True)
        plist_path = la_dir / f"{LAUNCHAGENT_RUN_LABEL}.plist"
        plist_path.write_text("<plist/>")

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
            1, "launchctl", stderr=b"not running"
        )):
            result = _remove_launchagent(LAUNCHAGENT_RUN_LABEL)

        assert result is True
        assert not plist_path.exists()


# --------------------------------------------------------------------------- #
# Linux: systemd user unit
# --------------------------------------------------------------------------- #


class TestSystemdUnitGeneration:
    def test_unit_with_binary(self):
        unit = _get_systemd_unit("/usr/local/bin/keepassxc-ssh-agent")
        assert "ExecStart=/usr/local/bin/keepassxc-ssh-agent run" in unit
        assert "WantedBy=default.target" in unit

    def test_unit_with_python_fallback(self):
        unit = _get_systemd_unit(sys.executable)
        assert f"ExecStart={sys.executable} -m keepassxc_ssh_agent run" in unit

    def test_unit_with_ssh_auth_sock(self):
        unit = _get_systemd_unit("/bin/agent", ssh_auth_sock="/run/user/1000/ssh-agent.socket")
        assert "Environment=SSH_AUTH_SOCK=/run/user/1000/ssh-agent.socket" in unit

    def test_unit_without_ssh_auth_sock(self):
        unit = _get_systemd_unit("/bin/agent")
        assert "Environment=SSH_AUTH_SOCK" not in unit


class TestCreateSystemdService:
    def test_creates_unit_and_starts(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = _create_systemd_service("/bin/agent", "/run/user/1000/ssh-agent.socket")

        assert result is True
        unit_path = tmp_path / "systemd" / "user" / SYSTEMD_UNIT_NAME
        assert unit_path.exists()
        assert "SSH_AUTH_SOCK" in unit_path.read_text()
        # daemon-reload + enable --now
        calls = [c.args[0] for c in mock_run.call_args_list]
        assert ["systemctl", "--user", "daemon-reload"] in calls
        assert ["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT_NAME] in calls

    def test_skips_if_exists(self, tmp_path, monkeypatch, capsys):
        unit_dir = tmp_path / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        unit_path = unit_dir / SYSTEMD_UNIT_NAME
        unit_path.write_text("existing")

        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        result = _create_systemd_service("/bin/agent")

        assert result is True
        assert "already exists" in capsys.readouterr().out
        assert unit_path.read_text() == "existing"

    def test_handles_systemctl_failure(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
            1, "systemctl", stderr=b"Failed to connect to bus"
        )):
            result = _create_systemd_service("/bin/agent")

        assert result is False
        assert "manually" in capsys.readouterr().out

    def test_handles_missing_systemctl(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        with patch("subprocess.run", side_effect=FileNotFoundError("systemctl")):
            result = _create_systemd_service("/bin/agent")

        assert result is False
        assert "manually" in capsys.readouterr().out


class TestRemoveSystemdService:
    def test_removes_unit(self, tmp_path, monkeypatch, capsys):
        unit_dir = tmp_path / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        unit_path = unit_dir / SYSTEMD_UNIT_NAME
        unit_path.write_text("[Unit]\n")

        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = _remove_systemd_service()

        assert result is True
        assert not unit_path.exists()
        output = capsys.readouterr().out
        assert "Stopped" in output
        assert "Removed" in output

    def test_skips_if_not_exists(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        result = _remove_systemd_service()

        assert result is False
        assert "does not exist" in capsys.readouterr().out

    def test_handles_disable_failure(self, tmp_path, monkeypatch):
        """Still removes unit even if systemctl disable fails."""
        unit_dir = tmp_path / "systemd" / "user"
        unit_dir.mkdir(parents=True)
        unit_path = unit_dir / SYSTEMD_UNIT_NAME
        unit_path.write_text("[Unit]\n")

        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(
            1, "systemctl", stderr=b"not loaded"
        )):
            result = _remove_systemd_service()

        assert result is True
        assert not unit_path.exists()


# --------------------------------------------------------------------------- #
# Platform dispatch
# --------------------------------------------------------------------------- #


class TestInstallServiceDispatch:
    def test_darwin_uses_launchagent(self):
        with patch.object(service.sys, "platform", "darwin"), \
                patch("keepassxc_ssh_agent.service._create_launchagent", return_value=True) as mac, \
                patch("keepassxc_ssh_agent.service._create_systemd_service") as linux:
            assert service.install_service("/bin/agent") is True
            mac.assert_called_once()
            linux.assert_not_called()

    def test_linux_uses_systemd(self):
        with patch.object(service.sys, "platform", "linux"), \
                patch("keepassxc_ssh_agent.service._create_systemd_service", return_value=True) as linux, \
                patch("keepassxc_ssh_agent.service._create_launchagent") as mac:
            assert service.install_service("/bin/agent", ssh_auth_sock="/x") is True
            linux.assert_called_once_with("/bin/agent", "/x")
            mac.assert_not_called()

    def test_remove_dispatch_linux(self):
        with patch.object(service.sys, "platform", "linux"), \
                patch("keepassxc_ssh_agent.service._remove_systemd_service", return_value=True) as linux:
            assert service.remove_service() is True
            linux.assert_called_once()
