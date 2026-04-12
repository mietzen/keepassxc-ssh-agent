"""Persistent configuration for the KeePassXC SSH agent proxy."""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CONFIG_DIR = Path.home() / ".keepassxc"
DEFAULT_SOCKET_PATH = DEFAULT_CONFIG_DIR / "agent.sock"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "ssh-agent.json"
DEFAULT_BROWSER_API_CONFIG_PATH = DEFAULT_CONFIG_DIR / "browser-api.json"

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """SSH agent configuration (agent-specific settings only).

    Browser API credentials (keypair, associations, unlock timeout) are stored
    separately in BrowserConfig (~/.keepassxc/browser-api.json) and shared
    with other tools such as keepassxc-cli.
    """

    socket_path: str = str(DEFAULT_SOCKET_PATH)
    # Path to the real system ssh-agent socket (saved on first run)
    system_agent_path: str = ""
    # Path to the shared browser API config (keepassxc-browser-api library)
    browser_api_config_path: str = str(DEFAULT_BROWSER_API_CONFIG_PATH)

    def to_dict(self) -> dict:
        d: dict = {
            "socket_path": self.socket_path,
            "browser_api_config_path": self.browser_api_config_path,
        }
        if self.system_agent_path:
            d["system_agent_path"] = self.system_agent_path
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Config:
        return cls(
            socket_path=d.get("socket_path", str(DEFAULT_SOCKET_PATH)),
            system_agent_path=d.get("system_agent_path", ""),
            browser_api_config_path=d.get(
                "browser_api_config_path",
                str(DEFAULT_BROWSER_API_CONFIG_PATH),
            ),
        )

    def save(self, path: Path | None = None) -> None:
        path = path or DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path.parent), stat.S_IRWXU)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        path = path or DEFAULT_CONFIG_PATH
        if not path.exists():
            return cls()
        mode = path.stat().st_mode
        if mode & 0o077:
            logger.warning(
                "Config file %s has insecure permissions %o; expected 0600. "
                "Fix with: chmod 600 %s",
                path, mode & 0o777, path,
            )
        with open(path) as f:
            return cls.from_dict(json.load(f))
