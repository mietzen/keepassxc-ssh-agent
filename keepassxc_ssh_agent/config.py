"""Persistent configuration for the KeePassXC SSH agent proxy."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_CONFIG_DIR = Path.home() / ".keepassxc"
DEFAULT_SOCKET_PATH = DEFAULT_CONFIG_DIR / "agent.sock"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "ssh-agent.json"

# Timeout for waiting on KeePassXC unlock (seconds)
DEFAULT_UNLOCK_TIMEOUT = 30


@dataclass
class Association:
    """Stored association with a KeePassXC database."""

    id: str
    id_key: str  # base64-encoded identity public key
    key: str  # base64-encoded identity secret key

    def to_dict(self) -> dict:
        return {"id": self.id, "id_key": self.id_key, "key": self.key}

    @classmethod
    def from_dict(cls, d: dict) -> Association:
        return cls(id=d["id"], id_key=d["id_key"], key=d["key"])


@dataclass
class Config:
    """Agent configuration."""

    socket_path: str = str(DEFAULT_SOCKET_PATH)
    unlock_timeout: int = DEFAULT_UNLOCK_TIMEOUT
    # NaCl keypair for browser protocol communication (base64-encoded)
    client_public_key: str = ""
    client_secret_key: str = ""
    # Path to the real system ssh-agent socket (saved on first run)
    system_agent_path: str = ""
    # Per-database associations (keyed by database hash)
    associations: dict[str, Association] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "socket_path": self.socket_path,
            "unlock_timeout": self.unlock_timeout,
            "client_public_key": self.client_public_key,
            "client_secret_key": self.client_secret_key,
            "associations": {k: v.to_dict() for k, v in self.associations.items()},
        }
        if self.system_agent_path:
            d["system_agent_path"] = self.system_agent_path
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Config:
        associations = {}
        for k, v in d.get("associations", {}).items():
            associations[k] = Association.from_dict(v)
        return cls(
            socket_path=d.get("socket_path", str(DEFAULT_SOCKET_PATH)),
            unlock_timeout=d.get("unlock_timeout", DEFAULT_UNLOCK_TIMEOUT),
            client_public_key=d.get("client_public_key", ""),
            client_secret_key=d.get("client_secret_key", ""),
            system_agent_path=d.get("system_agent_path", ""),
            associations=associations,
        )

    def save(self, path: Path | None = None) -> None:
        path = path or DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path.parent), stat.S_IRWXU)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        # Restrict permissions to owner only
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        path = path or DEFAULT_CONFIG_PATH
        if not path.exists():
            return cls()
        # Warn if config file has overly permissive permissions
        mode = path.stat().st_mode
        if mode & 0o077:
            import logging
            logging.getLogger(__name__).warning(
                "Config file %s has insecure permissions %o; expected 0600. "
                "Fix with: chmod 600 %s",
                path, mode & 0o777, path,
            )
        with open(path) as f:
            return cls.from_dict(json.load(f))
