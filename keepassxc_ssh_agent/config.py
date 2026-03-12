"""Persistent configuration for the KeePassXC SSH agent proxy."""

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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
    def from_dict(cls, d: dict) -> "Association":
        return cls(id=d["id"], id_key=d["id_key"], key=d["key"])


@dataclass
class Config:
    """Agent configuration."""

    socket_path: str = str(DEFAULT_SOCKET_PATH)
    unlock_timeout: int = DEFAULT_UNLOCK_TIMEOUT
    # NaCl keypair for browser protocol communication (base64-encoded)
    client_public_key: str = ""
    client_secret_key: str = ""
    # Per-database associations (keyed by database hash)
    associations: dict[str, Association] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "socket_path": self.socket_path,
            "unlock_timeout": self.unlock_timeout,
            "client_public_key": self.client_public_key,
            "client_secret_key": self.client_secret_key,
            "associations": {k: v.to_dict() for k, v in self.associations.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        associations = {}
        for k, v in d.get("associations", {}).items():
            associations[k] = Association.from_dict(v)
        return cls(
            socket_path=d.get("socket_path", str(DEFAULT_SOCKET_PATH)),
            unlock_timeout=d.get("unlock_timeout", DEFAULT_UNLOCK_TIMEOUT),
            client_public_key=d.get("client_public_key", ""),
            client_secret_key=d.get("client_secret_key", ""),
            associations=associations,
        )

    def save(self, path: Optional[Path] = None) -> None:
        path = path or DEFAULT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        # Restrict permissions to owner only
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        path = path or DEFAULT_CONFIG_PATH
        if not path.exists():
            return cls()
        with open(path) as f:
            return cls.from_dict(json.load(f))
