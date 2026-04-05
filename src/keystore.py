"""API Key Store — server-side key management for MCP client authentication.

Implements admin-managed API keys with SHA-256 hashing, thread-safe
file-backed persistence, and prefix-based identification/revocation.

Keys are stored as SHA-256 hashes in a JSON file (/data/keys.json by
default). Raw keys are never persisted — only returned once at
generation time.

Design mirrors the GDP MCP Server's Model B: Admin-Managed Key Store.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default location — mounted as a Docker volume for persistence
DEFAULT_KEYS_FILE = os.getenv("KEYS_FILE", "/data/keys.json")


@dataclass
class KeyRecord:
    """Metadata for a single API key (raw key is never stored)."""

    hash: str                       # SHA-256 hex digest of the raw key
    prefix: str                     # First 8 characters of the raw key (for identification)
    user: str                       # Email / label of the authorised user
    created_at: str = field(        # ISO-8601 timestamp
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class KeyStore:
    """Thread-safe, file-backed API key store with SHA-256 hashing.

    Public API:
        generate(user)       → raw key (shown once)
        validate(raw_key)    → bool
        list_keys()          → list of {prefix, user, created_at}
        revoke(prefix)       → bool
        has_any_keys()       → bool
    """

    def __init__(self, keys_file: str = DEFAULT_KEYS_FILE) -> None:
        self._path = Path(keys_file)
        self._lock = threading.Lock()
        self._keys: list[KeyRecord] = []
        self._load()

    # ── Public API ──────────────────────────────────────────────────

    def generate(self, user: str) -> str:
        """Generate a new 64-char hex API key for *user*.

        Returns the raw key (displayed once — never stored in plain text).
        """
        raw_key = secrets.token_hex(32)           # 64 hex chars
        record = KeyRecord(
            hash=self._hash(raw_key),
            prefix=raw_key[:8],
            user=user,
        )
        with self._lock:
            self._keys.append(record)
            self._save()
        logger.info("Generated API key for user=%s prefix=%s", user, record.prefix)
        return raw_key

    def validate(self, raw_key: str) -> bool:
        """Return True if *raw_key* matches any stored hash."""
        key_hash = self._hash(raw_key)
        with self._lock:
            return any(k.hash == key_hash for k in self._keys)

    def list_keys(self) -> list[dict[str, str]]:
        """Return a list of key metadata (prefix, user, created_at) — no hashes."""
        with self._lock:
            return [
                {"prefix": k.prefix, "user": k.user, "created_at": k.created_at}
                for k in self._keys
            ]

    def revoke(self, prefix: str) -> bool:
        """Revoke (delete) the key identified by *prefix*. Returns True if found."""
        with self._lock:
            before = len(self._keys)
            self._keys = [k for k in self._keys if k.prefix != prefix]
            if len(self._keys) < before:
                self._save()
                logger.info("Revoked API key with prefix=%s", prefix)
                return True
        logger.warning("Revoke failed — no key with prefix=%s", prefix)
        return False

    def has_any_keys(self) -> bool:
        """Return True if at least one key exists."""
        with self._lock:
            return len(self._keys) > 0

    # ── Internal helpers ────────────────────────────────────────────

    @staticmethod
    def _hash(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def _load(self) -> None:
        """Load keys from disk (if the file exists)."""
        if not self._path.exists():
            logger.info("No keys file at %s — starting with empty store", self._path)
            return
        try:
            data: list[dict[str, Any]] = json.loads(self._path.read_text())
            self._keys = [KeyRecord(**rec) for rec in data]
            logger.info("Loaded %d API key(s) from %s", len(self._keys), self._path)
        except Exception:
            logger.exception("Failed to load keys from %s — starting empty", self._path)
            self._keys = []

    def _save(self) -> None:
        """Persist keys to disk with owner-only permissions (0o600)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps([asdict(k) for k in self._keys], indent=2))
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass  # Windows or permission issues — best-effort
