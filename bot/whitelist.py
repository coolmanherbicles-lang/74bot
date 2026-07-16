"""
whitelist.py — persistent user whitelist backed by a local JSON file.
Thread-safe reads, async-safe writes via asyncio.Lock.
"""

import json
import asyncio
import os
from pathlib import Path

WHITELIST_PATH = Path(__file__).parent / "whitelist.json"
_lock = asyncio.Lock()


def _load_raw() -> dict:
    if WHITELIST_PATH.exists():
        try:
            with open(WHITELIST_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"users": []}


def load_whitelist() -> set[int]:
    """Synchronous read — safe to call at startup or in checks."""
    return {int(uid) for uid in _load_raw().get("users", [])}


async def add_user(user_id: int) -> bool:
    """Add a user ID to the whitelist. Returns True if newly added."""
    async with _lock:
        data = _load_raw()
        users: list = data.get("users", [])
        uid_str = str(user_id)
        if uid_str in users:
            return False
        users.append(uid_str)
        data["users"] = users
        with open(WHITELIST_PATH, "w") as f:
            json.dump(data, f, indent=2)
        return True


async def remove_user(user_id: int) -> bool:
    """Remove a user ID from the whitelist. Returns True if found and removed."""
    async with _lock:
        data = _load_raw()
        users: list = data.get("users", [])
        uid_str = str(user_id)
        if uid_str not in users:
            return False
        users.remove(uid_str)
        data["users"] = users
        with open(WHITELIST_PATH, "w") as f:
            json.dump(data, f, indent=2)
        return True


async def list_users() -> list[int]:
    """Return all whitelisted user IDs."""
    async with _lock:
        return [int(uid) for uid in _load_raw().get("users", [])]
