from __future__ import annotations

import json
import pathlib

from dataclasses import dataclass
from typing import Any, Dict, Optional

"""Master database (JSON) + DB-RPC helpers

    Stores user rows under key "users":
    {
        "users": {
            "<user_id>": { "pubkey": "<DER-b64url>", "version": 1 }
        }
    }
"""

@dataclass
class MasterDB:
    """Tiny JSON-backed user directory for SOCP"""
    path: pathlib.Path

    def _load(self) -> Dict[str, Any]:
        """Loads the JSON document from disk or returns an empty structure

        Returns:
            Dict[str, Any]: Parsed JSON object with at least {"users": {}}

        Raises:
            OSError: If the file cannot be read.
            JSONDecodeError: If the file contents are invalid JSON
        """

        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception:
                return {"users": {}}
        return {"users": {}}

    def _save(self, doc: Dict[str, Any]) -> None:
        """Atomically saves the JSON document to disk

        Args:
            doc (Dict[str, Any]): Document to persist

        Raises:
            OSError: If the file cannot be written or replaced
            TypeError: If `doc` is not JSON serializable
        """

        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(doc))
        tmp.replace(self.path)

    def get_user_pub(self, user_id: str) -> Optional[str]:
        """Returns a user's public key if registered

        Args:
            user_id (str): Mesh-unique user identifier

        Returns:
            Optional[str]: The user's DER(SPKI) public key encoded as base64url,
            or None if the user is not found
        """

        doc = self._load(); row = doc.get("users", {}).get(user_id)
        return row.get("pubkey") if row else None

    def register_user(self, user_id: str, pubkey_der_b64u: str) -> None:
        """Registers or updates a user's public key

        Args:
            user_id (str): Mesh-unique user identifier
            pubkey_der_b64u (str): Public key encoded as DER(SPKI) base64url
        """

        doc = self._load(); users = doc.setdefault("users", {})
        row = users.get(user_id)
        if row and row.get("pubkey") == pubkey_der_b64u:
            return
        users[user_id] = {"pubkey": pubkey_der_b64u, "version": 1}
        self._save(doc)
