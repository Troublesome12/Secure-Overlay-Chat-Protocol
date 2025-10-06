import sqlite3, json, pathlib, time

"""
SOCPStore - SQLite-backed persistent data store for Secure Overlay Chat Protocol (SOCP)
----------------------------------------------------------------------------------------

Implements a minimal SQL data model described in SOCP v1.3 specification.

Responsibilities:
- Store all registered users and their public keys.
- Manage group membership, including the default public broadcast channel.
- Ensure data persistence between sessions (unlike in-memory registries).

Tables:
1. users          → stores user identities, public keys, and metadata.
2. groups         → stores group/channel information (only 'public' required).
3. group_members  → stores which users belong to which group.

This replaces the legacy JSON-based master_db.json while maintaining backward compatibility.
"""

PUBLIC_ID = "public"


class SOCPStore:
    """Persistent SQLite store for SOCP user and group data."""

    def __init__(self, path: pathlib.Path):
        """
        Initialize the SQLite connection and schema.

        Args:
            path (pathlib.Path): Path to SQLite database file (e.g., data/socp.db)
        """

        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self):
        """Create all required tables if they don't already exist."""

        c = self._conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS users(
            user_id TEXT PRIMARY KEY,
            pubkey  TEXT NOT NULL,
            privkey_store TEXT DEFAULT '',
            pake_password TEXT DEFAULT '',
            meta    TEXT DEFAULT '{}',
            version INT  NOT NULL DEFAULT 1
        );""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS groups(
            group_id   TEXT PRIMARY KEY,
            creator_id TEXT NOT NULL,
            created_at INT  NOT NULL,
            meta       TEXT DEFAULT '{}',
            version    INT  NOT NULL DEFAULT 1
        );""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS group_members(
            group_id    TEXT NOT NULL,
            member_id   TEXT NOT NULL,
            role        TEXT DEFAULT 'member',
            wrapped_key TEXT DEFAULT '',      -- not used for pure-RSA public right now
            added_at    INT  NOT NULL,
            PRIMARY KEY (group_id, member_id),
            FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
        );""")
        self._conn.commit()

    # --- Public channel helpers ---

    def ensure_public_group(self) -> None:
        """
        Ensure that the default 'public' group exists in the database.
        If missing, it will be created with system as the creator.
        """

        c = self._conn.cursor()
        c.execute("SELECT 1 FROM groups WHERE group_id=?", (PUBLIC_ID,))
        if not c.fetchone():
            c.execute("INSERT INTO groups(group_id, creator_id, created_at, meta, version) VALUES(?,?,?,?,?)",
                      (PUBLIC_ID, "system", int(time.time()*1000), json.dumps({"title":"Public"}), 1))
            self._conn.commit()

    def add_member_public(self, user_id: str) -> None:
        """
        Add a user to the public channel membership list.

        Args:
            user_id (str): The UUID or name of the user to be added.
        """

        self.ensure_public_group()
        c = self._conn.cursor()
        c.execute("""INSERT OR IGNORE INTO group_members(group_id, member_id, role, wrapped_key, added_at)
                     VALUES(?,?,?,?,?)""",
                  (PUBLIC_ID, user_id, "member", "", int(time.time()*1000)))
        self._conn.commit()

    def remove_member_public(self, user_id: str) -> None:
        """
        Remove a user from the public channel membership list.

        Args:
            user_id (str): The UUID or name of the user to be removed.
        """

        c = self._conn.cursor()
        c.execute("DELETE FROM group_members WHERE group_id=? AND member_id=?", (PUBLIC_ID, user_id))
        self._conn.commit()

    # --- Users ---

    def upsert_user(self, user_id: str, pubkey_b64u: str) -> None:
        """
        Insert or update a user's public key in the database.

        Args:
            user_id (str): The user’s unique identifier.
            pubkey_b64u (str): The user’s RSA public key in Base64URL format.
        """

        c = self._conn.cursor()
        c.execute("""INSERT INTO users(user_id, pubkey, privkey_store, pake_password, meta, version)
                    VALUES(?,?,?,?,?,1)
                    ON CONFLICT(user_id) DO UPDATE SET pubkey=excluded.pubkey, version=users.version+1""",
                  (user_id, pubkey_b64u, "", "", "{}",))
        self._conn.commit()

    def get_user_pub(self, user_id: str) -> tuple[str, None]:
        """
        Fetch a user's public key from the database.

        Args:
            user_id (str): Target user ID to query.

        Returns:
            str | None: Base64URL-encoded public key, or None if user not found.
        """

        c = self._conn.cursor()
        c.execute("SELECT pubkey FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        return row[0] if row else None
