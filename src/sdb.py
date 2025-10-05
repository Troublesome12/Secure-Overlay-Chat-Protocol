import sqlite3, json, pathlib, time

PUBLIC_ID = "public"

class SOCPStore:
    def __init__(self, path: pathlib.Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    def _init_schema(self):
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

    def ensure_public_group(self):
        c = self._conn.cursor()
        c.execute("SELECT 1 FROM groups WHERE group_id=?", (PUBLIC_ID,))
        if not c.fetchone():
            c.execute("INSERT INTO groups(group_id, creator_id, created_at, meta, version) VALUES(?,?,?,?,?)",
                      (PUBLIC_ID, "system", int(time.time()*1000), json.dumps({"title":"Public"}), 1))
            self._conn.commit()

    def add_member_public(self, user_id: str):
        self.ensure_public_group()
        c = self._conn.cursor()
        c.execute("""INSERT OR IGNORE INTO group_members(group_id, member_id, role, wrapped_key, added_at)
                     VALUES(?,?,?,?,?)""",
                  (PUBLIC_ID, user_id, "member", "", int(time.time()*1000)))
        self._conn.commit()

    def remove_member_public(self, user_id: str):
        c = self._conn.cursor()
        c.execute("DELETE FROM group_members WHERE group_id=? AND member_id=?", (PUBLIC_ID, user_id))
        self._conn.commit()

    # --- Users ---

    def upsert_user(self, user_id: str, pubkey_b64u: str):
        c = self._conn.cursor()
        c.execute("""INSERT INTO users(user_id, pubkey, privkey_store, pake_password, meta, version)
                    VALUES(?,?,?,?,?,1)
                    ON CONFLICT(user_id) DO UPDATE SET pubkey=excluded.pubkey, version=users.version+1""",
                  (user_id, pubkey_b64u, "", "", "{}",))
        self._conn.commit()

    def register_user(self, user_id: str, pubkey_b64u: str):
        # Backwards-compat alias
        self.upsert_user(user_id, pubkey_b64u)

    def get_user_pub(self, user_id: str) -> tuple[str, None]:
        c = self._conn.cursor()
        c.execute("SELECT pubkey FROM users WHERE user_id=?", (user_id,))
        row = c.fetchone()
        return row[0] if row else None
