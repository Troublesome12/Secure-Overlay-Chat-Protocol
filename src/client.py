from __future__ import annotations

import sys
import asyncio
import json
import pathlib
import time
import uuid
import websockets

from pathlib import Path
from protocols import *
from crypto import RSAKeys, e2e_encrypt_for, e2e_decrypt_with
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from encoding import b64u_encode, b64u_decode

"""
SOCP Client (v1.1)

- Connects to one local server over WebSocket
- Sends USER_HELLO on connect
- Commands: /help, /pubget, /dbget <user>, /msg <user> <text>, /quit
- DMs: AES-256-GCM + RSA-OAEP(SHA-256) for the key, RSASSA-PSS(SHA-256) signature
"""

class SOCPClient:
    """User client. Keeps a keyring (user_uuid -> pubkey DER b64url)"""

    def __init__(self, user_uuid: str, server_url: str, key_path: pathlib.Path):
        """Initializes the SOCP client

        Args:
            user_uuid (str): Mesh-wide unique user identifier (e.g., "Alice")
            server_url (str): WebSocket URL of the local server (e.g., "ws://127.0.0.1:9101")
            key_path (pathlib.Path): Path to the RSA-4096 PEM; created if missing
        """

        self.user_uuid = user_uuid
        self.server_url = server_url
        self.keys = RSAKeys.load_or_create(key_path)
        self.group_keys: dict[str, bytes] = {}
        self.downloads: dict[str, bytearray] = {}
        self.keyring: dict[str,str] = {self.user_uuid: self.keys.pub_der_b64u()}
        self.recv_files: dict[str, dict] = {}       # file_id -> {"fh": f, "path": Path, "mode": str, "group_id": str|None}
        self.ws: websockets.WebSocketClientProtocol | None = None


    async def run(self) -> None:
        """Connects to the server, sends USER_HELLO, and runs receiver + REPL"""
        
        print(f"[client {self.user_uuid}] connect -> {self.server_url}")
        async with websockets.connect(self.server_url, ping_interval=20) as ws:
            self.ws = ws
            hello = {
                "type": T_USER_HELLO,
                "from": self.user_uuid,
                "to":   "server_*",
                "ts":   int(time.time()*1000),
                "payload": {
                    "client": "socp-cli-v1",
                    "pubkey": self.keys.pub_der_b64u(),
                    "enc_pubkey": self.keys.pub_der_b64u(),
                },
                "sig": "",
            }
            await ws.send(json.dumps(hello, separators=(',',':')))
            consumer = asyncio.create_task(self._recv())
            producer = asyncio.create_task(self._stdin()) if sys.stdin and sys.stdin.isatty() else None

            await self.ws.wait_closed()   # stay alive until /quit or server closes
            for t in (consumer, producer) if producer else (consumer,): t.cancel()

    async def _recv(self) -> None:
        """Receives and processes server frames (USER_DELIVER / USER_DB_USER / ERROR)
        
        Raises:
            Exception: If socket operations fail unexpectedly (internal errors are mostly caught)
        """

        assert self.ws
        from crypto import e2e_decrypt_with
        async for raw in self.ws:
            try: msg = json.loads(raw)
            except Exception: continue
            t = msg.get("type")
            pl = msg.get("payload", {})
            
            if t == T_USER_DELIVER:
                if "wrapped_key" not in pl:
                    print("[dm] malformed frame (missing wrapped_key) — ignored")
                    continue

                sender = pl.get("sender"); sender_pub = pl.get("sender_pub", "")
                # Optional content signature verification
                verified = False
                try:
                    from crypto import RSAKeys as _Keys
                    content_obj = {
                        "ciphertext": pl.get("ciphertext"),
                        "iv": pl.get("iv"),
                        "tag": pl.get("tag"),
                        "from": sender,
                        "to":   self.user_uuid,
                        "ts":   pl.get("content_ts", msg.get("ts")),
                    }
                    verified = _Keys.verify_payload(sender_pub, content_obj, pl.get("content_sig",""))
                except Exception:
                    verified = False
                # Decrypt
                try:
                    pt = e2e_decrypt_with(self.keys.priv, pl)
                    text = pt.decode('utf-8', errors='replace')
                except Exception as e:
                    text = f"<decrypt failed: {e}>"
                badge = "🔐" if verified else "⚠️"
                print(f"[dm from {sender}] {badge} {text}")

            elif t == T_USER_DB_USER:
                if pl.get("found"):
                    self.keyring[pl.get("user_id")] = pl.get("pubkey")
                    print(f"[db] cached pubkey for {pl.get('user_id')}")
                else:
                    print(f"[db] user not found: {pl.get('user_id')}")

            elif t == T_GROUP_KEY_SHARE:
                gid = pl.get("group_id")
                shares = pl.get("shares") or []
                # find my share
                my = next((s for s in shares if s.get("member") == self.user_uuid), None)
                if gid and my:
                    try:
                        from cryptography.hazmat.primitives import serialization, hashes
                        from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
                        key = self.keys.priv.decrypt(
                            b64u_decode(my["wrapped_group_key"]),
                            asy_padding.OAEP(mgf=asy_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                        )
                        self.group_keys[gid] = key
                        print(f"[group] received key for {gid} 🔑")
                    except Exception as e:
                        print(f"[group] key unwrap failed for {gid}: {e}")

            elif t == T_USER_LIST:
                users = pl.get("users", [])
                if not users:
                    print("[list] (none)")
                else:
                    print("[list]")
                    for u in users:
                        print(f"  - {u}")

            elif t == T_MSG_GROUP:
                gid = pl.get("group_id")
                key = self.group_keys.get(gid)
                if not key:
                    print(f"[group] missing key for {gid}"); continue
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    pt = AESGCM(key).decrypt(b64u_decode(pl["iv"]),
                                            b64u_decode(pl["ciphertext"])+b64u_decode(pl["tag"]),
                                            None)
                    text = pt.decode("utf-8", errors="replace")
                except Exception as e:
                    text = f"<decrypt failed: {e}>"
                # signature badge (reuse your badge logic)
                from crypto import RSAKeys as _Keys
                signed_ts = pl.get("content_ts", msg.get("ts"))
                content_obj = {
                    "group_id": gid,
                    "ciphertext": pl.get("ciphertext"),
                    "iv": pl.get("iv"),
                    "tag": pl.get("tag"),
                    "from": pl.get("from"), 
                    "ts": signed_ts,
                }
                verified = _Keys.verify_payload(pl.get("sender_pub",""), content_obj, pl.get("content_sig",""))
                badge = "🔐" if verified else "⚠️"
                print(f"[(Group) {gid}] {badge} {text}")

            elif t == T_FILE_START:
                await self._handle_file_start(pl)      # sets up recv_files[file_id]
            elif t == T_FILE_CHUNK:
                await self._handle_file_chunk(pl)      # decrypt + write + progress
            elif t == T_FILE_END:
                await self._handle_file_end(pl)        # close file, print saved path
            elif t == T_ERROR:
                print(f"[server error] {pl.get('code')}: {pl.get('detail')}")

    async def _stdin(self) -> None:
        """Reads commands from stdin and dispatches protocol actions

        Raises:
            EOFError: If stdin closes
        """

        assert self.ws
        loop = asyncio.get_event_loop()
        print("/help for commands")
        while self.ws and self.ws.open:
            try:
                line = await loop.run_in_executor(None, input)
            except Exception:
                await asyncio.sleep(0.2)
                continue
            
            line = (line or "").strip()
            if not line: continue
            
            if line == "/quit":
                await self.ws.close(); break
            
            if line == "/help":
                help_items = [
                    ("/help",                                   "list all available commands"),
                    ("/list",                                   "fetch & display known online users (sorted)"),
                    ("/pubget",                                 "print your own public key (SPKI DER base64url)"),
                    ("/dbget <user_uuid>",                      "fetch & cache <user>'s pubkey via Master (run before /msg or /gshare)"),
                    ("/msg <user_uuid> <text>",                 "send E2E-encrypted DM (AES-256-GCM + RSA-OAEP wrap + RSA-PSS signature)"),
                    ("/all <text>",                             "send to default group_global (requires /gshare group_global <members> once)"),
                    ("/gshare <group_id> <member1> [member2 ...]", "create/rotate group AES-256 key and send wrapped copies to members (requires /dbget for each)"),
                    ("/gmsg <group_id> <text>",                 "send E2E group message using the current group key (requires prior /gshare)"),
                    ("/file <user_uuid|group_id> <file_path>", "send file: DM wraps a per-file AES key to user; group uses group key; chunks via FILE_* frames"),
                    ("/quit",                                   "close the WebSocket and exit"),
                ]
                col = max(len(cmd) for cmd, _ in help_items) + 2        # pad before '#'
                for cmd, desc in help_items:
                    print(f"{cmd.ljust(col)}# {desc}")
                continue
            
            if line == "/list":
                await self._list(); continue

            if line == "/pubget":
                print(self.keys.pub_der_b64u()); continue
            
            if line.startswith("/dbget "):
                _, user = line.split(" ", 1)
                await self._db_get(user); continue
            
            if line.startswith("/msg "):
                try: _, user, text = line.split(" ", 2)
                except ValueError:
                    print("usage: /msg <user_uuid> <text>"); continue
                await self._send_dm(user, text); continue
            
            if line.startswith("/all "):
                # default group name (you may change this if your cohort picked another)
                gid = "group_global"
                if gid not in self.group_keys:
                    print("missing group key for group_global; run:")
                    print("  /list  # see online users")
                    print("  /gshare group_global <member1> [member2 ...]")
                    continue
                try: _, text = line.split(" ", 1)
                except ValueError:
                    print("usage: /all <text>"); continue
                await self._gmsg(gid, text); continue

            if line.startswith("/gshare "):
                try:
                    _, rest = line.split(" ", 1)
                    gid, members_str = rest.split(" ", 1)
                    members = members_str.split()
                except ValueError:
                    print("usage: /gshare <group_id> <member1> [member2 ...]"); continue
                await self._gshare(gid, members); continue
            
            if line.startswith("/gmsg "):
                try:
                    _, gid, text = line.split(" ", 2)
                except ValueError:
                    print("usage: /gmsg <group_id> <text>"); continue
                await self._gmsg(gid, text); continue
            
            if line.startswith("/file "):
                try: _, target, path = line.split(" ", 2)
                except ValueError:
                    print("usage: /file <user|group_id> <file_path>"); continue
                await self._fsend(target, pathlib.Path(path)); continue
            print("unknown command; /help")

    async def _list(self) -> None:
        """Requests the server’s current view of online users and prints them."""
        assert self.ws
        req = {
            "type": T_USER_LIST_REQ,
            "from": self.user_uuid,
            "to":   "server_*",
            "ts":   int(time.time()*1000),
            "payload": {},
            "sig": "",
        }
        await self.ws.send(json.dumps(req, separators=(",",":")))

    async def _db_get(self, user: str) -> None:
        """Requests a user's public key from the Master via the server

        Args:
            user (str): Target user UUID to look up
        """

        assert self.ws
        env = {
            "type": T_USER_DB_GET,
            "from": self.user_uuid,
            "to":   "server_*",
            "ts":   int(time.time()*1000),
            "payload": {"user_id": user},
            "sig": "",
        }
        await self.ws.send(json.dumps(env, separators=(',',':')))

    async def _send_dm(self, target: str, text: str) -> None:
        """Encrypts, signs, and sends a direct message to the target user

        Args:
            target (str): Recipient user UUID (must have a cached pubkey)
            text (str): Plaintext message to send (UTF-8)
        """

        assert self.ws
        if target not in self.keyring:
            print("unknown recipient key; try /dbget <user> first")
            return
        bundle = e2e_encrypt_for(self.keyring[target], text.encode('utf-8'))
        content_obj = {
            "ciphertext": bundle["ciphertext"],
            "iv": bundle["iv"],
            "tag": bundle["tag"],
            "from": self.user_uuid,
            "to": target,
            "ts": int(time.time()*1000),
        }
        content_sig = self.keys.sign_payload(content_obj)
        payload = {
            **bundle, 
            "sender_pub": self.keys.pub_der_b64u(), 
            "content_sig": content_sig,
            "content_ts": content_obj["ts"]
        }
        env = {
            "type": T_MSG_PRIVATE,
            "from": self.user_uuid,
            "to":   target,
            "ts":   content_obj["ts"],
            "payload": payload,
            "sig": "",
        }
        await self.ws.send(json.dumps(env, separators=(',',':')))
        print(f"[you -> {target}] {text}")

    async def _gshare(self, gid: str, members: list[str]) -> None:
        """Distributes a new group key to members by wrapping it under each member's RSA key

        Args:
            gid (str): Group identifier
            members (list[str]): User UUIDs (must have been /dbget'ed)
        """

        import os, time, json
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
        from encoding import b64u_encode, b64u_decode

        # Ensure we know everyone’s pubkey
        missing = [m for m in members if m not in self.keyring]
        if missing:
            print("missing pubkeys for:", ", ".join(missing))
            return

        # Create a fresh 256-bit group key and cache it locally
        key = os.urandom(32)
        self.group_keys[gid] = key

        # Wrap the GROUP KEY directly with RSA-OAEP(SHA-256) for each member
        shares = []
        for m in members:
            pub = serialization.load_der_public_key(b64u_decode(self.keyring[m]))
            wrapped = pub.encrypt(
                key,
                asy_padding.OAEP(
                    mgf=asy_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            shares.append({"member": m, "wrapped_group_key": b64u_encode(wrapped)})

        # Sign the content (group_id|shares|creator_pub)
        content_obj = {
            "group_id": gid,
            "shares": shares,
            "creator_pub": self.keys.pub_der_b64u(),
            "creator": self.user_uuid,
        }
        content_sig = self.keys.sign_payload(content_obj)

        env = {
            "type": T_GROUP_KEY_SHARE,
            "from": self.user_uuid,
            "to": "server_*",
            "ts": int(time.time()*1000),
            "payload": {**content_obj, "content_sig": content_sig},
            "sig": "",
        }
        await self.ws.send(json.dumps(env, separators=(",", ":")))
        print(f"[group] shared key for {gid} → {', '.join(members)}")

    async def _gmsg(self, gid: str, text: str) -> None:
        """Encrypts and sends a group message using the stored group key

        Args:
            gid (str): Group identifier
            text (str): Message
        """

        key = self.group_keys.get(gid)
        if not key:
            print("missing group key; run /gshare first"); return
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os
        iv = os.urandom(12)
        ct_tag = AESGCM(key).encrypt(iv, text.encode("utf-8"), None)
        ciphertext, tag = ct_tag[:-16], ct_tag[-16:]
        ts = int(time.time()*1000)
        content_obj = {
            "group_id": gid,
            "ciphertext": b64u_encode(ciphertext),
            "iv": b64u_encode(iv),
            "tag": b64u_encode(tag),
            "from": self.user_uuid,
            "ts": ts,
        }
        content_sig = self.keys.sign_payload(content_obj)
        payload = {**content_obj, "sender_pub": self.keys.pub_der_b64u(), "content_sig": content_sig, "content_ts": ts}
        env = {"type": T_MSG_GROUP, "from": self.user_uuid, "to": f"{gid}", "ts": ts, "payload": payload, "sig": ""}
        await self.ws.send(json.dumps(env, separators=(",",":")))
        print(f"[you -> (Group) {gid}] {text}")

    async def _fsend(self, target: str, path: pathlib.Path) -> None:
        """Sends a file to a DM target or a group (chunked, AES-256-GCM)

        Args:
            target (str): user UUID or group_<id>
            path (pathlib.Path): file path
        """

        if not path.exists() or not path.is_file():
            print("file not found"); return
        data = path.read_bytes()
        import hashlib, os
        sha = hashlib.sha256(data).hexdigest()
        mode = "group" if target.startswith("group_") else "dm"

        # Manifest
        pl = {
            "file_id": str(uuid.uuid4()),
            "name": path.name,
            "size": len(data),
            "sha256": sha,
            "mode": mode,
        }
        if mode == "group":
            gid = target
            pl["group_id"] = gid
            if gid not in self.group_keys:
                print("missing group key; run /gshare first"); return
        env = {"type": T_FILE_START, "from": self.user_uuid, "to": (target if mode=="dm" else gid),
            "ts": int(time.time()*1000), "payload": pl, "sig": ""}
        await self.ws.send(json.dumps(env, separators=(",",":")))
        # Encrypt & chunk
        CHUNK = 60 * 1024
        if mode == "dm":
            # per-spec: DM chunks include wrapped_key; use one AES key for whole file
            bundle_key = e2e_encrypt_for(self.keyring.get(target,""), b"\x00"*32)  # placeholder to get structure?
            # Better: generate key yourself and wrap once:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = os.urandom(32)
            # wrap key for target
            if target not in self.keyring:
                print("unknown recipient key; run /dbget first"); return
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
            wrapped = serialization.load_der_public_key(b64u_decode(self.keyring[target])).encrypt(
                key, asy_padding.OAEP(mgf=asy_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            for i in range(0, len(data), CHUNK):
                chunk = data[i:i+CHUNK]
                iv = os.urandom(12)
                ct = AESGCM(key).encrypt(iv, chunk, None)
                payload = {
                    "file_id": pl["file_id"],
                    "index": i//CHUNK,
                    "ciphertext": b64u_encode(ct[:-16]),
                    "iv": b64u_encode(iv),
                    "tag": b64u_encode(ct[-16:]),
                    "wrapped_key": b64u_encode(wrapped),
                }
                env = {"type": T_FILE_CHUNK, "from": self.user_uuid, "to": target, "ts": int(time.time()*1000),
                    "payload": payload, "sig": ""}
                await self.ws.send(json.dumps(env, separators=(",",":")))
        else:
            # group: use stored group key; no wrapped_key per chunk
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = self.group_keys[target]
            for i in range(0, len(data), CHUNK):
                chunk = data[i:i+CHUNK]
                iv = os.urandom(12)
                ct = AESGCM(key).encrypt(iv, chunk, None)
                payload = {
                    "file_id": pl["file_id"],
                    "index": i//CHUNK,
                    "ciphertext": b64u_encode(ct[:-16]),
                    "iv": b64u_encode(iv),
                    "tag": b64u_encode(ct[-16:]),
                }
                env = {"type": T_FILE_CHUNK, "from": self.user_uuid, "to": target, "ts": int(time.time()*1000),
                    "payload": payload, "sig": ""}
                await self.ws.send(json.dumps(env, separators=(",",":")))

        # End
        env = {"type": T_FILE_END, "from": self.user_uuid, "to": (target if mode=="dm" else gid),
            "ts": int(time.time()*1000), "payload": {"file_id": pl["file_id"]}, "sig": ""}
        await self.ws.send(json.dumps(env, separators=(",",":")))
        print(f"[file] sent {path.name} → {target}")

    async def _handle_file_chunk(self, pl: dict) -> None:
        """Processes a single FILE_CHUNK frame: decrypts the chunk and appends it to the open file

        Args:
            pl (dict): Chunk payload with:
                - file_id (str): Transfer identifier matching a prior FILE_START
                - index (int): Zero-based chunk index
                - ciphertext (str): Base64url-encoded AES-GCM ciphertext
                - iv (str): Base64url-encoded 12-byte nonce
                - tag (str): Base64url-encoded 16-byte GCM tag
                - wrapped_key (str, optional): RSA-OAEP(SHA-256)-wrapped AES key (present in DM mode only)
        """
        file_id = pl.get("file_id")
        idx = int(pl.get("index", 0))
        ciphertext = pl.get("ciphertext")
        iv = pl.get("iv")
        tag = pl.get("tag")
        wrapped_key = pl.get("wrapped_key", None)

        st = self.recv_files.get(file_id)
        if not st:
            print(f"[file] unexpected chunk #{idx}")
            return

        try:
            # Decrypt chunk
            if wrapped_key:
                # DM case: RSA-OAEP wrapped AES key per file (same wrapped_key on each chunk)
                pt = e2e_decrypt_with(self.keys.priv, pl)
            else:
                # Group case: use stored group key (no wrapped_key)
                key = self.group_keys[st["group_id"]]
                ct_tag = b64u_decode(ciphertext) + b64u_decode(tag)
                pt = AESGCM(key).decrypt(b64u_decode(iv), ct_tag, None)

            # Write plaintext to the open file handle
            st["fh"].write(pt)

            # Progress
            st["received"] += len(pt)
            pct = (st["received"] / max(st["size"], 1)) * 100
            print(f"[file] chunk #{idx+1} ({st['received']}/{st['size']} bytes, {pct:.0f}%)")

        except Exception as e:
            print(f"[file] decrypt failed for chunk #{idx}: {e}")

    async def _handle_file_start(self, pl: dict) -> None:
        """Initializes receiver state for an incoming file and opens the output file

        Args:
            pl (dict): Manifest payload with:
                - file_id (str): Transfer identifier (unique per file)
                - name (str): Original filename (used for saving)
                - size (int): Total plaintext size in bytes
                - mode (str): "dm" or "group" (determines decryption path)
                - group_id (str, optional): Group identifier if mode == "group"
        """
        fid   = pl.get("file_id")
        name  = pl.get("name", f"{fid}.bin")
        size  = pl.get("size", 0)
        mode  = pl.get("mode", "dm")
        gid   = pl.get("group_id")

        downloads = Path("downloads"); downloads.mkdir(parents=True, exist_ok=True)
        safe_name = name.split("/")[-1]  # strip any path components
        path = downloads / safe_name
        if path.exists():
            i = 1
            stem, ext = path.stem, path.suffix
            while path.exists():
                path = downloads / f"{stem}({i}){ext}"
                i += 1

        fh = open(path, "wb")
        self.recv_files[fid] = {"fh": fh, "path": path, "mode": mode, "group_id": gid, "size": size, "received": 0}
        print(f"[file] start {safe_name} ({size} bytes)")

    async def _handle_file_end(self, pl: dict) -> None:
        """Finalizes an incoming file transfer: closes the file handle and reports the saved path."""
        
        if st := self.recv_files.pop(pl.get("file_id"), None):
            st["fh"].close()
            print(f"[file] end → saved to {st['path']}")
