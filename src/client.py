from __future__ import annotations

import os
import sys
import asyncio
import json
import pathlib
import time
import uuid
import hashlib
import websockets

from pathlib import Path
from protocols import *
from crypto import RSAKeys, e2e_encrypt_for, e2e_decrypt_with
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from encoding import b64u_encode, b64u_decode

"""
SOCP Client (v1.1)

- Connects to one local server over WebSocket
- Sends USER_HELLO on connect
- Commands: /help, /pubget, /dbget <user>, /tell <user> <text>, /quit
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

            elif t == T_USER_LIST:
                users = pl.get("users") or []
                print("[online]")
                for u in users:
                    print(f" - {u}")

            elif t == T_PUBLIC_POST:
                p = pl
                # Verify signature over canonical content
                from crypto import RSAKeys as _Keys
                content_obj = {
                    "channel": p.get("channel", "public"),
                    "text": p.get("text", ""),
                    "from": p.get("from"),
                    "ts": p.get("ts"),
                }
                ok = _Keys.verify_payload(p.get("sender_pub", ""), content_obj, p.get("content_sig", ""))
                # Ignore our own echo (we already print “[you ->  Public Channel] ...”)
                if p.get("from") == self.user_uuid:
                    continue
                badge = "🔐" if ok else "⚠️"
                print(f"[Public Channel] {badge} {p.get('from')}: {p.get('text')}")
                
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
                    ("/dbget <user_uuid>",                      "fetch & cache <user>'s pubkey via Master (run before /tell)"),
                    ("/tell <user_uuid> <text>",                "send E2E-encrypted DM (AES-256-GCM + RSA-OAEP wrap + RSA-PSS signature)"),
                    ("/all <text>",                             "post to the mesh-wide public channel (authentic, not confidential)"),
                    ("/file <user_uuid|public> <file_path>",    "send file: DM wraps per-file AES key; 'public' is broadcast (no secrecy)"),
                    ("/quit",                                   "close the WebSocket and exit"),
                ]
                col = max(len(cmd) for cmd, _ in help_items) + 2
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
            
            if line.startswith("/tell "):
                try: _, user, text = line.split(" ", 2)
                except ValueError:
                    print("usage: /tell <user_uuid> <text>"); continue
                await self._send_dm(user, text); continue
            
            if line.startswith("/all "):
                _, text = line.split(" ", 1)
                await self._all(text)
                continue

            if line.startswith("/file "):
                try: _, target, path = line.split(" ", 2)
                except ValueError:
                    print("usage: /file <user_uuid|public> <file_path>"); continue
                
            await self._fsend(target, pathlib.Path(path))
            continue

    async def _list(self) -> None:
        """Requests a list of known-online users from the server."""
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

    async def _all(self, text: str) -> None:
        """Sends a message to the mesh-wide public channel.

        Args:
            text (str): UTF-8 plaintext to post publicly.
        """

        assert self.ws
        # Per your spec style: we still use end-to-end content signature; server does not decrypt.
        # For simplicity and to keep payload small, we send plaintext with PSS content_sig;
        # confidentiality on a public channel is not required; integrity/authenticity is.

        ts = int(time.time() * 1000)
        content_obj = {
            "channel": "public",
            "text": text,
            "from": self.user_uuid,
            "ts": ts,
        }
        content_sig = self.keys.sign_payload(content_obj)
        payload = {
            **content_obj,
            "sender_pub": self.keys.pub_der_b64u(),
            "content_sig": content_sig,
        }
        env = {
            "type": "PUBLIC_POST",
            "from": self.user_uuid,
            "to": "server_*",
            "ts": ts,
            "payload": payload,
            "sig": "",     # transport sig not required on user->server link (TLS-equivalent); your server signs on peer hops
        }
        await self.ws.send(json.dumps(env, separators=(",", ":")))
        print(f"[you ->  Public Channel] {text}")

    async def _fsend(self, target: str, path: pathlib.Path) -> None:
        """Sends a file either as a DM (RSA-OAEP wrapped per-file key) or to the
        Public Channel (single per-file key published in FILE_START).

        Args:
            target (str): User UUID for DM, or 'public' for the public channel.
            path (pathlib.Path): Path to the file to send.
        """

        if not path.exists() or not path.is_file():
            print("file not found")
            return

        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        ts = int(time.time() * 1000)
        file_id = str(uuid.uuid4())

        # Mode selection
        is_public = (target.lower() == "public")
        mode = "public" if is_public else "dm"
        to_field = ("public" if is_public else target)

        # Per-file AES key
        file_key = os.urandom(32)

        # Manifest (FILE_START)
        pl_start = {
            "file_id": file_id,
            "name": path.name,
            "size": len(data),
            "sha256": sha,
            "mode": mode,
        }
        if is_public:
            # Publish the per-file AES key once for all receivers (public channel).
            pl_start["pub_key"] = b64u_encode(file_key)

        env_start = {
            "type": T_FILE_START,
            "from": self.user_uuid,
            "to": to_field,
            "ts": ts,
            "payload": pl_start,
            "sig": "",
        }
        await self.ws.send(json.dumps(env_start, separators=(",", ":")))

        # Encrypt & send chunks
        CHUNK = 60 * 1024
        if not is_public:
            # DM: wrap the per-file AES key for the recipient
            if target not in self.keyring:
                print("unknown recipient key; run /dbget <user> first")
                return
            recip_pub = serialization.load_der_public_key(b64u_decode(self.keyring[target]))
            wrapped = recip_pub.encrypt(
                file_key,
                asy_padding.OAEP(
                    mgf=asy_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            wrapped_b64 = b64u_encode(wrapped)

        for i in range(0, len(data), CHUNK):
            chunk = data[i : i + CHUNK]
            iv = os.urandom(12)
            ct_tag = AESGCM(file_key).encrypt(iv, chunk, None)
            payload = {
                "file_id": file_id,
                "index": i // CHUNK,
                "ciphertext": b64u_encode(ct_tag[:-16]),
                "iv": b64u_encode(iv),
                "tag": b64u_encode(ct_tag[-16:]),
            }
            if not is_public:
                payload["wrapped_key"] = wrapped_b64  # DM only

            env_chunk = {
                "type": T_FILE_CHUNK,
                "from": self.user_uuid,
                "to": to_field,
                "ts": int(time.time() * 1000),
                "payload": payload,
                "sig": "",
            }
            await self.ws.send(json.dumps(env_chunk, separators=(",", ":")))

        # Finish (FILE_END)
        env_end = {
            "type": T_FILE_END,
            "from": self.user_uuid,
            "to": to_field,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": file_id},
            "sig": "",
        }
        await self.ws.send(json.dumps(env_end, separators=(",", ":")))

        human_to = "Public Channel" if is_public else target
        print(f"[file] sent {path.name} → {human_to}")

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
            if st["mode"] == "public":
                # Public: decrypt with per-file key from manifest
                key = st.get("public_key")
                if not key:
                    raise ValueError("missing public_key from FILE_START")
                ct_tag = b64u_decode(ciphertext) + b64u_decode(tag)
                pt = AESGCM(key).decrypt(b64u_decode(iv), ct_tag, None)
            elif wrapped_key:
                # DM: RSA-OAEP wrapped per-file key
                pt = e2e_decrypt_with(self.keys.priv, pl)
            else:
                raise ValueError("no decryption key available for this mode")

            st["fh"].write(pt)
            st["received"] += len(pt)
            pct = (st["received"] / max(st["size"], 1)) * 100
            print(f"[file] chunk #{idx+1} ({st['received']}/{st['size']} bytes, {pct:.0f}%)")

        except Exception as e:
            print(f"[file] decrypt failed for chunk #{idx}: {e}")

    async def _handle_file_start(self, pl: dict) -> None:
        """Initializes receiver-side state for an incoming FILE_START and opens the
        destination file for writing, using non-clobbering names like 'file.pdf',
        'file (1).pdf'...  For public channel, prefixes with '<receiver>_'.

        Args:
            pl (dict): FILE_START payload with keys:
                - file_id (str) : unique file id
                - name (str)    : sender's filename
                - size (int)    : total bytes
                - mode (str)    : 'dm' | 'group' | 'public'
                - group_id (str, optional)
                - pub_key (str, optional; base64url)  # public mode only
        """

        fid   = pl.get("file_id")
        name  = pl.get("name", f"{fid}.bin")
        size  = pl.get("size", 0)
        mode  = pl.get("mode", "dm")
        sender = pl.get("sender") or "unknown"
        public_key = None

        downloads = Path("downloads")
        downloads.mkdir(parents=True, exist_ok=True)

        # Prefix & capture per-file key for public channel
        if mode == "public":
            name = f"{sender}_{name}"
            pub_key_b64 = pl.get("pub_key") or ""
            try:
                public_key = b64u_decode(pub_key_b64)
            except Exception:
                public_key = None

        # split path and add (1), (2), ... to avoid clobber
        base = downloads / name
        if base.exists():
            stem = base.stem
            suffix = base.suffix
            k = 1
            while True:
                candidate = downloads / f"{stem} ({k}){suffix}"
                if not candidate.exists():
                    base = candidate
                    break
                k += 1

        fh = open(base, "wb")
        self.recv_files[fid] = {
            "fh": fh,
            "path": base,
            "mode": mode,
            "size": size,
            "received": 0,
            "sender": sender,
            "public_key": public_key
        }

        print(f"[file] from {sender}: start {base.name} ({size} bytes)")

    async def _handle_file_end(self, pl: dict) -> None:
        """Finalizes an incoming file transfer: closes the file handle and reports the saved path."""
        
        if st := self.recv_files.pop(pl.get("file_id"), None):
            st["fh"].close()
            print(f"[file] end → saved to {st['path']}")
