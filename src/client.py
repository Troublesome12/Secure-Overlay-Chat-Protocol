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
from crypto import  RSAKeys, rsa_encrypt, rsa_decrypt, rsa_chunk_iter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from encoding import b64u_encode, b64u_decode


"""
SOCP Client (v1.3)

- Connects to one local server over WebSocket
- Sends USER_HELLO on connect
- Commands: /help, /pubget, /dbget <user>, /tell <user> <text>, /all <text>, /file <user> <path>, /quit
- DMs: RSA-OAEP(SHA-256) for the key, RSASSA-PSS(SHA-256) signature
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
        self._send_lock = asyncio.Lock()

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
            hb = asyncio.create_task(self._heartbeat())

            await self.ws.wait_closed()   # stay alive until /quit or server closes
            for t in (consumer, producer, hb) if producer else (consumer, hb): t.cancel()

    async def _recv(self) -> None:
        """Receives and processes server frames (USER_DELIVER / USER_DB_USER / ERROR)
        
        Raises:
            Exception: If socket operations fail unexpectedly (internal errors are mostly caught)
        """

        assert self.ws
        async for raw in self.ws:
            try: msg = json.loads(raw)
            except Exception: continue
            t = msg.get("type")
            pl = msg.get("payload", {})
            
            if t == T_USER_DELIVER:
                sender = pl.get("sender")
                sender_pub = pl.get("sender_pub", "")

                # Verify signature over minimal canonical fields (no iv/tag/wrapped_key)
                verified = False
                try:
                    content_obj = {
                        "ciphertext": pl.get("ciphertext"),
                        "from": sender,
                        "to":   self.user_uuid,
                        "ts":   pl.get("content_ts", msg.get("ts")),
                    }
                    verified = RSAKeys.verify_payload(sender_pub, content_obj, pl.get("content_sig",""))
                except Exception:
                    verified = False

                # Decrypt with our RSA private key
                try:
                    pt = rsa_decrypt(self.keys.priv, pl["ciphertext"])
                    text = pt.decode("utf-8", errors="replace")
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

            elif t == T_MSG_PUBLIC_CHANNEL:
                p = pl
                content_obj = {
                    "channel": p.get("channel"),
                    "text": p.get("text"),
                    "from": p.get("from"),
                    "ts": p.get("ts"),
                }
                ok = RSAKeys.verify_payload(p.get("sender_pub",""), content_obj, p.get("content_sig",""))
                if p.get("from") == self.user_uuid:
                    continue
                badge = "🔐" if ok else "⚠️"
                # If your public messages are plaintext, change printed field accordingly
                print(f"[Public Channel] {badge} {p.get('from')}: {p.get('text') or '<encrypted>'}")
                
            elif t == T_FILE_START:
                await self._handle_file_start(pl)      # sets up recv_files[file_id]
            elif t == T_FILE_CHUNK:
                await self._handle_file_chunk(pl)      # decrypt + write + progress
            elif t == T_FILE_END:
                await self._handle_file_end(pl)        # close file, print saved path
            elif t == T_ERROR:
                print(f"[server error] {pl.get('code')}: {pl.get('detail')}")
            elif t == T_DUMP_USERS:
                print(f"[server message] {pl.get('users', '')}")
        
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

            if not line:
                continue
            line = line.strip()

            # Require commands to start with '/'
            if not line.startswith("/"):
                print("unknown input (commands start with '/'). Try /help")
                continue

            # Simple exact commands first
            if line == "/quit":
                await self.ws.close()
                break

            if line == "/help":
                help_items = [
                    ("/help",                                   "list all available commands"),
                    ("/list",                                   "fetch & display known online users (sorted)"),
                    ("/pubget",                                 "print your own public key (SPKI DER base64url)"),
                    ("/dbget <user_uuid>",                      "fetch & cache <user>'s pubkey via Master (run before /tell)"),
                    ("/tell <user_uuid> <text>",                "send E2E-encrypted DM (RSA-4096 OAEP + RSA-PSS signature)"),
                    ("/all <text>",                             "post to the mesh-wide public channel (authentic, not confidential)"),
                    ("/file <user_uuid|public> <file_path>",    "send file: DM per-chunk RSA; 'public' = plaintext (signed manifest)"),
                    ("/quit",                                   "close the WebSocket and exit"),
                ]
                col = max(len(cmd) for cmd, _ in help_items) + 2
                for cmd, desc in help_items:
                    print(f"{cmd.ljust(col)}# {desc}")
                continue

            if line == "/list":
                try:
                    await self._list()
                except Exception as e:
                    print(f"[list] error: {e!r}")
                continue

            if line == "/pubget":
                print(self.keys.pub_der_b64u())
                continue
            
            if line == "/dump":
                try: 
                    await self.ws.send(json.dumps({
                        "type": T_DUMP_USERS,
                        "from": self.user_uuid,
                        "to":   "server_*",
                        "ts":   int(time.time()*1000),
                        "payload": {},
                        "sig": "",
                    }, separators=(",",":")))
                except: continue
            
            # Commands with arguments
            if line.startswith("/dbget "):
                try:
                    _, user = line.split(" ", 1)
                    await self._db_get(user.strip())
                except Exception as e:
                    print(f"usage: /dbget <user_uuid>  ({e})")
                continue

            if line.startswith("/tell "):
                try:
                    # split once for the user, then keep the rest as text (allows spaces)
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        raise ValueError("missing text")
                    _, user, text = parts
                    await self._send_dm(user.strip(), text)
                except Exception as e:
                    print(f"usage: /tell <user_uuid> <text>  ({e})")
                continue

            if line.startswith("/all "):
                try:
                    _, text = line.split(" ", 1)
                    await self._all(text)
                except Exception as e:
                    print(f"usage: /all <text>  ({e})")
                continue

            if line.startswith("/file "):
                try:
                    # Keep paths with spaces: split into 3 parts max
                    parts = line.split(" ", 2)
                    if len(parts) < 3:
                        raise ValueError("missing target or file_path")
                    _, target, path_str = parts
                    await self._fsend(target.strip(), pathlib.Path(path_str.strip()))
                except Exception as e:
                    print(f"usage: /file <user_uuid|public> <file_path>  ({e})")
                continue

            # Fallback for anything else
            print("unknown command. Try /help")

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

        ts = int(time.time() * 1000)
        ciphertext = rsa_encrypt(self.keyring[target], text.encode("utf-8"))

        content_obj = {
            "ciphertext": ciphertext,
            "from": self.user_uuid,
            "to": target,
            "ts": ts,
        }
        content_sig = self.keys.sign_payload(content_obj)

        env = {
            "type": T_MSG_DIRECT,
            "from": self.user_uuid,
            "to":   target,
            "ts":   ts,
            "payload": {
                "ciphertext": ciphertext,
                "sender_pub": self.keys.pub_der_b64u(),
                "content_sig": content_sig,
                "content_ts": ts,
            },
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
            "type": T_MSG_PUBLIC_CHANNEL,
            "from": self.user_uuid,
            "to": "server_*",
            "ts": ts,
            "payload": payload,
            "sig": "",     # transport sig not required on user->server link (TLS-equivalent); your server signs on peer hops
        }
        await self.ws.send(json.dumps(env, separators=(",", ":")))
        print(f"[you ->  Public Channel] {text}")

    async def _fsend(self, target: str, path: pathlib.Path) -> None:
        """Send file: RSA-OAEP only (no AES). DM = per-chunk RSA; Public = plaintext.

        - DM: include `wrapped_key` in EVERY chunk (receiver expects it per-chunk).
        - Public: include `pub_key` (base64url AES key) in FILE_START; no wrapped_key in chunks.
        - Manifest is signed (v1.3) with RSASSA-PSS over canonical fields.
        """

        if not path.exists() or not path.is_file():
            print("file not found"); return

        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        ts = int(time.time() * 1000)
        file_id = str(uuid.uuid4())

        is_public = (target.lower() == "public")
        mode = "public" if is_public else "dm"
        to_field = "public" if is_public else target

        # For DM ensure we have recip key
        if not is_public and target not in self.keyring:
            print("unknown recipient key; run /dbget <user> first"); return

        # Manifest (no AES pub_key etc). We still sign the manifest for integrity/authenticity.
        pl_start = {
            "file_id": file_id,
            "name": path.name,
            "size": len(data),
            "sha256": sha,
            "mode": mode,
            "sender": self.user_uuid,
            "ts": ts,
            "sender_pub": self.keys.pub_der_b64u(),
        }
        manifest_to_sign = {
            "file_id": file_id,
            "name": path.name,
            "size": len(data),
            "sha256": sha,
            "mode": mode,
            "sender": self.user_uuid,
            "ts": ts,
        }
        pl_start["content_sig"] = self.keys.sign_payload(manifest_to_sign)

        env_start = {
            "type": T_FILE_START,
            "from": self.user_uuid,
            "to": to_field,
            "ts": ts,
            "payload": pl_start,
            "sig": "",
        }
        await self.ws.send(json.dumps(env_start, separators=(",", ":")))

        # Chunk & send
        # Max safe payload per RSA chunk depends on padding; assume rsa_chunk_iter enforces it.
        for idx, chunk in rsa_chunk_iter(data) if not is_public else enumerate([data], start=0) if len(data) == 0 else enumerate([data[i:i+4096] for i in range(0, len(data), 4096)], start=0):
            if is_public:
                # plaintext (base64) chunk
                ct = b64u_encode(chunk)
            else:
                ct = rsa_encrypt(self.keyring[target], chunk)

            pl_chunk = {
                "file_id": file_id,
                "index": idx,
                "ciphertext": ct,
                # no iv/tag/wrapped_key
            }
            env_chunk = {
                "type": T_FILE_CHUNK,
                "from": self.user_uuid,
                "to": to_field,
                "ts": int(time.time() * 1000),
                "payload": pl_chunk,
                "sig": "",
            }
            await self.ws.send(json.dumps(env_chunk, separators=(",", ":")))

        # End
        env_end = {
            "type": T_FILE_END,
            "from": self.user_uuid,
            "to": to_field,
            "ts": int(time.time() * 1000),
            "payload": {"file_id": file_id},
            "sig": "",
        }
        await self.ws.send(json.dumps(env_end, separators=(",", ":")))
        print(f"[file] sent {path.name} → {'Public Channel' if is_public else target}")

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

        fid = pl.get("file_id"); idx = int(pl.get("index", 0))
        st = self.recv_files.get(fid)
        if not st:
            print(f"[file] unexpected chunk #{idx}")
            return

        try:
            if st["mode"] == "public":
                # plaintext: base64url decode and write
                pt = b64u_decode(pl["ciphertext"])
            else:
                # DM: RSA decrypt per chunk
                pt = rsa_decrypt(self.keys.priv, pl["ciphertext"])

            st["fh"].write(pt)
            st["received"] += len(pt)
            pct = (st["received"] / max(st["size"], 1)) * 100
            print(f"[file] chunk #{idx+1} ({st['received']}/{st['size']} bytes, {pct:.0f}%)")
        except Exception as e:
            print(f"[file] decrypt failed for chunk #{idx}: {e}")

    async def _handle_file_start(self, pl: dict) -> None:
        """Prepare to receive a file.

        Naming:
        - DM: keep original filename (e.g., demo.txt)
        - Public: prefix with receiver name (e.g., Alice_demo.txt)
        """

        fid    = pl.get("file_id")
        orig   = pl.get("name", f"{fid}.bin")
        size   = pl.get("size", 0)
        mode   = pl.get("mode", "dm")
        sender = pl.get("sender") or "unknown"

        name = f"{self.user_uuid}_{orig}" if mode == "public" else orig

        downloads = Path("downloads"); downloads.mkdir(parents=True, exist_ok=True)
        base = downloads / name
        if base.exists():
            stem, suffix = base.stem, base.suffix
            k = 1
            while True:
                cand = downloads / f"{stem} ({k}){suffix}"
                if not cand.exists():
                    base = cand; break
                k += 1

        fh = open(base, "wb")
        self.recv_files[fid] = {
            "fh": fh, "path": base, "mode": mode, "size": size,
            "received": 0, "sender": sender
        }
        print(f"[file] from {sender}: start {base.name} ({size} bytes)")

    async def _handle_file_end(self, pl: dict) -> None:
        """Finalizes an incoming file transfer: closes the file handle and reports the saved path."""
        
        if st := self.recv_files.pop(pl.get("file_id"), None):
            st["fh"].close()
            print(f"[file] end → saved to {st['path']}")

    async def _heartbeat(self):
        """Send a lightweight heartbeat to the server periodically."""
        # If your protocols.py has T_HEARTBEAT, use it; otherwise "HEARTBEAT" literal works.
        hb_type = "HEARTBEAT" if "T_HEARTBEAT" not in globals() else T_HEARTBEAT
        assert self.ws
        while self.ws and self.ws.open:
            try:
                env = {
                    "type": hb_type,
                    "from": self.user_uuid,
                    "to": "server_*",
                    "ts": int(time.time() * 1000),
                    "payload": {},
                    "sig": "",
                }
                await self.ws.send(json.dumps(env, separators=(",", ":")))
            except Exception:
                break
            await asyncio.sleep(15)
