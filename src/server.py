from __future__ import annotations

import asyncio
import json
import pathlib
import uuid
import websockets
import hashlib

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any

from websockets.server import WebSocketServerProtocol

from protocols import *
from crypto import RSAKeys
from envelope import make_env
from db import MasterDB
        



"""SOCP Server (mesh peer)

Implements:
- Peer linking (PEER_HELLO_LINK)
- Presence gossip (USER_ADVERTISE / USER_REMOVE)
- DM routing (MSG_PRIVATE -> PEER_DELIVER / USER_DELIVER)
- Simple DB-RPC proxy to Master (DB_GET_USER, DB_REGISTER_USER)
"""

@dataclass
class Link:
    """Connection link wrapper

    Args:
        ws (websockets.WebSocketCommonProtocol): Underlying WebSocket
        kind (str): 'peer' or 'user'
        ident (str): server_uuid or user_uuid
    """

    ws: websockets.WebSocketCommonProtocol
    kind: str  # 'peer' or 'user'
    ident: str # server_uuid or user_uuid

class SOCPServer:
    def __init__(
        self,
        server_uuid: str,
        master_uuid: str,
        listen: str,
        key_path: pathlib.Path,
        peer_urls: list[str],
        db_path: Optional[pathlib.Path] = None,
    ):
        """Initializes a SOCP mesh server

        Args:
            server_uuid (str): This server's UUID (master_server_* or server_*)
            master_uuid (str): Cluster Master UUID (stable)
            listen (str): Bind address "host:port"
            key_path (pathlib.Path): RSA-4096 PEM path for this server
            peer_urls (list[str]): Outbound peer dial targets (ws://host:port)
            db_path (Optional[pathlib.Path]): Master JSON DB path (master-only)
        """

        self.server_uuid = server_uuid
        self.master_uuid = master_uuid
        self.is_master = (server_uuid == master_uuid)
        self.listen_host, self.listen_port = listen.split(":")
        self.keys = RSAKeys.load_or_create(key_path)
        self.peer_urls = set(peer_urls)
        self.db = MasterDB(db_path or pathlib.Path("data/master_db.json")) if self.is_master else None
        self.servers: Dict[str, Link] = {}
        self.server_addrs: Dict[str, Tuple[str, int]] = {}
        self.server_pubs: Dict[str, str] = {}
        self.local_users: Dict[str, Link] = {}
        self.user_locations: Dict[str, str] = {}
        self.pending_db: Dict[str, WebSocketServerProtocol] = {}
        self.handshakes_done: set[str] = set()
        self.ws_to_peeruuid: Dict[websockets.WebSocketCommonProtocol, str] = {}
        self.group_members: Dict[str, set[str]] = {}
        self.seen_ids: dict[str,int] = {}
        self.url_to_ws = {}
        self.ws_to_url = {}

    async def run(self) -> None:
        """Starts the WebSocket server and the dialer loop

        Raises:
            Exception: If the server cannot bind or serve
        """

        server = await websockets.serve(self._accept, self.listen_host, int(self.listen_port), ping_interval=20)
        print(f"[server {self.server_uuid}{' (MASTER)' if self.is_master else ''}] listening ws://{self.listen_host}:{self.listen_port}")
        asyncio.create_task(self._dial_loop())
        try:
            await asyncio.Event().wait()
        finally:
            server.close(); 
            await server.wait_closed()

    async def _dial_loop(self) -> None:
        """Periodically attempts outbound connections to configured peers

        Raises:
            Exception: Network errors are swallowed and retried later
        """

        while True:
            for url in list(self.peer_urls):
                if url in self.url_to_ws and not self.url_to_ws[url].closed:
                    continue        # already connected

                try:
                    ws = await websockets.connect(url, ping_interval=20)
                    self.url_to_ws[url] = ws
                    self.ws_to_url[ws] = url

                    hello = make_env(T_PEER_HELLO_LINK, self.server_uuid, "server_*", {
                        "host": self.listen_host,
                        "port": int(self.listen_port),
                        "pubkey": self.keys.pub_der_b64u(),
                        "role": "master" if self.is_master else "local",
                    }, self.keys)
                    await ws.send(json.dumps(hello, separators=(',',':')))
                    asyncio.create_task(self._peer_recv(ws))
                except Exception:
                    pass
            await asyncio.sleep(5)

    async def _accept(self, ws: WebSocketServerProtocol) -> None:
        """Accepts an incoming connection and dispatches by first frame type

        Args:
            ws (WebSocketServerProtocol): Newly accepted socket

        Raises:
            Exception: If the first frame cannot be received/parsed
        """

        try:
            raw = await ws.recv()
            msg = json.loads(raw)
            t = msg.get("type")

            if t == T_PEER_HELLO_LINK:
                await self._on_peer_hello(ws, msg)
                if ws.closed: return
                await self._peer_recv(ws)
            elif t == T_USER_HELLO:
                await self._on_user_hello(ws, msg)
                if ws.closed: return
                await self._user_recv(ws)
            else:
                await self._send_error(ws, E_UNKNOWN_TYPE, f"expected {T_PEER_HELLO_LINK} or {T_USER_HELLO}")
                await ws.close()
        except Exception:
            try: await ws.close()
            except Exception: pass

    async def _on_peer_hello(self, ws: websockets.WebSocketCommonProtocol, msg: Dict[str, Any]) -> None:
        """Registers/refreshes a peer on PEER_HELLO_LINK and (only on initial dial) replies

        Args:
            ws (websockets.WebSocketCommonProtocol): Peer socket
            msg (Dict[str, Any]): Parsed PEER_HELLO_LINK frame

        Raises:
            Exception: Network send/close errors may propagate (duplicates are closed best-effort).
        """

        pl = msg.get("payload", {}) or {}
        host = pl.get("host") or "?"
        try:
            port = int(pl.get("port") or 0)
        except Exception:
            port = 0
        pub = pl.get("pubkey") or ""
        peer_uuid = msg.get("from") or f"server_{uuid.uuid4()}"

        # Keep a single live socket per peer_uuid; drop newcomers.
        existing = self.servers.get(peer_uuid)
        if existing and existing.ws is not ws:
            try:
                await ws.close()
            except Exception:
                pass
            return

        first_time = existing is None

        # Register / refresh metadata and ws->peer mapping (for cleanup)
        self.servers[peer_uuid] = Link(ws, "peer", peer_uuid)
        self.server_addrs[peer_uuid] = (host, port)
        if pub:
            self.server_pubs[peer_uuid] = pub
        self.ws_to_peeruuid[ws] = peer_uuid  # for unpeer logging

        # Reply exactly once on initial dial so the dialer learns our UUID.
        # (Dialer sends to "server_*"; our reply targets their concrete peer_uuid,
        #  so there is no ping-pong.)
        if first_time and msg.get("to") == "server_*":
            hello_back = make_env(
                T_PEER_HELLO_LINK,
                self.server_uuid,
                peer_uuid,
                {
                    "host": self.listen_host,
                    "port": int(self.listen_port),
                    "pubkey": self.keys.pub_der_b64u(),
                    "role": "master" if self.is_master else "local",
                },
                self.keys,
            )
            await ws.send(json.dumps(hello_back, separators=(",", ":")))

        if first_time:
            print(f"[peer] linked {peer_uuid} @{host}:{port}")

    async def _peer_recv(self, ws: websockets.WebSocketCommonProtocol) -> None:
        """Receives and routes frames from a peer server until socket closes

        Args:
            ws (websockets.WebSocketCommonProtocol): Peer socket

        Raises:
            Exception: Underlying network errors propagate to finally cleanup
        """

        try:
            async for raw in ws:
                try: msg = json.loads(raw)
                except Exception: continue

                # IMPORTANT: process HELLOs first so dialers can register peers
                if msg.get("type") == T_PEER_HELLO_LINK:
                    await self._on_peer_hello(ws, msg)
                    continue

                # Verify signature for all other peer frames
                if not await self._verify_peer_frame(msg):
                    continue
                
                # Route verified frame
                await self._route_peer_frame(msg)

        finally:
            if peer_uuid := self.ws_to_peeruuid.pop(ws, None):
                self.server_addrs.pop(peer_uuid, None)
                self.servers.pop(peer_uuid, None)
                self.server_pubs.pop(peer_uuid, None)

            if url := self.ws_to_url.pop(ws, None):
                self.url_to_ws.pop(url, None)

            self._detach_ws(ws)

    async def _verify_peer_frame(self, msg: Dict[str, Any]) -> bool:
        """Verifies server→server frame signature using stored peer pubkey

        Args:
            msg (Dict[str, Any]): Incoming peer frame

        Returns:
            bool: True if signature verifies; False otherwise
        """

        frm = msg.get("from"); pl = msg.get("payload", {}); sig = msg.get("sig", "")
        pub = self.server_pubs.get(frm)
        return bool(pub) and RSAKeys.verify_payload(pub, pl, sig)

    async def _msg_dedupe_id(self, msg: dict) -> str:
        h = hashlib.sha256(json.dumps(msg.get("payload", {}), sort_keys=True, separators=(",",":")).encode()).digest()
        return f"{msg.get('ts')}|{msg.get('from')}|{msg.get('to')}|{h[:8].hex()}"
    
    async def _route_peer_frame(self, msg: Dict[str, Any]) -> None:
        """Routes a verified peer frame to the appropriate handler

        Args:
            msg (Dict[str, Any]): Verified peer frame
        """

        mid = self._msg_dedupe_id(msg)
        now = int(msg.get("ts", 0))
        last = self.seen_ids.get(mid)
        if last and now - last < 60_000:   # 60s window
            return
        self.seen_ids[mid] = now

        t = msg.get("type")
        pl = msg.get("payload", {})

        if t == T_USER_ADVERTISE:
            self.user_locations[pl.get("user_id")] = pl.get("location")

        elif t == T_USER_REMOVE:
            if self.user_locations.get(pl.get("user_id")) == pl.get("location"):
                self.user_locations.pop(pl.get("user_id"), None)

        elif t == T_PEER_DELIVER:
            await self._handle_peer_deliver(pl)

        elif t == T_DB_GET_USER and self.is_master:
            await self._handle_db_get_user(msg)

        elif t == T_DB_REGISTER and self.is_master:
            await self._handle_db_register(msg)

        elif t == T_DB_USER and not self.is_master:
            req_id = pl.get("req_id")
            user_ws = self.pending_db.pop(req_id, None)
            if user_ws:
                resp = make_env(T_USER_DB_USER, self.server_uuid, "user_*", {
                    "user_id": pl.get("user_id"),
                    "found": bool(pl.get("found")),
                    "pubkey": pl.get("pubkey", ""),
                }, self.keys)
                await self._send_raw(user_ws, resp)

        elif t == T_GROUP_KEY_SHARE:
            await self._deliver_group_share_local(pl)

        elif t == T_MSG_GROUP:
            await self._deliver_group_msg_local(pl)

        elif t in (T_FILE_START, T_FILE_CHUNK, T_FILE_END):
            await self._deliver_file_local({"type": t, "payload": pl}, override_recipient=pl.get("user_id"))

    async def _handle_peer_deliver(self, pl: Dict[str, Any]) -> None:
        """Handles a PEER_DELIVER by forwarding to local user or to next hop

        Args:
            pl (Dict[str, Any]): Delivery payload for `user_id`
        """

        user = pl.get("user_id"); loc = self.user_locations.get(user)
        if loc == "local":
            await self._deliver_to_local_user(user, pl)
        elif isinstance(loc, str) and (loc.startswith("master_server_") or loc.startswith("server_")):
            lk = self.servers.get(loc)
            if lk: await self._send_raw(lk.ws, make_env(T_PEER_DELIVER, self.server_uuid, loc, pl, self.keys))

    async def _handle_db_register(self, msg: dict) -> None:
        """Master handler: registers or updates a user's public key

        Args:
            msg (dict): A `T_DB_REGISTER` frame from a peer server
                Expected `payload` keys:
                    - user_id (str): Mesh-unique user identifier
                    - pubkey (str): User public key (DER(SPKI) base64url)
        """

        if not self.is_master or not self.db:
            return
        pl = msg.get("payload", {}) or {}
        uid = pl.get("user_id")
        pub = pl.get("pubkey")
        if uid and pub:
            self.db.register_user(uid, pub)
            # optional: print(f"[db] registered {uid}")

    async def _on_user_list(self, ws, msg) -> None:
        """Return a sorted list of known online users (presence cache)."""
        try:
            # users known as local:
            locals_ = list(self.local_users.keys())
            # users known via gossip (exclude those we think are offline)
            remotes = [u for u, loc in self.user_locations.items() if loc != "local"]
            users = sorted(set(locals_ + remotes))
            env = make_env(T_USER_LIST, self.server_uuid, msg.get("from", "user_*"), {
                "users": users
            }, self.keys)
            await self._send_raw(ws, env)
        except Exception:
            await self._send_error(ws, E_UNKNOWN_TYPE, "list failed")

    async def _handle_db_get_user(self, msg: dict) -> None:
        """Master handler: looks up a user's public key and replies with `T_DB_USER`

        Args:
            msg (dict): A `T_DB_GET_USER` frame from a peer server
                Expected `payload` keys:
                    - user_id (str): Target user to look up
                    - req_id (str): Correlation ID to echo back in the reply
        """

        if not self.is_master or not self.db:
            return
        pl = msg.get("payload", {}) or {}
        uid = pl.get("user_id")
        req_id = pl.get("req_id")
        pub = self.db.get_user_pub(uid) if uid else None

        resp = make_env(
            T_DB_USER,
            self.server_uuid,
            msg.get("from"),
            {"user_id": uid, "found": bool(pub), "pubkey": pub or "", "req_id": req_id},
            self.keys,
        )
        # send back to requesting peer
        peer = self.servers.get(msg.get("from"))
        if peer:
            await self._send_raw(peer.ws, resp)

    async def _user_recv(self, ws: websockets.WebSocketCommonProtocol) -> None:
        """Receives frames from a connected user and dispatches

        Args:
            ws (websockets.WebSocketCommonProtocol): User socket
        """

        try:
            async for raw in ws:
                try: msg = json.loads(raw)
                except Exception: continue
                t = msg.get("type")
                if t == T_MSG_PRIVATE:
                    await self._on_msg_private(ws, msg)
                elif t == T_USER_LIST_REQ:
                    await self._on_user_list(ws, msg)
                elif t == T_USER_DB_GET:
                    await self._on_user_db_get(ws, msg)
                elif t == T_GROUP_KEY_SHARE:
                    await self._on_group_key_share(ws, msg)
                elif t == T_MSG_GROUP:
                    await self._on_msg_group(ws, msg)
                elif t in (T_FILE_START, T_FILE_CHUNK, T_FILE_END):
                    await self._on_file_from_user(ws, msg)
        finally:
            user_id = self._find_user_by_ws(ws)
            if user_id:
                self.local_users.pop(user_id, None)
                if self.user_locations.get(user_id) == "local":
                    self.user_locations.pop(user_id, None)
                    await self._broadcast_peers(make_env(T_USER_REMOVE, self.server_uuid, "*", {
                        "user_id": user_id, "location": self.server_uuid
                    }, self.keys))

    async def _on_user_hello(self, ws: websockets.WebSocketCommonProtocol, msg: Dict[str, Any]) -> None:
        """Registers a local user and gossips presence

        Args:
            ws (websockets.WebSocketCommonProtocol): User socket
            msg (Dict[str, Any]): USER_HELLO frame

        Raises:
            Exception: If sending errors or gossip fails
        """

        user_id = msg.get("from"); pl = msg.get("payload", {})
        if user_id in self.local_users:
            await self._send_error(ws, E_NAME_IN_USE, f"{user_id} already connected"); await ws.close(); return
        self.local_users[user_id] = Link(ws, 'user', user_id)
        self.user_locations[user_id] = "local"
        pub = pl.get("pubkey", "")
        if self.is_master and self.db:
            self.db.register_user(user_id, pub)
        else:
            await self._send_to_master(make_env(T_DB_REGISTER, self.server_uuid, self.master_uuid, {
                "user_id": user_id, "pubkey": pub
            }, self.keys))
        await self._broadcast_peers(make_env(T_USER_ADVERTISE, self.server_uuid, "*", {
            "user_id": user_id, "location": self.server_uuid
        }, self.keys))
        print(f"[user] connected: {user_id}")

    async def _on_msg_private(self, ws: websockets.WebSocketCommonProtocol, msg: Dict[str, Any]) -> None:
        """Routes an incoming MSG_PRIVATE from a local user

        Args:
            ws (WebSocketCommonProtocol): User socket
            msg (Dict[str, Any]): MSG_PRIVATE frame
        """

        frm = msg.get("from"); to = msg.get("to"); pl = msg.get("payload", {})
        loc = self.user_locations.get(to)
        if loc == "local":
            await self._deliver_to_local_user(to, {
                "user_id": to,
                "ciphertext": pl.get("ciphertext"),
                "iv": pl.get("iv"),
                "tag": pl.get("tag"),
                "wrapped_key": pl.get("wrapped_key"),
                "sender": frm,
                "sender_pub": pl.get("sender_pub"),
                "content_sig": pl.get("content_sig", ""),
                "content_ts": msg.get("ts"),
            })
        elif isinstance(loc, str) and (loc.startswith("master_server_") or loc.startswith("server_")):
            lk = self.servers.get(loc)
            if lk:
                peer_msg = make_env(T_PEER_DELIVER, self.server_uuid, loc, {
                    "user_id": to,
                    "ciphertext": pl.get("ciphertext"),
                    "iv": pl.get("iv"),
                    "tag": pl.get("tag"),
                    "wrapped_key": pl.get("wrapped_key"),
                    "sender": frm,
                    "sender_pub": pl.get("sender_pub"),
                    "content_sig": pl.get("content_sig", ""),
                    "content_ts": msg.get("ts"),
                }, self.keys)
                await self._send_raw(lk.ws, peer_msg)
            else:
                await self._send_error(ws, E_TIMEOUT, f"no link to {loc}")
        else:
            await self._send_error(ws, E_USER_NOT_FOUND, f"unknown location for {to}")

    async def _on_user_db_get(self, ws: websockets.WebSocketCommonProtocol, msg: Dict[str, Any]) -> None:
        """Handles a user request to fetch another user's pubkey (via Master)

        Args:
            ws (websockets.WebSocketCommonProtocol): Requesting user's socket
            msg (Dict[str, Any]): USER_DB_GET frame (payload.user_id required)
        """

        target = msg.get("payload", {}).get("user_id")
        if not target:
            await self._send_error(ws, E_UNKNOWN_TYPE, "missing user_id"); return
        if self.is_master and self.db:
            pub = self.db.get_user_pub(target)
            resp = make_env(T_USER_DB_USER, self.server_uuid, msg.get("from"), {
                "user_id": target, "found": bool(pub), "pubkey": pub or ""
            }, self.keys)
            await self._send_raw(ws, resp)
        else:
            req_id = str(uuid.uuid4()); self.pending_db[req_id] = ws
            await self._send_to_master(make_env(T_DB_GET_USER, self.server_uuid, self.master_uuid, {
                "user_id": target, "req_id": req_id
            }, self.keys))

    async def _deliver_to_local_user(self, user_id: str, payload: Dict[str, Any]) -> None:
        """Sends USER_DELIVER to a connected local user

        Args:
            user_id (str): Recipient user UUID (must be connected locally)
            payload (Dict[str, Any]): Delivery payload (ciphertext fields)
        """

        link = self.local_users.get(user_id)
        if not link: return
        env = make_env(T_USER_DELIVER, self.server_uuid, user_id, payload, self.keys)
        await self._send_raw(link.ws, env)

    async def _broadcast_peers(self, obj: Dict[str, Any]) -> None:
        """Broadcasts a signed envelope to all connected peer servers

        Args:
            obj (Dict[str, Any]): Signed SOCP envelope
        """

        dead = []
        for sid, link in list(self.servers.items()):
            try: await self._send_raw(link.ws, obj)
            except Exception: dead.append(sid)
        for sid in dead: self.servers.pop(sid, None)

    async def _send_to_master(self, obj: Dict[str, Any]) -> None:
        """Sends a signed envelope to the Master server if linked

        Args:
            obj (Dict[str, Any]): Signed SOCP envelope
        """

        lk = self.servers.get(self.master_uuid)
        if lk: await self._send_raw(lk.ws, obj)

    async def _send_raw(self, ws: websockets.WebSocketCommonProtocol, obj: Dict[str, Any]) -> None:
        """Sends a JSON object over a WebSocket with canonical separators

        Args:
            ws (websockets.WebSocketCommonProtocol): Destination socket
            obj (Dict[str, Any]): JSON-serializable object
        """

        await ws.send(json.dumps(obj, separators=(',',':')))

    async def _send_error(self, ws, code: str, detail: str):
        env = make_env(T_ERROR, self.server_uuid, "server_*", {"code": code, "detail": detail}, self.keys)
        await self._send_raw(ws, env)

    async def _send_error(self, ws: websockets.WebSocketCommonProtocol, code: str, detail: str) -> None:
        """Sends a standardized ERROR envelope to a socket

        Args:
            ws (websockets.WebSocketCommonProtocol): Destination socket
            code (str): Error code (e.g., USER_NOT_FOUND, NAME_IN_USE)
            detail (str): Human-readable detail text
        """

        for sid, lk in list(self.servers.items()):
            if lk.ws is ws: self.servers.pop(sid, None)
        for uid, lk in list(self.local_users.items()):
            if lk.ws is ws: self.local_users.pop(uid, None)

    def _detach_ws(self, ws: websockets.WebSocketCommonProtocol) -> None:
        """Removes any server/user link entries associated with a socket

        Args:
            ws (websockets.WebSocketCommonProtocol): Closed socket
        """

        for sid, lk in list(self.servers.items()):
            if lk.ws is ws:
                self.servers.pop(sid, None)
        for uid, lk in list(self.local_users.items()):
            if lk.ws is ws:
                self.local_users.pop(uid, None)

    def _find_user_by_ws(self, ws: websockets.WebSocketCommonProtocol) -> Optional[str]:
        """Finds the local user UUID bound to a socket, if any

        Args:
            ws (websockets.WebSocketCommonProtocol): User socket

        Returns:
            Optional[str]: user_uuid if found; otherwise None
        """

        for uid, lk in self.local_users.items():
            if lk.ws is ws: return uid
        return None
    
    # -------- Groups --------

    async def _on_group_key_share(self, ws, msg: dict) -> None:
        """Accepts GROUP_KEY_SHARE from a local user, caches members, and routes shares

        Args:
            ws: User websocket.
            msg (dict): GROUP_KEY_SHARE frame from creator. payload keys:
                - group_id (str)
                - shares (list[{member,str wrapped_group_key}])
                - creator_pub (str), content_sig (str)
        """

        pl = msg.get("payload", {}) or {}
        gid: str = pl.get("group_id")
        shares = pl.get("shares") or []
        # Cache membership (for routing future MSG_GROUP / file fanout)
        members = {s.get("member") for s in shares if s.get("member")}
        if creator := pl.get("creator") or msg.get("from"):
            members.add(creator)

        if gid and members:
            self.group_members.setdefault(gid, set()).update(members)

        # Route each share to the member’s hosting server (or deliver local)
        for s in shares:
            member = s.get("member")
            if not member:
                continue
            loc = self.user_locations.get(member)
            if loc == "local":
                self.group_members.setdefault(gid, set()).add(member)
                if link := self.local_users.get(member):
                    env = make_env(T_GROUP_KEY_SHARE, self.server_uuid, member, pl, self.keys)
                    await self._send_raw(link.ws, env)
            elif isinstance(loc, str) and (loc.startswith("master_server_") or loc.startswith("server_")):
                lk = self.servers.get(loc)
                if lk:
                    await self._send_raw(lk.ws, make_env(T_GROUP_KEY_SHARE, self.server_uuid, loc, pl, self.keys))

    async def _deliver_group_share_local(self, pl: dict) -> None:
        """Delivers a GROUP_KEY_SHARE to any local members listed in payload.shares"""

        gid = pl.get("group_id")
        creator = pl.get("creator")
        if gid and creator:
            self.group_members.setdefault(gid, set()).add(creator)

        shares = pl.get("shares") or []
        for s in shares:
            member = s.get("member")
            if not member: continue
            self.group_members.setdefault(gid, set()).add(member)
            if member in self.local_users:
                env = make_env(T_GROUP_KEY_SHARE, self.server_uuid, member, pl, self.keys)
                await self._send_raw(self.local_users[member].ws, env)

    async def _on_msg_group(self, ws, msg: dict) -> None:
        """Fans-out a MSG_GROUP from a local sender to all known group members

        Args:
            ws: User websocket
            msg (dict): MSG_GROUP frame with payload:
                - group_id, ciphertext, iv, tag, sender_pub, content_sig, content_ts
        """

        pl = msg.get("payload", {}) or {}
        gid = pl.get("group_id")
        if not gid:
            return
        members = self.group_members.get(gid, set())
        sender = msg.get("from")
        for m in members:
            if m == sender:
                continue
            loc = self.user_locations.get(m)
            if loc == "local":
                # deliver to the user
                await self._deliver_group_msg_local(pl, override_recipient=m)
            elif isinstance(loc, str) and (loc.startswith("master_server_") or loc.startswith("server_")):
                lk = self.servers.get(loc)
                if lk:
                    await self._send_raw(lk.ws, make_env(T_MSG_GROUP, self.server_uuid, loc, pl, self.keys))

    async def _deliver_group_msg_local(self, pl: dict, override_recipient: Optional[str] = None) -> None:
        """Delivers a group message to a local member (if present)"""

        gid = pl.get("group_id")
        # infer members from cached table; deliver to specific user if given
        if override_recipient:
            if override_recipient in self.local_users:
                await self._send_raw(self.local_users[override_recipient].ws,
                                    make_env(T_MSG_GROUP, self.server_uuid, override_recipient, pl, self.keys))
            return
        # generic: deliver to any local members of this group
        for m in self.group_members.get(gid, set()):
            if m in self.local_users:
                await self._send_raw(self.local_users[m].ws,
                                    make_env(T_MSG_GROUP, self.server_uuid, m, pl, self.keys))

    # -------- Files --------

    async def _on_file_from_user(self, ws, msg: dict) -> None:
        """Route FILE_* from a user to a local/remote user, or fan-out to a group."""
        t  = msg.get("type")
        to = msg.get("to", "")
        pl = msg.get("payload", {}) or {}

        # Group mode if payload says so, else DM to a single user
        if pl.get("mode") == "group" or (isinstance(to, str) and to.startswith("group_")):
            gid = pl.get("group_id") or to
            await self._file_route_group(gid, msg)
        else:
            # DM: 'to' must be a user id
            await self._file_route_dm(to, msg)

    async def _file_route_dm(self, user_id: str, msg: dict) -> None:
        """DM file routing: deliver locally or forward to hosting server."""
        loc = self.user_locations.get(user_id)
        if loc == "local":
            await self._deliver_file_local(msg, override_recipient=user_id)
        elif isinstance(loc, str) and (loc.startswith("master_server_") or loc.startswith("server_")):
            lk = self.servers.get(loc)
            if lk:
                # include recipient for the remote server
                payload = {**msg.get("payload", {}), "user_id": user_id}
                await self._send_raw(lk.ws, make_env(msg["type"], self.server_uuid, loc, payload, self.keys))
        else:
            # optional: tell sender we don't know where the user is
            if isinstance(ws, websockets.WebSocketCommonProtocol):
                await self._send_error(ws, E_USER_NOT_FOUND, f"unknown location for {user_id}")

    async def _file_route_group(self, gid: str, msg: dict) -> None:
        """Fan-out FILE_* to all known members of a group (except the sender)."""
        pl     = msg.get("payload", {}) or {}
        sender = msg.get("from")
        members = self.group_members.get(gid, set()) if hasattr(self, "group_members") else set()
        if not members:
            return
        for m in members:
            if m == sender:
                continue
            loc = self.user_locations.get(m)
            if loc == "local":
                await self._deliver_file_local(msg, override_recipient=m)
            elif isinstance(loc, str) and (loc.startswith("master_server_") or loc.startswith("server_")):
                lk = self.servers.get(loc)
                if lk:
                    payload = {**pl, "user_id": m}
                    await self._send_raw(lk.ws, make_env(msg["type"], self.server_uuid, loc, payload, self.keys))

    async def _deliver_file_local(self, msg: dict, override_recipient: Optional[str] = None) -> None:
        """Delivers FILE_* frames to a local user

        Args:
            msg (dict): Original USER/PEER frame (we pass through payload)
            override_recipient (Optional[str]): Specific user to deliver to
        """

        to_user = override_recipient or msg.get("to") or msg.get("payload", {}).get("user_id")
        if not isinstance(to_user, str):
            return
        link = self.local_users.get(to_user)
        if not link:
            return
        env = make_env(msg["type"], self.server_uuid, to_user, msg.get("payload", {}) or {}, self.keys)
        await self._send_raw(link.ws, env)
