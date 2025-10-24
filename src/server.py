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

from sdb import SOCPStore
from protocols import *
from crypto import RSAKeys
from envelope import make_env



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
        self.servers: Dict[str, Link] = {}
        self.server_addrs: Dict[str, Tuple[str, int]] = {}
        self.server_pubs: Dict[str, str] = {}
        self.local_users: Dict[str, Link] = {}
        self.user_locations: Dict[str, str] = {}
        self.pending_db: Dict[str, WebSocketServerProtocol] = {}
        self.ws_to_peeruuid: Dict[websockets.WebSocketCommonProtocol, str] = {}
        self.seen_public: set[str] = set()  # post-id strings "from|ts"
        self.seen_pub_files_start: set[str] = set()          # file_id
        self.seen_pub_files_chunk: set[tuple[str,int]] = set()  # (file_id, index)
        self.seen_pub_files_end: set[str] = set()
        self.seen_ids: dict[str,int] = {}
        self.public_members: set[str] = set()
        self.public_version: int = 1
        self.url_to_ws = {}
        self.ws_to_url = {}

        self.store = SOCPStore(pathlib.Path("data/socp.db"))
        self.db = self.store if self.is_master else None
        if self.is_master and self.db:
            self.db.ensure_public_group()

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
                    print(f"[peer] dialing {url} … sending JOIN as {self.server_uuid}")
                    ws = await websockets.connect(url, ping_interval=20)
                    self.url_to_ws[url] = ws
                    self.ws_to_url[ws] = url
                    hello = make_env(
                        T_SERVER_HELLO_JOIN,
                        self.server_uuid,
                        "server_*",
                        {
                            "host": self.listen_host,
                            "port": int(self.listen_port),
                            "pubkey": self.keys.pub_der_b64u(),
                            "role": "master" if self.is_master else "local",
                        },
                        self.keys,
                    )
                    await ws.send(json.dumps(hello, separators=(',',':')))
                    print(f"[peer] => JOIN to {url}")
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
            elif t == T_SERVER_HELLO_JOIN:
                await self._on_server_hello_join(ws, msg)
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
                try:
                    msg = json.loads(raw)
                    if not isinstance(msg, dict):
                        continue
                except Exception:
                    continue

                t = msg.get("type")
                
                # --- Handle join/welcome/announce/legacy-hello BEFORE sig verification ---
                if t == T_PEER_HELLO_LINK:
                    await self._on_peer_hello(ws, msg)
                    continue

                if t == T_SERVER_HELLO_JOIN:
                    await self._on_server_hello_join(ws, msg)
                    continue

                if t == T_SERVER_WELCOME:
                    await self._on_server_welcome(ws, msg)
                    continue

                if t == T_SERVER_ANNOUNCE:
                    # Verify with the sending peer's pubkey if we already know it.
                    known_pub = self.server_pubs.get(msg.get("from"))
                    if known_pub and not RSAKeys.verify_payload(
                        known_pub, msg.get("payload", {}), msg.get("sig", "")
                    ):
                        continue
                    await self._on_server_announce(ws, msg)
                    continue

                # --- Everything else must pass peer signature verification ---
                if not await self._verify_peer_frame(msg):
                    print(f"[peer rx] {t} from={msg.get('from')} to={msg.get('to')} ts={msg.get('ts')}")
                    continue

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
    
        # if pub == E_OVERRIDE_KEY:
        #     print("Override key used for peer authentication!")
        #     return True
        return bool(pub) and RSAKeys.verify_payload(pub, pl, sig)

    def _msg_dedupe_id(self, msg: dict) -> str:
        h = hashlib.sha256(
            json.dumps(msg.get("payload", {}), sort_keys=True, separators=(",",":")).encode()
        ).digest()
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
            uid = pl.get("user_id")
            sid = pl.get("server_id")
            if not uid or not sid:
                return

            was = self.user_locations.get(uid)
            self.user_locations[uid] = sid

            if self.is_master and self.db:
                self.db.add_member_public(uid)

            if was is None or was != sid:
                print(f"[user] connected: {uid} @ {sid}")

        elif t == T_USER_REMOVE:
            uid = pl.get("user_id")
            sid = pl.get("server_id")
            if uid and sid and self.user_locations.get(uid) == sid:
                self.user_locations.pop(uid, None)
                if self.is_master and self.db:
                    self.db.remove_member_public(uid)
                print(f"[user] disconnected: {uid} @ {sid}")
            src = msg.get("from")
            fwd = make_env(T_USER_REMOVE, self.server_uuid, "*",
                        {"user_id": uid, "server_id": sid}, self.keys)
            await self._broadcast_peers_except(src, fwd)

        elif t == T_PEER_DELIVER:
            await self._handle_peer_deliver(pl)

        elif t == T_SERVER_DELIVER:
            pl = msg.get("payload", {}) or {}
            user = pl.get("user_id")
            loc = self.user_locations.get(user)
            sender_ts = msg.get("ts")

            if loc == "local":
                payload = {
                    "ciphertext": pl.get("ciphertext"),
                    "sender": pl.get("sender"),
                    "sender_pub": pl.get("sender_pub"),
                    "content_sig": pl.get("content_sig",""),
                }
                env = make_env(T_USER_DELIVER, self.server_uuid, user, payload, self.keys)
                env["ts"] = sender_ts
                await self._send_raw(self.local_users[user].ws, env)

            elif isinstance(loc, str) and loc.startswith(("server_", "master_server_")):
                fwd = dict(msg)                            # keep whole envelope intact
                await self._send_raw(self.servers[loc].ws, fwd)

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

        elif t in (T_PUBLIC_CHANNEL_ADD, T_PUBLIC_CHANNEL_UPDATED, T_PUBLIC_CHANNEL_KEY_SHARE):
            await self._broadcast_peers_except(msg.get("from"), msg)
            return

        elif t == T_MSG_PUBLIC_CHANNEL:
            await self._on_public_from_peer(msg)

        elif t in (T_FILE_START, T_FILE_CHUNK, T_FILE_END):
            if pl.get("mode") == "public":
                # file frames for public channel from a peer
                await self._on_file_public_from_peer(msg)
            else:
                # DM file frame from a peer: deliver to the named local recipient
                # (origin server added payload.user_id when forwarding)
                await self._deliver_file_local(msg)

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
        if self.is_master and self.db and uid and pub:
            self.db.upsert_user(uid, pub)

    async def _on_user_list_req(self, ws, msg) -> None:
        """Builds a sorted list of known-online users and replies to the requester.

        Args:
            ws: WebSocket of the requesting user.
            msg (dict): The request envelope (unused except for 'from').
        """

        # Known online = all locally connected users + any users present in user_locations
        known = set(self.local_users.keys())
        known.update([u for u, loc in self.user_locations.items() if loc])  # loc: "local" or "server_<uuid>"
        users_sorted = sorted(known)

        resp = make_env(
            T_USER_LIST,
            self.server_uuid,
            msg.get("from") or "user_*",
            {"users": users_sorted},
            self.keys,
        )
        await self._send_raw(ws, resp)

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
        """Receives and processes frames from a connected user socket.

        Dispatches all user-originated frames to their appropriate handlers:
        - MSG_DIRECT: end-to-end encrypted direct message (RSA-OAEP)
        - MSG_PUBLIC_CHANNEL: broadcast to public channel
        - PUBLIC_CHANNEL_*: rebroadcast membership/key updates
        - FILE_*: file transfer (direct or public)
        - USER_LIST_REQ: list online users
        - USER_DB_GET: lookup another user's pubkey
        - HEARTBEAT: ignore (keepalive)
        - DUMP_USERS: diagnostic list of local users

        On disconnect:
        - Removes user from local registry
        - Broadcasts USER_REMOVE to all peers
        """

        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue

                t = msg.get("type")
                if not t:
                    continue

                # --- Direct Messages (Private DM) ---
                if t == T_MSG_DIRECT:
                    await self._on_msg_direct(ws, msg)

                # --- Public Channel Management ---
                elif t in (T_PUBLIC_CHANNEL_ADD, T_PUBLIC_CHANNEL_UPDATED, T_PUBLIC_CHANNEL_KEY_SHARE):
                    # Forward these to all peers (no local processing)
                    await self._broadcast_peers(make_env(t, self.server_uuid, "*", msg.get("payload", {}), self.keys))

                # --- Public Channel Chat Messages ---
                elif t == T_MSG_PUBLIC_CHANNEL:
                    await self._on_public_from_user(ws, msg)

                # --- User List Request (/list) ---
                elif t == T_USER_LIST_REQ:
                    await self._on_user_list_req(ws, msg)

                # --- Database Lookup Request (/dbget <user>) ---
                elif t == T_USER_DB_GET:
                    await self._on_user_db_get(ws, msg)

                # --- File Transfers ---
                elif t in (T_FILE_START, T_FILE_CHUNK, T_FILE_END):
                    pl = msg.get("payload", {}) or {}
                    to = msg.get("to", "")
                    mode = pl.get("mode", "")
                    if to == ("public" if "CHANNEL_PUBLIC" not in globals() else CHANNEL_PUBLIC) or mode == "public":
                        await self._on_file_public_from_user(msg)
                    else:
                        await self._on_file_from_user(ws, msg)

                # --- Debug: Dump all local users (/dump) ---
                # elif t == T_DUMP_USERS:
                #     resp = make_env(
                #         T_DUMP_USERS,
                #         self.server_uuid,
                #         msg.get("from") or "user_*",
                #         {"users": list(self.local_users.keys())},
                #         self.keys,
                #     )
                #     await self._send_raw(ws, resp)

                # --- Heartbeat (ignored) ---
                elif t == ("HEARTBEAT" if "T_HEARTBEAT" not in globals() else T_HEARTBEAT):
                    continue

                else:
                    # Unknown or unsupported message type
                    await self._send_error(ws, E_UNKNOWN_TYPE, f"unrecognized type: {t}")

        finally:
            # --- Handle user disconnection ---
            user_id = self._find_user_by_ws(ws)
            if user_id:
                self.local_users.pop(user_id, None)

                # Remove from presence map only if still mapped locally
                if self.user_locations.get(user_id) == "local":
                    self.user_locations.pop(user_id, None)

                    # Broadcast USER_REMOVE (v1.3 uses server_id field)
                    removal = make_env(
                        T_USER_REMOVE,
                        self.server_uuid,
                        "*",
                        {"user_id": user_id, "server_id": self.server_uuid},
                        self.keys,
                    )
                    await self._broadcast_peers(removal)

                if self.is_master and self.db:
                    self.db.remove_member_public(user_id)
                
                print(f"[user] disconnected: {user_id}")

    async def _broadcast_peers_except(self, src_peer_id: Optional[str], obj: Dict[str, Any]) -> None:
        dead = []
        for peer_id, link in list(self.servers.items()):
            if src_peer_id and peer_id == src_peer_id:
                continue
            try:
                await self._send_raw(link.ws, obj)
            except Exception:
                dead.append(peer_id)
        for pid in dead:
            self.servers.pop(pid, None)
    
    async def _on_server_hello_join(self, ws, msg: dict) -> None:
        """
        Dialer sent T_SERVER_HELLO_JOIN to us. Cache their metadata and reply T_SERVER_WELCOME.
        payload: {host, port, pubkey, role}
        """

        pl = msg.get("payload", {}) or {}
        host = pl.get("host") or "?"
        port = int(pl.get("port") or 0)
        role = pl.get("role", "local")
        pub  = pl.get("pubkey") or ""
        peer_uuid = msg.get("from") or f"server_{uuid.uuid4()}"

        # register/refresh
        self.servers[peer_uuid] = Link(ws, "peer", peer_uuid)
        self.server_addrs[peer_uuid] = (host, port)
        if pub:
            self.server_pubs[peer_uuid] = pub
        self.ws_to_peeruuid[ws] = peer_uuid

        print(f"[peer] <= JOIN from {peer_uuid} @{host}:{port} role={role}")

        # send WELCOME with OUR metadata (signed)
        welcome = make_env(
            T_SERVER_WELCOME,
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
        await self._send_raw(ws, welcome)
        print(f"[peer] => WELCOME to {peer_uuid}")

        # announce this newcomer to our other peers
        announce = make_env(
            T_SERVER_ANNOUNCE,
            self.server_uuid,
            "*",
            {
                "server_id": peer_uuid,
                "host": host,
                "port": port,
                "pubkey": pub,
                "role": pl.get("role") or "local",
            },
            self.keys,
        )
        await self._broadcast_peers_except(peer_uuid, announce)
        print(f"[peer] join {peer_uuid} @{host}:{port}")
        await self._send_presence_snapshot(peer_uuid)
        await self._send_public_snapshot(peer_uuid)

    async def _on_server_welcome(self, ws, msg: dict) -> None:
        """
        We dialed THEM. They replied T_SERVER_WELCOME with their uuid+pubkey.
        payload: {host, port, pubkey, role}
        """

        pl = msg.get("payload", {}) or {}
        peer_uuid = msg.get("from") or f"server_{uuid.uuid4()}"
        host = pl.get("host") or "?"
        port = int(pl.get("port") or 0)
        role = pl.get("role", "local")
        pub  = pl.get("pubkey") or ""

        # bind this socket to the announced uuid, store pubkey for verification
        self.servers[peer_uuid] = Link(ws, "peer", peer_uuid)
        self.server_addrs[peer_uuid] = (host, port)
        if pub:
            self.server_pubs[peer_uuid] = pub
        self.ws_to_peeruuid[ws] = peer_uuid

        print(f"[peer] <= WELCOME from {peer_uuid} @{host}:{port} role={role}")
        
        # tell everyone we (re)linked this peer
        announce = make_env(
            T_SERVER_ANNOUNCE,
            self.server_uuid,
            "*",
            {
                "server_id": peer_uuid,
                "host": host,
                "port": port,
                "pubkey": pub,
                "role": pl.get("role") or "local",
            },
            self.keys,
        )
        await self._broadcast_peers_except(peer_uuid, announce)
        print(f"[peer] => ANNOUNCE to {peer_uuid}")
        await self._send_presence_snapshot(peer_uuid)
        await self._send_public_snapshot(peer_uuid)

    async def _on_server_announce(self, ws, msg: dict) -> None:
        """
        Gossip: learn/update metadata about a third server.
        payload: {server_id, host, port, pubkey, role}
        """

        pl = msg.get("payload", {}) or {}
        peer_uuid = msg.get("from") or "server_?"
        sid = pl.get("server_id")
        if not sid:
            return
        host = pl.get("host") or "?"
        port = int(pl.get("port") or 0)
        role = pl.get("role", "local")
        pub  = pl.get("pubkey") or ""
        self.server_addrs[sid] = (host, port)
        if pub:
            self.server_pubs[sid] = pub
        
        print(f"[peer] <= ANNOUNCE from {peer_uuid} @{host}:{port} role={role}")

        # (optional) we do not auto-dial here; dialer loop can use peer_urls if desired
        # Re-gossip further (not back to the incoming peer)
        src = self.ws_to_peeruuid.get(ws)
        fwd = make_env(T_SERVER_ANNOUNCE, self.server_uuid, "*", pl, self.keys)
        await self._broadcast_peers_except(src, fwd)



    async def _on_user_hello(self, ws: websockets.WebSocketCommonProtocol, msg: Dict[str, Any]) -> None:
        """Registers a local user and gossips presence

        Args:
            ws (websockets.WebSocketCommonProtocol): User socket
            msg (Dict[str, Any]): USER_HELLO frame

        Raises:
            Exception: If sending errors or gossip fails
        """

        user_id = msg.get("from"); 
        pl = msg.get("payload", {})
        
        if user_id in self.local_users:
            await self._send_error(ws, E_NAME_IN_USE, f"{user_id} already connected"); 
            await ws.close(); 
            return
        
        self.local_users[user_id] = Link(ws, 'user', user_id)
        self.user_locations[user_id] = "local"

        pub = pl.get("pubkey", "")

        if not self.is_master:
            await self._send_to_master(make_env(T_DB_REGISTER, self.server_uuid, self.master_uuid, {
                "user_id": user_id, "pubkey": pub
            }, self.keys))

        if self.is_master and self.db:
            self.store.upsert_user(user_id, pub)
            self.store.add_member_public(user_id)
        
        await self._broadcast_peers(make_env(T_USER_ADVERTISE, self.server_uuid, "*", {
            "user_id": user_id, "server_id": self.server_uuid
        }, self.keys))
        print(f"[user] connected: {user_id}")
        
        if user_id not in self.public_members:
            self.public_members.add(user_id)
            self.public_version += 1
            add_env = make_env(
                T_PUBLIC_CHANNEL_ADD,
                self.server_uuid,
                "*",
                {"add": [user_id], "if_version": 1},  # minimal, per §9.3
                self.keys,
            )
            await self._broadcast_peers(add_env)

            # optional: also send an UPDATED snapshot right away
            upd_env = make_env(
                T_PUBLIC_CHANNEL_UPDATED,
                self.server_uuid,
                "*",
                {
                    "version": self.public_version,
                    "wraps": [],  # we’re not distributing a secret; empty list is fine for your plaintext approach
                },
                self.keys,
            )
            await self._broadcast_peers(upd_env)

    async def _send_public_snapshot(self, peer_id: str) -> None:
        """Send current public-channel membership to a single peer."""
        link = self.servers.get(peer_id)
        if not link:
            return
        env = make_env(
            T_PUBLIC_CHANNEL_UPDATED,
            self.server_uuid,
            peer_id,
            {
                "version": self.public_version,
                "wraps": [],  # no per-member key wraps in your implementation
            },
            self.keys,
        )
        await self._send_raw(link.ws, env)

    async def _on_msg_direct(self, ws, msg: Dict[str, Any]) -> None:
        """Routes a MSG_DIRECT to either a local user (USER_DELIVER) or next hop (SERVER_DELIVER)

        Args:
            ws (WebSocketCommonProtocol): User socket
            msg (Dict[str, Any]): MSG_PRIVATE frame
        """

        frm = msg.get("from"); 
        to = msg.get("to"); 
        pl = msg.get("payload", {}) or {}
        original_ts = msg.get("ts")
        loc = self.user_locations.get(to)

        if loc == "local":
            # Build payload unchanged
            deliver_pl = {
                "ciphertext": pl.get("ciphertext"),
                "sender": frm,
                "sender_pub": pl.get("sender_pub"),
                "content_sig": pl.get("content_sig",""),
            }
            # Create env and then overwrite ts to the original
            env = make_env(T_USER_DELIVER, self.server_uuid, to, deliver_pl, self.keys)
            env["ts"] = original_ts                         # <- preserve sender ts
            await self._send_raw(self.local_users[to].ws, env)
            return

        if isinstance(loc, str) and loc.startswith(("server_", "master_server_")):
            lk = self.servers.get(loc)
            if not lk:
                await self._send_error(ws, E_TIMEOUT, f"no link to {loc}")
                return
            hop = make_env(T_SERVER_DELIVER, self.server_uuid, loc, {
                "user_id": to,
                "ciphertext": pl.get("ciphertext"),
                "sender": frm,
                "sender_pub": pl.get("sender_pub"),
                "content_sig": pl.get("content_sig",""),
            }, self.keys)
            hop["ts"] = original_ts
            await self._send_raw(lk.ws, hop)
            return

        await self._send_error(ws, E_USER_NOT_FOUND, f"unknown location for {to}")

    async def _on_public_from_user(self, ws, msg) -> None:
        """Handles T_MSG_PUBLIC_CHANNEL from a local user: deliver to locals and fan-out to peers.

        Args:
            ws: WebSocket of the sender (unused except for potential errors).
            msg (dict): Envelope from the user.
        """
        
        pl = msg.get("payload", {}) or {}

        # (optional) dedupe using (from|ts) like you already do
        post_id = f"{pl.get('from')}|{pl.get('ts')}"
        if post_id in self.seen_public:
            return
        self.seen_public.add(post_id)

        # Deliver to locals as v1.3
        for uid, lk in list(self.local_users.items()):
            env = make_env(T_MSG_PUBLIC_CHANNEL, self.server_uuid, uid, pl, self.keys)
            await self._send_raw(lk.ws, env)

        # Fan-out to peers as v1.3
        for peer_id, link in list(self.servers.items()):
            envp = make_env(T_MSG_PUBLIC_CHANNEL, self.server_uuid, peer_id, pl, self.keys)
            await self._send_raw(link.ws, envp)

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

    async def _send_presence_snapshot(self, peer_id: str) -> None:
        """Tell a freshly linked peer about all users currently local here."""
        link = self.servers.get(peer_id)
        if not link:
            return
        # build and send one advertise per local user
        for uid in list(self.local_users.keys()):
            adv = make_env(
                T_USER_ADVERTISE,
                self.server_uuid,
                peer_id,
                {"user_id": uid, "server_id": self.server_uuid},  # v1.3 uses server_id
                self.keys,
            )
            try:
                await self._send_raw(link.ws, adv)
            except Exception:
                pass

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
                if self.user_locations.get(uid) == "local":
                    self.user_locations.pop(uid, None)
                    # fire-and-forget announce (no await here)
                    asyncio.create_task(self._broadcast_peers(make_env(
                        T_USER_REMOVE, self.server_uuid, "*", {"user_id": uid, "server_id": self.server_uuid}, self.keys
                    )))
                
                if self.is_master and self.db:
                    self.db.remove_member_public(uid)

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
    
    # -------- Public Channel --------

    async def _on_public_from_peer(self, msg: dict) -> None:
        """Handles T_MSG_PUBLIC_CHANNEL from a peer: deliver to locals and re-fan-out to other peers.

        Args:
            msg (dict): Peer envelope.
        """

        pl = msg.get("payload", {}) or {}
        src_peer = msg.get("from")
        post_id = f"{pl.get('from')}|{pl.get('ts')}"
        if post_id in self.seen_public:
            return
        self.seen_public.add(post_id)

        # Deliver to locals as v1.3
        for uid, lk in list(self.local_users.items()):
            env = make_env(T_MSG_PUBLIC_CHANNEL, self.server_uuid, uid, pl, self.keys)
            await self._send_raw(lk.ws, env)

        # Re-fan-out to other peers as v1.3 (don’t bounce to src)
        for peer_id, link in list(self.servers.items()):
            if peer_id == src_peer:
                continue
            envp = make_env(T_MSG_PUBLIC_CHANNEL, self.server_uuid, peer_id, pl, self.keys)
            await self._send_raw(link.ws, envp)

    # -------- Files --------

    async def _on_file_from_user(self, ws, msg: dict) -> None:
        """
        Route FILE_* from a local user to the recipient:
        - If recipient is local: deliver FILE_* directly to that user
        - If remote: forward FILE_* to the hosting server as a peer frame (same type),
        adding payload.user_id = <recipient>.
        """

        t   = msg.get("type")
        frm = msg.get("from")
        to  = msg.get("to")
        pl  = dict(msg.get("payload", {}) or {})

        if t == T_FILE_START:
            pl.setdefault("sender", frm)  # keep sender at source if client didn’t include

        loc = self.user_locations.get(to)
        if loc == "local":
            if lk := self.local_users.get(to):
                env = make_env(t, self.server_uuid, to, pl, self.keys)
                await self._send_raw(lk.ws, env)
            else:
                await self._send_error(ws, E_TIMEOUT, f"{to} not attached")
            return

        if isinstance(loc, str) and (loc.startswith("server_") or loc.startswith("master_server_")):
            lk = self.servers.get(loc)
            if not lk:
                await self._send_error(ws, E_TIMEOUT, f"no link to {loc}")
                return
            fwd = dict(pl)
            fwd.setdefault("user_id", to)
            peer_env = make_env(t, self.server_uuid, loc, fwd, self.keys)
            await self._send_raw(lk.ws, peer_env)
            return

        await self._send_error(ws, E_USER_NOT_FOUND, f"unknown location for {to}")

    async def _on_file_public_from_user(self, msg: dict) -> None:
        """Broadcasts FILE_* from a local user to Public Channel:
        - deliver to all local users
        - fan-out to all peer servers
        - dedupe per (file_id[, index]) to avoid loops
        """

        t   = msg.get("type")
        pl  = dict(msg.get("payload", {}) or {})
        fid = pl.get("file_id")
        idx = pl.get("index")
        sender = msg.get("from")

        # Dedupe
        if t == T_FILE_START and fid in self.seen_pub_files_start: return
        if t == T_FILE_CHUNK and (fid, int(idx or 0)) in self.seen_pub_files_chunk: return
        if t == T_FILE_END   and fid in self.seen_pub_files_end: return
        if t == T_FILE_START: self.seen_pub_files_start.add(fid)
        elif t == T_FILE_CHUNK: self.seen_pub_files_chunk.add((fid, int(idx or 0)))
        else: self.seen_pub_files_end.add(fid)

        # Ensure mode & sender carried to everyone
        pl["mode"] = "public"
        if t == T_FILE_START:
            pl.setdefault("sender", sender)

        # Deliver to all *other* local users (skip sender)
        for uid, lk in list(self.local_users.items()):
            if uid == sender:
                continue
            env = make_env(t, self.server_uuid, uid, pl, self.keys)
            try:
                await self._send_raw(lk.ws, env)
            except Exception:
                pass

        # Fan-out to peers
        for peer_id, link in list(self.servers.items()):
            envp = make_env(t, self.server_uuid, peer_id, pl, self.keys)
            try:
                await self._send_raw(link.ws, envp)
            except Exception:
                pass

    async def _deliver_file_local(self, msg: dict) -> None:
        """
        Deliver a FILE_* frame (arrived from a peer) to the local recipient.
        Expects payload.user_id to be set by the origin server when forwarding.
        """
        t  = msg.get("type")
        pl = msg.get("payload", {}) or {}
        user = pl.get("user_id")
        if not user:
            return
        lk = self.local_users.get(user)
        if not lk:
            return
        env = make_env(t, self.server_uuid, user, pl, self.keys)
        await self._send_raw(lk.ws, env)

    async def _on_file_public_from_peer(self, msg: dict) -> None:
        """Handles FILE_* for Public Channel from a peer:
        - deliver to local users
        - re-fan-out to other peers (not back to sender)
        - dedupe per file_id/index
        """

        t   = msg.get("type")
        pl  = dict(msg.get("payload", {}) or {})
        pl["mode"] = "public"
        src_peer = msg.get("from")
        fid = pl.get("file_id")
        idx = pl.get("index")

        # Dedupe
        if t == T_FILE_START and fid in self.seen_pub_files_start: return
        if t == T_FILE_CHUNK and (fid, int(idx or 0)) in self.seen_pub_files_chunk: return
        if t == T_FILE_END   and fid in self.seen_pub_files_end: return
        if t == T_FILE_START: self.seen_pub_files_start.add(fid)
        elif t == T_FILE_CHUNK: self.seen_pub_files_chunk.add((fid, int(idx or 0)))
        else: self.seen_pub_files_end.add(fid)

        # Deliver to locals
        for uid, lk in list(self.local_users.items()):
            env = make_env(t, self.server_uuid, uid, pl, self.keys)
            try:
                await self._send_raw(lk.ws, env)
            except Exception:
                pass

        # Re-fan-out to other peers (not back to sender peer)
        for peer_id, link in list(self.servers.items()):
            if peer_id == src_peer:
                continue
            envp = make_env(t, self.server_uuid, peer_id, pl, self.keys)
            try:
                await self._send_raw(link.ws, envp)
            except Exception:
                pass
