# Secure Overlay Chat Protocol (SOCP)

**Description:** This project implements the class Secure Overlay Chat Protocol (SOCP) using Python and WebSockets.\
**Version:** v1.3 (protocol freeze)

## Group Information

**Group No:**  45  
**Students:**
- **Sk Md Shariful Islam Arafat** - a1983627 
- **Aditya Dixit** - a1980937  
- **Hasnain Habib Sayed** - a1988079  
- **Sukarna Paul** - a1986887
- **Atiq Ullah Ador** - a1989573 

## Features
- **Server (mesh peer)**: `server_uuid`, presence gossip (`USER_ADVERTISE`/`USER_REMOVE`), DM routing (`PEER_DELIVER`/`USER_DELIVER`), error frames.
- **Master DB**: single authority (configurable by `--master-uuid`) for user registry & pubkey lookup. Locals proxy via DB-RPC.
- **Client**: users attach to one local server; DMs are **E2E encrypted** (AES‑256‑GCM; RSA‑OAEP key wrap) and **content‑signed** (RSA‑PSS).
- **Security**: RSA‑4096, SHA‑256, base64url (no padding), canonical JSON signing.

## Project Tree
```
SOCP
├── src                               
│    ├── client.py              # user client
│    ├── crypto.py              # RSA-4096 PSS/OAEP, AES-256-GCM, helpers
│    ├── db.py                  # Master DB (JSON) + helpers
│    ├── encoding.py            # base64url + canonical JSON
│    ├── envelope.py            # SOCP envelope creation/signing
│    ├── server.py              # mesh server (Master/Local)
│    ├── protocols.py           # protocol constants
│    └── main.py                # CLI entrypoint
├── clean.sh                    # Command line file to clean the enviornment
├── README.md
├── DESIGN.md
└── requirements.txt
```

## Install
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Quickstart
- **Master**: stable UUID stored in `keys/master.uuid` (generated once if missing).
- **Local server**: per-node UUID stored in `keys/server.uuid` (generated if missing).

### Generate UUIDs explicitly (optional)
```bash
# Generate and persist a Master server UUID (writes in keys/master.uuid)
python3 src/main.py gen master

# Generate and persist a Local server UUID (writes in keys/server.uuid)
python3 src/main.py gen local
```

### Run servers
```bash
# Master server (uses keys/master.uuid; creates if missing)
python3 src/main.py server --role master --listen 0.0.0.0:9101

# Local server (uses keys/server.uuid; creates if missing)
# Reads Master UUID from keys/master.uuid; you can also pass --master-uuid to override
python3 src/main.py server --role local --listen 127.0.0.1:9102 --master-url ws://127.0.0.1:9101

# If your master runs on another host, use --listen 0.0.0.0:9101 on the master and --master-url ws://<MASTER_IP>:9101 on locals.
```

### Run clients
```bash
# Client Alice
python3 src/main.py client --user-uuid Alice --server ws://127.0.0.1:9101

# Client Bob
python3 src/main.py client --user-uuid Bob --server ws://127.0.0.1:9102
```

### Client commands
```
/help                                               # list all available commands
/list                                               # fetch & display known online users (sorted)
/pubget                                             # print your own public key (SPKI DER base64url)
/dbget <user_uuid>                                  # fetch & cache <user>'s pubkey via Master (run before /tell)
/tell <user_uuid> <text>                            # send E2E-encrypted DM (AES-256-GCM + RSA-OAEP wrap + RSA-PSS signature)
/all <text>                                         # post to the mesh-wide public channel (authentic, not confidential)
/file <user_uuid|public> <file_path>                # send file: DM wraps per-file AES; 'public' broadcasts to all (no confidentiality)
/quit                                               # close the WebSocket and exit
```

### Message Flow

```bash
# --- DM  ---

# In Alice client:
/dbget Bob                                   # learn Bob's pubkey (one-time)
/tell Bob Hello Bob!                         # send E2E DM

# In Bob client:
/dbget Alice                                 # learn Alice's pubkey for replies
/tell Alice Hi Alice!                        # reply

# --- Public Channel ---

#In any client:
/all Hello Everyone                          # send message to all the online users
```

### File Sharing Flow

```bash
# --- DM  ---

# In Alice client:
/dbget Bob                                   # ensure you have Bob's pubkey
/file Bob ./requirements.txt                 # send file (manifest + encrypted chunks)

# --- Public Channel ---

# In any client:
/file public ./requirements.txt              # send file to all the online users
```

## Cleanup / Reset

Use the helper script to reset local state between runs.

```bash
# Make the script executable (one-time)
chmod +x clean.sh

# Clean state (keeps Master identity: keys/master.uuid + its PEM)
./clean.sh

# Full reset (also deletes Master identity)
./clean.sh --nuke-master
```

## SOCP Compliance
- Envelope: `{type, from, to, ts(ms), payload, sig}`, with `sig = RSA‑PSS(SHA‑256)` over **canonical `payload`** only.
- Crypto: RSA‑4096 (PSS & OAEP), AES‑256‑GCM, SHA‑256, **base64url (no padding)** for all binary values.
- Transport: WebSocket text frames (one JSON per frame).
- Master selection: **`--role master`** makes that node Master forever (UUID persisted). Locals auto-load the Master UUID from `keys/master.uuid` or `--master-uuid`.
