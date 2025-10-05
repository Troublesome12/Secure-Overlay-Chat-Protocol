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

**PoC:** 
- **Name:** Aditya Dixit
- **Email:** a1980937@adelaide.edu.au
- **Phone:** 0478614602

## Features
- **Server (mesh peer)**: Handles peer linking (`PEER_HELLO_LINK`), user presence gossip (`USER_ADVERTISE` / `USER_REMOVE`), and DM routing (`PEER_DELIVER` / `USER_DELIVER`).
- **Master DB**: Single authority (configurable by `--master-uuid`) for user registry & pubkey lookup. Locals proxy DB-RPC requests to the Master.
- **Client**: Users attach to one local server; DMs are **RSA-encrypted** (OAEP-SHA256) and **content‑signed** (RSA-PSS-SHA256).
- **Security**: Pure RSA-4096 cryptography — no AES keywrap — using SHA-256, base64url (no padding), and canonical JSON signing.

<br>

> VULNERABILITY INJECTED — FOR STUDY PURPOSE

## Project Tree
```
SOCP
├── src                               
│    ├── client.py              # user client
│    ├── crypto.py              # RSA-4096 PSS/OAEP, AES-256-GCM, helpers
│    ├── encoding.py            # base64url + canonical JSON
│    ├── envelope.py            # SOCP envelope creation/signing
│    ├── server.py              # mesh server (Master/Local)
│    ├── protocols.py           # protocol constants
│    ├── sdb.py                 # SQLite DB management file
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
/help                                               # list all commands
/list                                               # show all online users
/pubget                                             # print your own public key
/dbget <user_uuid>                                  # fetch and cache a user's public key
/tell <user_uuid> <text>                            # send RSA-OAEP encrypted + RSA-PSS signed DM
/all <text>                                         # post public message (signed only)
/file <user_uuid|public> <file_path>                # send file (RSA-OAEP per recipient; plaintext for public)
/quit                                               # close the client
```

### Message Flow

```bash
# --- DM (E2E) ---

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
chmod +x clean.sh           # Make the script executable (one-time)
./clean.sh                  # reset local runtime (preserves master identity)
./clean.sh --nuke-master    # Full reset  (deletes master identity too)
```

## SOCP Compliance (v1.3)

<table>
  <thead>
    <tr>
      <th style="text-align:center;">Layer</th>
      <th style="text-align:center;">Mechanism</th>
    </tr>
  </thead>
  <tbody>
  <tr>
      <td style="text-align:left;">Envelope</td>
      <td style="text-align:left;"><code>{type, from, to, ts(ms), payload, sig}</code></td>
    </tr>
    <tr>
      <td style="text-align:left;">Signature</td>
      <td style="text-align:left;">RSA-PSS(SHA-256) over canonical <code>payload</code></td>
    </tr>
    <tr>
      <td style="text-align:left;">Encryption (DMs)</td>
      <td style="text-align:left;">RSA-4096 OAEP(SHA-256) — no AES hybrid</td>
    </tr>
    <tr>
      <td style="text-align:left;">Hashing</td>
      <td style="text-align:left;">SHA-256</td>
    </tr>
    <tr>
      <td style="text-align:left;">Encoding</td>
      <td style="text-align:left;">base64url (no padding) for all binary fields</td>
    </tr>
    <tr>
      <td style="text-align:left;">Transport</td>
      <td style="text-align:left;">WebSocket (JSON text frames)</td>
    </tr>
    <tr>
      <td style="text-align:left;">Identity</td>
      <td style="text-align:left;"><code>--role</code> master designates permanent Master (UUID persisted)</td>
    </tr>
  </tbody>
</table><br>


## Version Notes
- v1.0 – v1.2: AES-GCM hybrid encryption (deprecated).
- v1.3: Fully RSA-based — simplified key management, stronger signature discipline, and reduced dependencies.