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
- **Server (mesh peer):** Peer linking (`SERVER_HELLO_JOIN` → `SERVER_WELCOME` → `SERVER_ANNOUNCE`), user presence gossip (`USER_ADVERTISE` / `USER_REMOVE`), and routing (`MSG_DIRECT`, `SERVER_DELIVER`, `USER_DELIVER`, `MSG_PUBLIC_CHANNEL`).
- **Master Database:** A central SQLite database (`data/socp.db`) to store user information, public channel membership, and RSA public keys.
- **Client:** Connects to one local server. Direct messages (DMs) are **RSA‑OAEP(SHA‑256)** encrypted and **RSA‑PSS(SHA‑256)** signed. Public messages are plaintext but signed for authenticity.
- **Security:** 100% **RSA‑4096** (no AES). Uses SHA‑256, base64url encoding, and canonical JSON for all signatures.

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

## Setup
```bash
brew install python@3.9
python -m venv venv && source venv/bin/activate
pip install -U pip setuptools wheel
pip install -r requirements.txt
```

## Running the System

### Start the Servers

```bash
# Master server (uses keys/master.uuid; creates if missing)
python3 src/main.py server --role master --listen 0.0.0.0:9101

# Local server (uses keys/server.uuid; creates if missing)
# Reads Master UUID from keys/master.uuid; you can also pass --master-uuid to override
python3 src/main.py server --role local --listen 127.0.0.1:9102 --master-url ws://127.0.0.1:9101

# If your master runs on another host, use --listen 0.0.0.0:9101 on the master and --master-url ws://<MASTER_IP>:9101 on locals.
```

### Start clients
```bash
# Client Alice (connects to master)
python3 src/main.py client --user-uuid Alice --server ws://127.0.0.1:9101

# Client Bob (connects to local server)
python3 src/main.py client --user-uuid Bob --server ws://127.0.0.1:9102
```

### Client commands
```
/help                                 # Show command list
/list                                 # Show online users
/pubget                               # Display your public key
/dbget <user_uuid>                    # Fetch another user's public key from master
/tell <user_uuid> <text>              # Send RSA-encrypted, PSS-signed DM
/all <text>                           # Broadcast a message to all users
/file <user_uuid|public> <path>       # Send file (RSA per-chunk for DM, plaintext for public)
/quit                                 # Exit the client
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

## Cleanup Script

To reset all runtime data and kill open ports:

```bash
chmod +x clean.sh           # Make the script executable (one-time)
./clean.sh                  # reset local runtime (preserves master identity)
./clean.sh --nuke-master    # Full reset  (deletes master identity too)
```
This removes DBs, cached keys, downloads, and running ports (9101–9103).

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
      <td style="text-align:left;"><code>{type, from, to, ts(ms), payload, sig}</code> — Canonical JSON, signed and verifiable</td>
    </tr>
    <tr> 
      <td style="text-align:left;">Signature</td>
      <td style="text-align:left;">RSA-PSS (SHA-256) over canonical <code>payload</code></td>
    </tr>
    <tr>
      <td style="text-align:left;">Encryption (DMs)</td>
      <td style="text-align:left;">Pure RSA-4096 OAEP (SHA-256); servers never decrypt user ciphertexts</td>
    </tr> 
    <tr> 
      <td style="text-align:left;">Encryption (Public Channel)</td>
      <td style="text-align:left;">Plaintext with RSA-PSS authenticity signature; no confidentiality enforced</td>
    </tr>
    <tr>
      <td style="text-align:left;">Hashing</td>
      <td style="text-align:left;">SHA-256 for message integrity, manifest signing, and file hashing</td>
    </tr>
    <tr>
      <td style="text-align:left;">Encoding</td>
      <td style="text-align:left;">Base64URL (no padding) for all binary data (keys, ciphertext, signatures)</td>
    </tr>
    <tr>
      <td style="text-align:left;">Transport</td>
      <td style="text-align:left;">WebSocket (JSON text frames; one envelope per frame)</td>
    </tr>
    <tr>
      <td style="text-align:left;">Persistence</td>
      <td style="text-align:left;">SQLite (<code>data/socp.db</code>) — stores users, keys, and public channel membership</td>
    </tr>
    <tr>
      <td style="text-align:left;">Identity</td>
      <td style="text-align:left;"><code>--role master</code> designates the permanent Master server (UUID + PEM persisted under <code>keys/</code>)</td>
    </tr>
  </tbody>
</table>
