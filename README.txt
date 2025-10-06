Secure Overlay Chat Protocol (SOCP)
===================================

Version: 1.3
Language: Python 3
Type: Secure Distributed Chat System using WebSockets

---------------------------------------------------------
Overview
---------------------------------------------------------
The Secure Overlay Chat Protocol (SOCP) is a distributed, RSA-secured chat framework 
designed for confidential and authenticated communication across a peer-to-peer mesh 
of servers and users.

Each user connects to a local SOCP server, and all servers form a federated overlay 
where the Master server acts as the authoritative registry for user identities and 
public keys. 

All data exchanged — including messages, announcements, and file transfers — is 
protected through pure RSA-4096 cryptography (OAEP for encryption and PSS for signing), 
ensuring authenticity and integrity across the network without using any symmetric 
key wrapping.

!!! VULNERABILITY INJECTED — FOR STUDY PURPOSE !!!

---------------------------------------------------------
Group Information
---------------------------------------------------------
Group No: 45

Team Members:
- Sk Md Shariful Islam Arafat (a1983627)
- Aditya Dixit (a1980937)
- Hasnain Habib Sayed (a1988079)
- Sukarna Paul (a1986887)
- Atiq Ullah Ador (a1989573)

PoC:
- Name: Aditya Dixit
- Email: a1980937@adelaide.edu.au
- Phone: 0478614602

---------------------------------------------------------
Core Components
---------------------------------------------------------
1. **Master Server**
   - Acts as the root authority for the mesh.
   - Maintains the SQLite database (`data/socp.db`) storing registered users and 
     public keys.
   - Responds to DB lookup and registration requests from local servers.

2. **Local Server**
   - Hosts user connections locally via WebSocket.
   - Forwards encrypted messages and files to other servers based on routing tables.
   - Broadcasts user presence and public messages across the network.
   - Stores cached metadata and relays Master DB requests when needed.

3. **Client**
   - User-facing application for encrypted chat and file sharing.
   - Supports:
       - `/tell <user> <text>` → RSA-encrypted DM (end-to-end secure)
       - `/all <text>` → signed public broadcast
       - `/file <user|public> <path>` → per-chunk RSA file transfer
   - Each client holds an RSA-4096 keypair generated on first use.

4. **Encryption System**
   - **Encryption:** RSA-4096 OAEP (SHA-256) for all private messages and file chunks.
   - **Signing:** RSA-PSS (SHA-256) for message and file authenticity.
   - **Hashing:** SHA-256 for integrity checks and manifest verification.
   - **Encoding:** Base64URL (no padding) for all binary data.
   - **No AES hybrid:** all operations are handled via RSA only.

---------------------------------------------------------
Features
---------------------------------------------------------
- End-to-end encrypted Direct Messages using RSA-4096.
- Public Channel broadcasts signed with RSA-PSS (plaintext, authenticated only).
- File sharing with RSA-based encryption for DMs and signed plaintext for public.
- Peer-to-peer server linking (multi-server mesh replication).
- Real-time user presence (join and leave announcements).
- Automatic public channel membership upon connection.
- Persistent SQLite database for user, key, and group management.
- Clean separation between Master and Local server logic.

---------------------------------------------------------
Setup and Installation
---------------------------------------------------------
1. Create a virtual environment and install dependencies:
   $ python3 -m venv venv
   $ source venv/bin/activate
   $ pip install -r requirements.txt

2. Run the Master Server:
   $ python3 src/main.py server --role master --listen 0.0.0.0:9101

3. Run a Local Server:
   $ python3 src/main.py server --role local --listen 127.0.0.1:9102 --master-url ws://127.0.0.1:9101

4. Run Clients:
   $ python3 src/main.py client --user-uuid Alice --server ws://127.0.0.1:9101
   $ python3 src/main.py client --user-uuid Bob --server ws://127.0.0.1:9102

---------------------------------------------------------
Client Commands
---------------------------------------------------------
/help                       - List all available commands
/list                       - Show all users currently online
/pubget                     - Print your own public key
/dbget <user>               - Retrieve a user’s public key from Master
/tell <user> <text>         - Send a secure direct message (encrypted and signed)
/all <text>                 - Send a signed public message to everyone
/file <user|public> <path>  - Send files privately or to all users
/quit                       - Exit the client

---------------------------------------------------------
Example Usage
---------------------------------------------------------
1. Direct Message:
   Alice → Bob
   /dbget Bob
   /tell Bob Hello, Bob!

2. Public Message:
   /all Hello, everyone!

3. Private File Transfer:
   /dbget Bob
   /file Bob ./notes.txt

4. Public File Sharing:
   /file public ./requirements.txt

---------------------------------------------------------
Artifacts and Persistence
---------------------------------------------------------
All runtime data, keys, and received files are stored locally to allow 
persistent identities and message continuity across sessions.

Artifacts are saved under:

- `downloads/` — received files and attachments from peers
- `data/socp.db` — main SQLite database for users, public channel, and membership
- `keys/` — RSA-4096 PEM files and UUID identities for both Master and Local servers

---------------------------------------------------------
Reset and Cleanup
---------------------------------------------------------
If you want to reset your environment:

1. Make the cleanup script executable:
   $ chmod +x clean.sh

2. Reset all local data (except master keys):
   $ ./clean.sh

3. Full reset (deletes all keys including Master identity):
   $ ./clean.sh --nuke-master

---------------------------------------------------------
Security Overview
---------------------------------------------------------
The SOCP framework enforces:
- **Confidentiality:** Only the intended recipient can decrypt messages.
- **Integrity:** All payloads (messages, files, channel posts) are signed and verified.
- **Authentication:** Every entity (server or user) owns a persistent RSA-4096 keypair.
- **Non-repudiation:** Senders cannot deny signed communications.
- **No shared symmetric keys:** Every encryption and signature is performed using RSA-4096.

---------------------------------------------------------
Protocol Compliance (v1.3)
---------------------------------------------------------
- **Envelope Structure:** {type, from, to, ts, payload, sig}
- **Encryption:** RSA-4096 OAEP (SHA-256)
- **Signature:** RSA-PSS (SHA-256)
- **Hashing:** SHA-256
- **Encoding:** Base64URL (no padding)
- **Transport:** WebSocket (UTF-8 JSON text frames)
- **Persistence:** SQLite (`data/socp.db`) for user and channel records
- **Identity Management:** `--role master` designates the permanent Master UUID

---------------------------------------------------------
End of File
---------------------------------------------------------
