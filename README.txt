Secure Overlay Chat Protocol (SOCP)
===================================

Version: 1.3
Language: Python 3
Type: Secure Distributed Chat System using WebSockets

---------------------------------------------------------
Overview
---------------------------------------------------------
The Secure Overlay Chat Protocol (SOCP) is a distributed chat application that allows
multiple servers and users to communicate securely across a peer-to-peer mesh.
It focuses on privacy, authentication, and message integrity using strong encryption.

The system uses RSA-4096 for encryption and signing, ensuring that every direct message,
file transfer, and public announcement is verifiable and tamper-proof. Each user connects
to a local server, and all servers in the mesh synchronize through the Master server.

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
   - Acts as a central authority.
   - Registers users and stores their public keys.
   - Communicates with all local servers in the mesh.

2. **Local Server**
   - Handles local user connections.
   - Relays messages and files between users and peers.
   - Keeps track of online users and their locations.

3. **Client**
   - User application for messaging and file sharing.
   - Supports both encrypted direct messages and public broadcasts.

4. **Encryption System**
   - Uses RSA-4096 OAEP (SHA-256) for encryption.
   - Uses RSA-PSS (SHA-256) for digital signatures.
   - AES-256-GCM is optionally used for file encryption.
   - Encodes binary data using Base64 URL format (no padding).

---------------------------------------------------------
Features
---------------------------------------------------------
- End-to-end encryption for private messages.
- Public message broadcasting to all users.
- Secure file sharing (encrypted for DM, signed for public).
- Peer-to-peer server linking (multi-server mesh).
- Automatic presence update (join/leave notifications).
- Signature verification for message authenticity.
- Minimal dependencies and easy setup.

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
Security Overview
---------------------------------------------------------
The system ensures:
- Confidentiality: Only the intended recipient can read messages.
- Integrity: Each message and file is signed to prevent tampering.
- Authentication: Every user and server has a unique RSA-4096 key.
- Non-repudiation: Senders cannot deny sending a signed message.

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
Protocol Compliance (v1.3)
---------------------------------------------------------
- Encryption: RSA-4096 OAEP (SHA-256)
- Signature: RSA-PSS (SHA-256)
- Encoding: Base64 URL without padding
- Transport: WebSocket JSON frames
- Structure: {type, from, to, ts, payload, sig}

---------------------------------------------------------
End of File
---------------------------------------------------------
