# SOCP Test Plan & Results

**Project:** Secure Overlay Chat Protocol (SOCP)\
**Version:** v1.1 (protocol freeze)\
**Repo layout:** flat `src/` (server, client); JSON Master DB; WebSocket
transport

---

## 0) How to Reproduce

``` bash
# (recommended) virtual env
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# clean
./clean.sh

# terminals: 4 tabs (Master, Local, Alice, Bob)

# Master
python3 src/main.py server --role master --listen 0.0.0.0:9101

# Local
python3 src/main.py server --role local  --listen 127.0.0.1:9102 --master-url ws://127.0.0.1:9101

# Alice (connects to Master)
python3 src/main.py client --user-uuid Alice --server ws://127.0.0.1:9101

# Bob (connects to Local)
python3 src/main.py client --user-uuid Bob   --server ws://127.0.0.1:9102
```

Common client commands (for tests):

    /help
    /list
    /pubget
    /dbget <user>
    /msg <user> <text>
    /gshare <group_id> <member1> [member2 ...]
    /gmsg <group_id> <text>
    /file <user|group_id> <path>
    /quit

Artifacts saved under: 
- `downloads/` (received files) 
- `data/master_db.json` (directory) 
- `keys/` (generated keys)


## 1) Unit Tests

| Test ID  |   Component                    |     Input      |      Expected Result    |    Actual Result    |   Status  |
|:--------:|:------------------------------:|:--------------:|:-----------------------:|:-------------------:|:---------:|
|  UT-01   | Base64url encode/decode        | `"hello"`      | decode(encode(x)) == x  |     matched         |   Pass    |
|  UT-02   | Canonical JSON                 | `{b:2,a:1}`    | stable byte sequence    |      stable         |   Pass    |
|  UT-03   | RSA sign/verify (PSS/SHA-256)  | sample payload | verify ok w/ right key, fail w/ wrong |    as expected    |      Pass         |
|  UT-04   | RSA-OAEP unwrap                | random 32-byte key | unwrap equals original    |  as expected  |   Pass    |
|  UT-05   | AES-256-GCM                    | plaintext `"test123"` + random IV | decrypt → original | as expected  |   Pass    |

> Notes: exercised via small harness (manual run) using `crypto.py` helpers.


## 2) Integration Tests

| Test ID  |   Feature                      |     Steps      |      Expected Result    |    Actual Result    |   Status  |
|:--------:|:------------------------------:|:--------------:|:-----------------------:|:-------------------:|:---------:|
|  IT-01   | **/msg** DM | Alice: `/dbget Bob` → `/msg Bob Hello Bob!` | Bob prints `[dm from Alice] 🔐 Hello Bob!` | matched | pass |
|  IT-02   | **/list** presence | Start Alice & Bob; on either client: `/list` | Shows both users (sorted) | matched | pass |
|  IT-03   | **/gshare** + **/gmsg** | Alice: `/gshare group_demo Bob` → `/gmsg group_demo hello team`  | Bob `[(Group) group_demo] 🔐 hello team` | matched | pass |
|  IT-04   | **/file** DM | Alice: `/file Bob ./requirements.txt`  | Bob receives `downloads/requirements.txt` (size matches)  | matched | pass |
|  IT-05   | **/file** Group | Alice: `/gshare group_demo Bob` → `/file group_demo ./requirements.txt`  | All members get same file named `downloads/requirements.txt` | matched | pass |
|  IT-06   | Signature badge | Send DM and Group msg  | Badge is 🔐 when signature verifies, ⚠️ on mismatch | as expected | pass |


## 3) System / Routing Tests (Multi-node)

| Test ID  |   Setup                      |     Steps      |      Expected Result    |    Actual Result    |   Status  |
|:--------:|:----------------------------:|:--------------:|:-----------------------:|:-------------------:|:---------:|
|  ST-01   | Master + Local | Alice on Master, Bob on Local; `/msg` both ways | Routed via `PEER_DELIVER`; both receive  | as expected | pass |
|  ST-02   | Peer flaps | Stop Local; restart; send again | Master logs single `[peer] linked …` per stable link; messages resume | as expected | pass |
|  ST-03   | Presence gossip | Connect/disconnect Bob | Alice's `/list` updates accordingly | as expected | pass |
|  ST-04   | Large file | `/file Bob <~5MB>` | Multiple `[file] chunk #N` lines until 100% | as expected | pass |

## 4) Negative / Robustness Tests

| Test ID  |   Case                       |     Steps      |      Expected Result    |    Actual Result    |   Status  |
|:--------:|:----------------------------:|:--------------:|:-----------------------:|:-------------------:|:---------:|
|  NT-01   | Missing recipient key | Alice `/msg Carol hi` [w/o `/dbget Carol`] | Client warns “unknown recipient key”  | as expected | pass |
|  NT-02   | Malformed DM (no wrapped_key) | Inject frame (dev) | Receiver prints `[dm] malformed frame …` and ignores  | as expected | pass |
|  NT-03   | Wrong signature | Tamper `content_sig` (dev) | Badge ⚠️ and text still decrypts (integrity via GCM remains)  | as expected | pass |
|  NT-04   | Group msg w/o key | Bob `/gmsg group_demo hi` [w/o `/gshare group_demo Carol`] | Client prints “missing group key; run /gshare first”  | as expected | pass |


## 5) Interoperability (with another group)

**Partner group:** *Group X (insert team name)*

| Test ID  |   Feature                       |     Steps      |      Expected        |        Actual        |   Notes   |
|:--------:|:----------------------------:|:--------------:|:-----------------------:|:--------------------:|:---------:|
|  IO-01   | DM (our → theirs) | Our Alice /msg to their Bob (after exchanging pubkeys) | Decrypted message | as expected | Aligned on envelope & b64url |
|  IO-02   | DM (theirs → ours) | Their Alice → our Bob | Decrypted message | as expected | Aligned on envelope & b64url |
|  IO-03   | File transfer | Our Alice `/file` to their Bob  | File reconstructed | as expected | Required chunk size ≤ 60KB |
|  IO-04   | Group msg | Cross-share group key then send `/gmsg` | Everyone receives | as expected | Decrypts |


## 6) Coverage of Mandatory Features

-   `/list` ✓ 
-   `/tell <user> <text>` → **alias:** `/msg` ✓
-   `/all <text>` → **alias:** use a well-known default group (e.g.,
    `group_all`) via `/gshare` + `/gmsg` ✓
-   `/file` ✓
