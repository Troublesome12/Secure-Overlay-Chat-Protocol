# SOCP Test Plan & Results

**Project:** Secure Overlay Chat Protocol (SOCP)\
**Version:** v1.3 (protocol freeze)\
**Repo layout:** flat `src/` (server, client); SQLite Master DB; WebSocket transport

---

## Installation

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
```
/help
/list
/pubget
/dbget <user_uuid>
/tell <user_uuid> <text>
/all <text>
/file <user_uuid|public> <file_path>
/quit
```
Artifacts saved under: 
- `downloads/` (received files) 
- `data/master_db.json` (directory) 
- `keys/` (generated keys)


## Test

### 1. Direct Messaging (`/tell`)

<table>
  <thead>
    <tr>
      <th style="text-align:center;">Test Case</th>
      <th style="text-align:center;">Steps</th>
      <th style="text-align:center;">Expected Result</th>
      <th style="text-align:center;">Actual Result</th>
      <th style="text-align:center;">Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:center;">Send DM</td>
      <td style="text-align:left;">1. Alice runs <code>/dbget Bob</code> <br>2. Alice runs <code>/tell Bob Hello Bob</code> </td>
      <td style="text-align:left;">Bob sees <code>[dm from Alice] 🔐 Hello Bob</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
    <tr>
      <td style="text-align:center;">Tampered Message </td>
      <td style="text-align:left;">Modify ciphertext in transit</code> </td>
      <td style="text-align:left;">Bob sees <code>[dm from Alice] ⚠️ <decrypt failed: ...></code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
  </tbody>
</table><br>

---

### 2. Public Channel Messaging (`/all`)

<table>
  <thead>
    <tr>
      <th style="text-align:center;">Test Case</th>
      <th style="text-align:center;">Steps</th>
      <th style="text-align:center;">Expected Result</th>
      <th style="text-align:center;">Actual Result</th>
      <th style="text-align:center;">Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:center;">Broadcast message</td>
      <td style="text-align:left;">Alice runs <code>/all hello</code> </td>
      <td style="text-align:left;">Alice sees <code>[you -> Public Channel] hello</code><br>Bob sees <code>[Public Channel] 🔐 Alice: hello</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
    <tr>
      <td style="text-align:center;">Deduplication</td>
      <td style="text-align:left;">Forwarded message loops</code> </td>
      <td style="text-align:left;">Only one copy is displayed per user</td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
  </tbody>
</table><br>

---

### 3. File Transfer (DM: `/file <user_uuid> <path>`)

<table>
  <thead>
    <tr>
      <th style="text-align:center;">Test Case</th>
      <th style="text-align:center;">Steps</th>
      <th style="text-align:center;">Expected Result</th>
      <th style="text-align:center;">Actual Result</th>
      <th style="text-align:center;">Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:center;">Send file via DM</td>
      <td style="text-align:left;">Alice runs <code>/file Bob ./requirements.txt</code></td>
      <td style="text-align:left;">Bob sees:<br> <code>[file] start requirements.txt (38 bytes)</code><br><code>[file] chunk #1 (38/38 bytes, 100%)</code><br><code>[file] end → saved to downloads/requirements.txt</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
    <tr>
      <td style="text-align:center;">Non-clobber</td>
      <td style="text-align:left;">Bob already has <code>requirements.txt</code></td>
      <td style="text-align:left;">Saved as <code>requirements (1).txt</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
  </tbody>
</table><br>

---

### 4. File Transfer (Public: `/file public <path>`)

<table>
  <thead>
    <tr>
      <th style="text-align:center;">Test Case</th>
      <th style="text-align:center;">Steps</th>
      <th style="text-align:center;">Expected Result</th>
      <th style="text-align:center;">Actual Result</th>
      <th style="text-align:center;">Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:center;">Broadcast file</td>
      <td style="text-align:left;">Bob runs <code>/file public ./report.pdf</code></td>
      <td style="text-align:left;">Alice sees:<br> <code>[file] from Bob: start Bob_report.pdf (...)</code><br><code>[file] end → saved to downloads/Bob_report.pdf</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
    <tr>
      <td style="text-align:center;">Exclude sender</td>
      <td style="text-align:left;">Bob sends file to public</td>
      <td style="text-align:left;">Bob does not receive his own file</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
    <tr>
      <td style="text-align:center;">Non-clobber</td>
      <td style="text-align:left;">Alice already has <code>Bob_report.pdf</code></td>
      <td style="text-align:left;">Saved as <code>Bob_report (1).pdf</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
  </tbody>
</table><br>

---

### 5. User Presence (`/list`)

<table>
  <thead>
    <tr>
      <th style="text-align:center;">Test Case</th>
      <th style="text-align:center;">Steps</th>
      <th style="text-align:center;">Expected Result</th>
      <th style="text-align:center;">Actual Result</th>
      <th style="text-align:center;">Status</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:center;">List users</td>
      <td style="text-align:left;">Alice runs <code>/list</code></td>
      <td style="text-align:left;">Alice sees:<br> <code>[online]</code><br><code>- Alice</code><br><code>- Bob</code></td>
      <td style="text-align:center;">as expected</td>
      <td style="text-align:center;"><b>Pass</b></td>
    </tr>
  </tbody>
</table><br>

---

## Coverage of Mandatory Features

-   `/list` ✓ 
-   `/tell <user_uuid> <text>` ✓
-   `/all <text>` ✓
-   `/file <user_uuid|public> <path>` ✓
