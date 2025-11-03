# 🧩 Performance Analysis of Blockchain-Based Decentralized Chat & File Transfer on LAN 

A fully interactive, **secure**, decentralized **LAN chat + file share** built on a blockchain-style append-only ledger.  
Every chat/file TX becomes a block; peers sync the longest valid chain and **verify on-disk files**.  
Now with **message deduplication**, **tamper-alert cooldowns**, faster UI dispatch, and **red-highlighted blocks** in the explorer on tamper.

---

## 🚀 Overview
This application demonstrates how blockchain principles can harden day‑to‑day collaboration on a local network. Each message or file is recorded immutably; peers reconcile forks via a chain‑sync protocol and continuously check local files for tampering. When a mismatch is detected, a **TAMPER_ALERT** is broadcast (without spam), and a one‑click **Fix Files** tool requests a clean copy from healthy peers.

Recent updates include:
- **Deduplicated network messages** (no more repeated alerts).
- **Per‑file tamper alert cooldown** + global anti‑spam controls.
- **Explorer highlight:** tampered/missing blocks render with a **red accent**.
- **Faster GUI event loop**; lower perceived latency.
- Safer shutdown to avoid Tk “application destroyed” errors.

---

## 🛡️ Key Features
- **Blockchain Backbone:** Each TX (chat/file) is a block; longest valid chain wins.
- **Peer Synchronization:** `REQUEST_CHAIN` / `RESPONSE_CHAIN` + on‑append rebroadcast.
- **Cross‑Network Tamper Checks:** Periodic local verify + broadcast `TAMPER_ALERT` and peer replies for `TAMPER_CHECK_REQUEST`.
- **Smart Anti‑Spam:**
  - Message **dedup IDs** to drop repeats.
  - **Per‑file cooldown** to throttle repeated tamper alerts.
  - **Rate limiter** (token bucket) per remote peer.
- **One‑Click Restore:** `🛠 Fix Files` sends `FILE_SYNC_REQUEST`; a healthy peer replies with `FILE_SYNC_RESPONSE` to restore the exact bytes.
- **Explorer with Red Highlight:** Tampered/missing blocks are visually flagged.
- **Live Metrics:** Latency, throughput, and simulated loss visualized with Matplotlib.
- **Cross‑Platform Notifications:** macOS (osascript) / Windows (win10toast) optional.
- **Resource Safety:** Bounded queues, size caps, timeouts, context managers.
- **Security Extras:** Path traversal prevention, input validation, thread‑safe chain.

---

## ⚙️ System Requirements
- **Python:** 3.10+
- **OS:** Windows / macOS / Linux
- **Network:** Devices on the same LAN (Wi‑Fi or Ethernet)

---

## 🐍 Install Python
### macOS (Homebrew)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python
python3 --version
pip3 --version
```
(Optional) create a venv:
```bash
python3 -m venv venv && source venv/bin/activate
```

### Windows
- Download Python 3.10+ from python.org → **check “Add Python to PATH.”**
```powershell
python --version
pip --version
python -m venv venv
.\venv\Scripts\activate
```

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-tk
python3 --version
pip3 --version
```

> On macOS/Linux you may need `python3` / `pip3` instead of `python` / `pip`.

---

## 📦 Dependencies
Install directly (use `pip3` if needed):
```bash
pip install customtkinter matplotlib networkx win10toast
```
> Linux needs Tk:
> ```bash
> sudo apt install -y python3-tk
> ```

---

## ▶️ How to Run
1. Place `blockchain_chat.py` and this `README.md` in a folder.
2. Start the **first node** (no peers):
   ```bash
   python blockchain_chat.py
   ```
3. In **Start Your Node**:
   - **Node Name:** e.g., `Node-A`
   - **Your Port:** e.g., `5001`
   - **Connect to Peers:** leave empty (first node)
   - Click **🚀 Start Node**

### Add more nodes on the same machine
Open new terminals and run:
```bash
python blockchain_chat.py
```
- For the second node: name `Node-B`, port `5002`, peers: `localhost:5001`
- For a third: name `Node-C`, port `5003`, peers: `localhost:5001, localhost:5002`

### Add nodes on other machines (LAN)
- Use the host’s LAN IP in **Connect to Peers**: `192.168.x.y:5001`
- Allow Python in OS firewall for the chosen ports.

---

## 📖 Step‑by‑Step User Manual

### 1) Send Messages
- Type in the input box → **Enter** or click **📤 Send**.
- A block is created and broadcast; the chat bubble appears locally and remotely.

### 2) Send a File
- Click **📎 File** and choose a file (≤ 50 MB).
- File bytes are sent; a file‑TX block is added with the **SHA‑256**.
- Files save to **~/Downloads** and are verified periodically.

### 3) View the Blockchain
- Click **🔗 Explorer** → a horizontal chain graph appears.
- Click any block to see its hash, prev hash, time, and TX details.
- **If a file TX is tampered/missing, its block is shown with a red accent.**

### 4) Monitor Performance
- Click **📊 Performance** to see **Latency**, **Throughput**, **Loss** over time.

### 5) Fix Files (Restore)
- Click **🛠 Fix Files** → **🔧 Fix All Problems**.
- The node broadcasts `FILE_SYNC_REQUEST` for each missing/tampered file.
- A healthy peer replies with `FILE_SYNC_RESPONSE`; the file is restored to Downloads.

### 6) Verify Network
- Click **🔍 Verify Network**. Your node:
  - Runs local verification (chain linkage + file hashes).
  - Broadcasts `VERIFY_REQUEST` to peers.
- **Peers respond** with `VERIFY_RESPONSE { ok, issues[] }` which the console shows.

### 7) Color‑Coded Peers
- Peers are given persistent colors (stored in `peer_colors.json`).

### 8) Quit Safely
- Close the window; the app stops timers/animation and closes sockets cleanly.

---

## 🧪 Testing (Single PC or LAN)

### A) Single laptop (multi‑node)
- Run 2–4 instances on ports **5001, 5002, 5003, …** and interconnect via `localhost:<port>`.

### B) LAN
- Devices on the same network; connect to a peer using `hostLANIP:port`.

### C) Tamper Demo + Restore
1. Send a small file.
2. On one node, **edit or overwrite** the saved copy in **~/Downloads**.
3. Wait ≤ 60s or click **🔍 Verify Network** → **TAMPER_ALERT** appears (not spammed).
4. Click **🛠 Fix Files → 🔧 Fix All Problems** on any node. A good peer restores the file.

> **Note:** With only **one** node running, no one can restore your tampered file. Start at least two nodes.

---

## ⚙️ Configuration Knobs (in code)
- `VERIFICATION_INTERVAL = 60` — periodic integrity scan (seconds)
- `HEARTBEAT_INTERVAL = 12` — peer heartbeat
- `PEER_TIMEOUT = 30` — mark peer inactive
- `MAX_REQUESTS_PER_MINUTE = 100` — per‑peer rate limiter
- `MAX_MESSAGE_SIZE = 100*1024*1024` (100 MB) — network payload cap
- `MAX_FILE_SIZE = 50*1024*1024` (50 MB) — file transfer cap
- **Dedup/Spam Control:**
  - `message_ttl = 600` — remember seen IDs for 10 minutes
  - `seen_cleanup_interval = 300` — prune old IDs
  - `TAMPER_ALERT_COOLDOWN = 90` — minimum seconds between alerts for the same file
- **UI Responsiveness:**
  - GUI dispatcher runs frequently (≈60 ms) for snappy updates
  - Retry backoff starts low; does not affect successful sends

---

## 🧯 Troubleshooting
| Symptom | Likely Cause | Fix |
|---|---|---|
| “application has been destroyed” on exit | After‑callbacks firing post‑close | Use the latest build (cancels timers/animation on shutdown). |
| `f-string: unmatched ']'` | Edited a log string incorrectly | Use the provided code; avoid inserting stray braces/brackets. |
| `'App' has no attribute _show_start_dialog` | Partial copy of the file | Re‑download the full script; the method is defined in `App`. |
| Peers don’t appear | Not connected / firewall | Add peers in the dialog; allow Python through the firewall. |
| Messages feel slow | Large file in flight / rate‑limit hit | Send large files when idle; default rate limit is generous. |
| No restore happens | Only one node running | Start at least two nodes; a healthy peer must serve the file. |

---

## 🔐 Security Enhancements Recap
- Thread‑safe blockchain (RLock)
- Sanitized file names + path traversal prevention
- Bounded queues and size caps
- Timeouts and context‑managed I/O
- **Per‑peer** rate limiting
- **Message ID deduplication** (CHAT/BLOCK/FILE/ALERT/VERIFY)
- **Per‑file tamper alert cooldown** to prevent alert floods

---

## 🧱 System Architecture
```text
GUI (CustomTkinter) ──► GUI Queue (batched) ──► Dispatcher
                                  │
                                  ▼
                         P2P Node (sockets, rate limit,
                         dedup, retries, heartbeats, metrics)
                                  │
                                  ├──► SimpleChain (append‑only, replace longest)
                                  │
                                  └──► File Ops (hashing, verify, sync/restore)
```

---

## 🔮 Future Enhancements
- Optional signatures for TX authenticity
- Chunked, resumable file transfer
- Multicast/MDNS peer discovery
- Export/import chain snapshots
- Web dashboard viewer

---

## 🏁 Conclusion
This application offers a practical, classroom‑friendly view of **distributed integrity**, **peer coordination**, and **resilience**. With deduplication, cooldowns, and visual tamper flags, it’s ideal for demonstrating how blockchain‑style systems behave under failure and recovery.

---

## 👨‍💻 Authors
**Ilangkumaran Yogamani** — *ilangkumaran.2024@vitstudent.ac.in*  
**Ranen Abner** — *ranen.abner2024@vitstudent.ac.in*

---

## 📜 License
MIT License. Use, modify, and distribute with attribution; no warranty.

---

## 🙏 Acknowledgements
- **CustomTkinter**, **Tkinter**
- **Matplotlib**, **NetworkX**
- **Python sockets & threading**
- Everyone who tested and reported timing/dedup issues
