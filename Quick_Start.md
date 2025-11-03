# ⚡ QUICK START — Blockchain P2P Chat (Secured, Deduped)

This is the short, practical guide. For full docs, see **README_updated.md**.

---

## 1) Install Python & Deps
- **Windows/macOS**: Install Python 3.10+ from python.org (check “Add to PATH” on Windows).
- **Linux**: `sudo apt install -y python3 python3-pip python3-venv python3-tk`

Create a venv (recommended):
```bash
python -m venv venv        # or: python3 -m venv venv
# Windows: .\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

Install packages:
```bash
pip install -r requirements.txt
```

---

## 2) Run the First Node (no peers yet)
```bash
python bccc.py   # or: python3 bccc.py
```
In **Start Your Node**:
- **Node Name**: `Node-A` (any unique name)
- **Your Port**: `5001` (or any free port 1024–65535)
- **Connect to Peers**: leave empty
- Click **🚀 Start Node**

---

## 3) Add More Nodes

### Same machine
Open a new terminal for each extra node:
```bash
python bccc.py
```
- **Node-B** on port **5002**, peers: `localhost:5001`
- **Node-C** on port **5003**, peers: `localhost:5001, localhost:5002`

### Different machines (LAN)
- Use the host machine’s **LAN IP**: e.g., `192.168.1.20:5001`
- Allow Python through your firewall for chosen ports

---

## 4) Use the App
- **Send Chat**: type → **Enter** or **📤 Send**
- **Send File**: **📎 File** (≤ 50 MB)
- **Explorer**: **🔗 Explorer** → click a block for details
- **Performance**: **📊 Performance** → live latency/throughput/loss
- **Verify**: **🔍 Verify Network** (local + peer reports)
- **Restore**: **🛠 Fix Files → 🔧 Fix All Problems** (requests good copy from peers)

---

## 5) Tamper Demo (with restore)
1. Send a small file
2. On one node, **edit or overwrite** the saved copy in **~/Downloads**
3. Wait ≤ 60s or click **🔍 Verify Network** → **TAMPER_ALERT** appears
4. Click **🛠 Fix Files → 🔧 Fix All Problems** on any node to restore from a healthy peer

> With only one node, no one can restore your file. Run at least two nodes.

---

## 6) Common Issues
- **Peers don’t show**: add peer addresses correctly; check firewall; same LAN
- **Slow messages**: avoid sending huge files during chat; default rate limit is generous
- **Exit errors**: close from UI; latest build cancels timers/animations on shutdown
- **Tk not found (Linux)**: `sudo apt install -y python3-tk`

---

## 7) Defaults (in code)
- `VERIFICATION_INTERVAL = 60` s (auto file integrity)
- `HEARTBEAT_INTERVAL = 12` s
- `TAMPER_ALERT_COOLDOWN = 90` s (no spammy alerts)
- `MAX_FILE_SIZE = 50 * 1024 * 1024`
- `MAX_REQUESTS_PER_MINUTE = 100`
- Files save to **~/Downloads**

Happy testing! 🚀
