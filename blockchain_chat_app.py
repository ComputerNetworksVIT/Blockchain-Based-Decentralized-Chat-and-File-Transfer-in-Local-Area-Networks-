#!/usr/bin/env python3
"""
Enhanced Interactive Multi-Client Blockchain Chat - SECURED VERSION
Features:
- Complete chain synchronization with REQUEST_CHAIN/RESPONSE_CHAIN
- Network-wide tamper verification via VERIFY_REQUEST/VERIFY_RESPONSE
- File tampering detection with automatic alerts to all peers
- Refined UI with better visualization
- Real-time performance metrics (latency, throughput, packet loss)
- Blockchain visualizer with click-to-inspect blocks
- Cross-platform notifications
- Persistent peer color coding

SECURITY ENHANCEMENTS:
- Thread-safe blockchain operations with proper locking
- Resource leak prevention with context managers
- Input validation and sanitization
- Message size limits and timeouts
- Rate limiting protection
- Path traversal prevention
- Bounded memory usage

FIXES:
- Fixed canvas scrolling mechanism
- Fixed cross-network file tampering verification
- Improved error handling throughout
- Better thread synchronization
- Enhanced file sync mechanism
- Automatic periodic integrity checks
- Explorer highlights blocks involved in tamper alerts / fixes
"""

import os
import json
import random
import socket
import threading
import time
import queue
import hashlib
import base64
import uuid
import subprocess
import platform
import re
import sys
from datetime import datetime, timezone
from contextlib import contextmanager
from collections import defaultdict, deque

import customtkinter as ctk
from tkinter import filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import networkx as nx

# Optional Windows notification
try:
    from win10toast import ToastNotifier
except Exception:
    ToastNotifier = None

# Python version compatibility
try:
    # Python 3.11+
    UTC = datetime.UTC
except AttributeError:
    # Python 3.10 and earlier
    UTC = timezone.utc

# ==================== Configuration ====================
DOWNLOADS = os.path.join(os.path.expanduser("~"), "Downloads")
os.makedirs(DOWNLOADS, exist_ok=True)

PEER_COLOR_FILE = "peer_colors.json"
PACKET_LOSS_PROB = 0.0  # Simulate packet loss (0.0 = no loss)
PERF_LOG_PATH = "perf_log.txt"

# Security limits
MAX_MESSAGE_SIZE = 100 * 1024 * 1024  # 100MB max message size
MAX_CHAIN_LENGTH = 10000  # Maximum blockchain length
MAX_PENDING_MESSAGES = 1000  # Max pending retry messages
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB max file size
RECV_TIMEOUT = 30.0  # Socket receive timeout
CONNECT_TIMEOUT = 5.0  # Socket connect timeout
MAX_REQUESTS_PER_MINUTE = 100  # Rate limit per peer

# Verification settings
VERIFICATION_INTERVAL = 60  # Automatic verification every 60 seconds
HEARTBEAT_INTERVAL = 12  # Heartbeat every 12 seconds
PEER_TIMEOUT = 30  # Consider peer inactive after 30 seconds

# Color palette for peer identification
COLORS = [
    "#66b3ff", "#ffb366", "#99ff99", "#ff99cc", "#c299ff",
    "#ffd480", "#8dd3c7", "#fdb462", "#b3de69", "#bebada",
    "#8ecae6", "#ffb703", "#6a4c93", "#ff6b6b", "#4ecdc4"
]
SELF_COLOR = "#2a9d8f"
SYSTEM_COLOR = "#e9c46a"
ALERT_COLOR = "#e63946"
SWATCH_SIZE = 12

gui_queue = queue.Queue(maxsize=10000)  # Bounded queue
peer_colors = {}
active_peers = {}  # Live peer tracker
lock = threading.RLock()  # Global lock for active_peers

SYSTEM = platform.system().lower()
WIN_NOTIFIER = ToastNotifier() if (SYSTEM == "windows" and ToastNotifier) else None

# ==================== Utility Functions ====================
def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal attacks"""
    if not filename:
        return "unnamed_file"
    safe_name = os.path.basename(filename)
    safe_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', safe_name)
    if len(safe_name) > 255:
        name, ext = os.path.splitext(safe_name)
        safe_name = name[:250] + ext
    if not safe_name or safe_name in ['.', '..']:
        safe_name = f"file_{uuid.uuid4().hex[:8]}"
    return safe_name

def load_peer_colors():
    """Load peer color mappings from file"""
    global peer_colors
    if os.path.exists(PEER_COLOR_FILE):
        try:
            with open(PEER_COLOR_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    peer_colors.update(data)
        except Exception as e:
            print(f"[warn] Could not load peer colors: {e}")
            peer_colors.clear()
            save_peer_colors()

def save_peer_colors():
    """Save peer color mappings to file"""
    try:
        with open(PEER_COLOR_FILE, "w") as f:
            json.dump(peer_colors, f, indent=2)
    except Exception as e:
        print(f"[error] saving peer_colors: {e}")

def ensure_peer_color(name):
    """Assign a unique color to a peer if not already assigned"""
    if not name:
        return
    with lock:
        active_peers[name] = time.time()
    if name in peer_colors:
        return
    used = set(peer_colors.values())
    available = [c for c in COLORS if c not in used]
    color = random.choice(available) if available else random.choice(COLORS)
    peer_colors[name] = color
    save_peer_colors()
    enqueue_gui("update_legend")

def enqueue_gui(action, *args):
    """Thread-safe GUI update queue"""
    try:
        gui_queue.put_nowait((action, args))
    except queue.Full:
        try:
            gui_queue.get_nowait()
            gui_queue.put_nowait((action, args))
        except Exception:
            pass

def notify_user(title, msg):
    """Cross-platform desktop notifications"""
    try:
        if SYSTEM == "darwin":
            safe_title = str(title).replace('"', '\\"').replace('`', '\\`')[:100]
            safe_msg = str(msg).replace('"', '\\"').replace('`', '\\`')[:200]
            subprocess.run(
                ["osascript", "-e", f'display notification "{safe_msg}" with title "{safe_title}"'],
                timeout=5,
                stderr=subprocess.DEVNULL
            )
        elif SYSTEM == "windows" and WIN_NOTIFIER:
            WIN_NOTIFIER.show_toast(str(title)[:100], str(msg)[:200], duration=4, threaded=True)
        else:
            print(f"[notify] {title}: {msg}")
    except Exception:
        pass

# ==================== Rate Limiter ====================
class RateLimiter:
    """Token bucket rate limiter for request throttling"""
    def __init__(self, max_requests, time_window=60.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()

    def is_allowed(self, peer_id):
        """Check if request from peer is allowed"""
        with self.lock:
            now = time.time()
            peer_requests = self.requests[peer_id]
            while peer_requests and peer_requests[0] < now - self.time_window:
                peer_requests.popleft()
            if len(peer_requests) < self.max_requests:
                peer_requests.append(now)
                return True
            return False

    def cleanup_old_peers(self):
        """Remove inactive peers from tracking"""
        with self.lock:
            now = time.time()
            inactive = [
                peer_id for peer_id, reqs in self.requests.items()
                if not reqs or reqs[-1] < now - self.time_window * 2
            ]
            for peer_id in inactive:
                del self.requests[peer_id]

# ==================== Performance Analyzer ====================
class PerformanceAnalyzer:
    """Track and analyze network performance metrics"""
    def __init__(self):
        self.latency_records = {}
        self.throughput_records = {}
        self.results = []
        self.total_sent = 0
        self.total_lost = 0
        self.history = {
            "latency": deque(maxlen=300),
            "throughput": deque(maxlen=300),
            "loss": deque(maxlen=300)
        }
        self.lock = threading.Lock()

    def start_latency(self, ping_id):
        with self.lock:
            self.latency_records[ping_id] = time.time()

    def end_latency(self, ping_id):
        with self.lock:
            if ping_id in self.latency_records:
                rtt = time.time() - self.latency_records.pop(ping_id)
                self.results.append(("latency", rtt))
                self.history["latency"].append(rtt * 1000.0)
                self._log_perf("LATENCY", rtt)
                enqueue_gui("print", f"📶 RTT {ping_id[:6]}: {rtt*1000:.1f} ms")
                enqueue_gui("update_metrics")
                return rtt
        return None

    def start_throughput(self, tx_id, size):
        with self.lock:
            self.throughput_records[tx_id] = (time.time(), size)

    def end_throughput(self, tx_id):
        with self.lock:
            rec = self.throughput_records.pop(tx_id, None)
            if rec:
                start, size = rec
                dur = time.time() - start
                if dur > 0:
                    bps = size / dur
                    self.results.append(("throughput", bps))
                    self.history["throughput"].append(bps / 1024.0)
                    self._log_perf("THROUGHPUT", bps, extra=size)
                    enqueue_gui("print",
                        f"🚀 {tx_id[:6]}: {bps/1024.0:.2f} KB/s ({size} bytes in {dur:.2f}s)")
                    enqueue_gui("update_metrics")
                    return bps
        return None

    def record_packet_sent(self):
        with self.lock:
            self.total_sent += 1
            enqueue_gui("update_metrics")

    def record_packet_lost(self):
        with self.lock:
            self.total_lost += 1
            self.history["loss"].append(self.packet_loss_rate())
            enqueue_gui("print", "⚠️ Simulated packet loss")
            enqueue_gui("update_metrics")

    def avg_latency(self):
        with self.lock:
            vals = [v for (k, v) in self.results if k == "latency"]
            return sum(vals) / len(vals) if vals else 0.0

    def avg_throughput(self):
        with self.lock:
            vals = [v for (k, v) in self.results if k == "throughput"]
            return sum(vals) / len(vals) if vals else 0.0

    def packet_loss_rate(self):
        return (self.total_lost / self.total_sent * 100.0) if self.total_sent else 0.0

    def _log_perf(self, tag, value, extra=None):
        try:
            ts = datetime.now(UTC).isoformat()
            with open(PERF_LOG_PATH, "a") as f:
                if tag == "LATENCY":
                    f.write(f"{ts}\tLATENCY\t{value:.6f}\n")
                elif tag == "THROUGHPUT":
                    f.write(f"{ts}\tTHROUGHPUT\t{value:.2f}\tbytes={extra}\n")
        except Exception:
            pass

    def get_history_snapshot(self):
        with self.lock:
            return {
                "latency": list(self.history["latency"]),
                "throughput": list(self.history["throughput"]),
                "loss": list(self.history["loss"])
            }

perf = PerformanceAnalyzer()

# ==================== Blockchain ====================
class Block:
    """Blockchain block with transaction data"""
    def __init__(self, idx, prev_hash, ts, txs, nonce=0):
        self.index = idx
        self.prev_hash = prev_hash
        self.timestamp = ts
        self.txs = txs
        self.nonce = nonce

    def to_dict(self):
        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "txs": self.txs,
            "nonce": self.nonce
        }

    def hash(self):
        return hashlib.sha256(
            json.dumps(self.to_dict(), sort_keys=True).encode()
        ).hexdigest()

class SimpleChain:
    """Thread-safe blockchain implementation with validation"""
    def __init__(self):
        self.lock = threading.RLock()
        with self.lock:
            self.chain = [Block(
                0, "0" * 64, time.time(),
                [{"type": "genesis", "msg": "genesis"}]
            )]
            self.save()

    def last(self):
        with self.lock:
            return self.chain[-1]

    def append_tx_as_block(self, tx):
        with self.lock:
            prev = self.chain[-1]
            b = Block(prev.index + 1, prev.hash(), time.time(), [tx])
            self.chain.append(b)
            self.save()
            return b

    def add_block(self, b):
        with self.lock:
            if len(self.chain) >= MAX_CHAIN_LENGTH:
                return False
            last = self.chain[-1]
            if b.prev_hash == last.hash() and b.index == last.index + 1:
                self.chain.append(b)
                self.save()
                return True
            return False

    def is_valid_chain(self, chain_blocks):
        if not chain_blocks or len(chain_blocks) > MAX_CHAIN_LENGTH:
            return False
        try:
            genesis_dict = self.chain[0].to_dict()
            their_genesis = chain_blocks[0].to_dict()
            if (genesis_dict["index"] != their_genesis["index"] or
                genesis_dict["prev_hash"] != their_genesis["prev_hash"]):
                return False
        except Exception:
            return False
        for i in range(1, len(chain_blocks)):
            prev = chain_blocks[i - 1]
            cur = chain_blocks[i]
            if cur.prev_hash != prev.hash():
                return False
            if cur.index != prev.index + 1:
                return False
        return True

    def replace_chain(self, chain_blocks):
        with self.lock:
            if (self.is_valid_chain(chain_blocks) and
                len(chain_blocks) > len(self.chain)):
                self.chain = chain_blocks
                self.save()
                return True
            return False

    def save(self):
        try:
            with open("blockchain.json", "w") as f:
                json.dump([bb.to_dict() for bb in self.chain], f, indent=2)
        except Exception as e:
            print(f"[error] saving blockchain: {e}")

    def get_chain_copy(self):
        with self.lock:
            return list(self.chain)

# ==================== Networking ====================
def send_json(host, port, payload, timeout=CONNECT_TIMEOUT):
    """Send JSON payload to peer with proper resource management"""
    perf.record_packet_sent()
    if random.random() < PACKET_LOSS_PROB:
        perf.record_packet_lost()
        return False
    sock = None
    try:
        data = json.dumps(payload).encode() + b"\n"
        if len(data) > MAX_MESSAGE_SIZE:
            print(f"[error] Message too large: {len(data)} bytes")
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(data)
        return True
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

class Node:
    """P2P Network Node with blockchain capabilities"""
    def __init__(self, host, port, peers, name=None):
        self.host = host
        self.port = int(port)
        self.peers = set(peers)
        self.peers_lock = threading.Lock()
        self.name = name or f"{socket.gethostname()}:{self.port}"
        ensure_peer_color(self.name)
        self.chain = SimpleChain()
        self.pending = deque(maxlen=MAX_PENDING_MESSAGES)
        self.pending_lock = threading.Lock()
        self.rate_limiter = RateLimiter(MAX_REQUESTS_PER_MINUTE)
        self.running = True
        self.verify_results = {}
        self.verify_lock = threading.Lock()

        # MESSAGE DEDUPLICATION SYSTEM
        self.seen_messages = {}  # message_id -> timestamp
        self.seen_lock = threading.Lock()
        self.seen_cleanup_interval = 300  # Clean old entries every 5 minutes
        self.message_ttl = 600  # Keep message IDs for 10 minutes

        self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self._server_thread.start()
        time.sleep(1.0)

        self._hello_peers()

        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()

        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        # FIXED: Add automatic verification thread
        self._verification_thread = threading.Thread(target=self._verification_loop, daemon=True)
        self._verification_thread.start()

        # Start seen messages cleanup thread
        self._seen_cleanup_thread = threading.Thread(target=self._seen_cleanup_loop, daemon=True)
        self._seen_cleanup_thread.start()

    def _generate_message_id(self, msg):
        """Generate unique ID for message deduplication"""
        msg_type = msg.get("type", "")
        if msg_type == "CHAT":
            tx = msg.get("tx", {})
            return f"chat_{tx.get('tx_id', '')}_{tx.get('sender', '')}_{tx.get('sent_ts', '')}"
        elif msg_type == "BLOCK":
            blk = msg.get("block", {})
            return f"block_{blk.get('index', '')}_{blk.get('prev_hash', '')}"
        elif msg_type == "FILE_TRANSFER":
            return f"file_{msg.get('tx_id', '')}_{msg.get('from', '')}"
        elif msg_type == "TAMPER_ALERT":
            alert = msg.get("alert", {})
            return f"tamper_{alert.get('filename', '')}_{alert.get('from', '')}_{alert.get('timestamp', '')}"
        elif msg_type == "TAMPER_CHECK_REQUEST":
            file_info = msg.get("file_info", {})
            return f"tampercheck_{file_info.get('filename', '')}_{msg.get('from', '')}"
        elif msg_type == "VERIFY_REQUEST":
            return f"verify_{msg.get('from', '')}_{time.time()}"
        elif msg_type in ["HELLO", "HELLO_ACK"]:
            return f"{msg_type}_{msg.get('host', '')}_{msg.get('port', '')}_{msg.get('name', '')}"
        else:
            return f"{msg_type}_{hashlib.md5(json.dumps(msg, sort_keys=True).encode()).hexdigest()}"

    def _is_duplicate_message(self, msg):
        """Check if message has been seen before"""
        msg_id = self._generate_message_id(msg)
        with self.seen_lock:
            now = time.time()
            if msg_id in self.seen_messages:
                last_seen = self.seen_messages[msg_id]
                if now - last_seen < self.message_ttl:
                    return True
            self.seen_messages[msg_id] = now
            return False

    def _seen_cleanup_loop(self):
        """Periodically clean up old message IDs"""
        while self.running:
            time.sleep(self.seen_cleanup_interval)
            with self.seen_lock:
                now = time.time()
                expired = [
                    msg_id for msg_id, timestamp in self.seen_messages.items()
                    if now - timestamp > self.message_ttl
                ]
                for msg_id in expired:
                    del self.seen_messages[msg_id]
                if expired:
                    print(f"[dedup] Cleaned {len(expired)} old message IDs")

    def _heartbeat_loop(self):
        while self.running:
            time.sleep(HEARTBEAT_INTERVAL)
            self.broadcast({"type": "PING", "name": self.name})
            enqueue_gui("clean_legend")

    def _verification_loop(self):
        """Automatically verify file integrity periodically"""
        while self.running:
            time.sleep(VERIFICATION_INTERVAL)
            try:
                self._auto_verify_files()
                # Also verify chain continuity and alert on breaks
                self._auto_verify_chain()
            except Exception as e:
                print(f"[verification] error: {e}")

    def _auto_verify_files(self):
        """Automatically verify all files and alert on tampering"""
        chain_copy = self.chain.get_chain_copy()
        file_txs = []
        for b in chain_copy:
            for tx in b.txs:
                if isinstance(tx, dict) and tx.get("kind") == "file":
                    file_txs.append((b.index, tx))
        if not file_txs:
            return
        for block_idx, tx in file_txs:
            fname = tx.get("filename")
            expected_hash = tx.get("file_hash")
            if not fname or not expected_hash:
                continue
            local_path = os.path.join(DOWNLOADS, fname)
            # Check if file exists
            if not os.path.exists(local_path):
                enqueue_gui("print", f"⚠️ Missing file detected: {fname}")
                # Request file from network
                self._request_file_from_network(fname, expected_hash)
                continue
            # Check file integrity
            try:
                with open(local_path, "rb") as f:
                    actual_hash = hashlib.sha256(f.read()).hexdigest()
                if actual_hash != expected_hash:
                    # TAMPERING DETECTED!
                    enqueue_gui("print", f"🚨 TAMPERING DETECTED: {fname}")
                    enqueue_gui("notify", "File Tampered!", f"{fname} has been modified")
                    # Broadcast tamper alert
                    alert_data = {
                        "filename": fname,
                        "expected_hash": expected_hash,
                        "actual_hash": actual_hash,
                        "block_index": block_idx,
                        "from": self.name,
                        "timestamp": time.time()
                    }
                    self.broadcast_tamper_alert(alert_data)
                    # Request network verification
                    self._request_network_file_verification(fname, expected_hash)
            except Exception as e:
                enqueue_gui("print", f"⚠️ Error checking {fname}: {e}")

    def _auto_verify_chain(self):
        """Automatically verify chain continuity and broadcast an alert on break."""
        chain_copy = self.chain.get_chain_copy()
        for i in range(1, len(chain_copy)):
            prev = chain_copy[i - 1]
            cur = chain_copy[i]
            try:
                prev_hash = prev.hash()
            except Exception:
                prev_hash = ""
            if cur.prev_hash != prev_hash or cur.index != prev.index + 1:
                alert_data = {
                    "filename": "BLOCKCHAIN",
                    "expected_hash": prev_hash,
                    "actual_hash": cur.prev_hash,
                    "block_index": i,
                    "from": self.name,
                    "timestamp": time.time()
                }
                self.broadcast_tamper_alert(alert_data)
                enqueue_gui("print", f"🚨 CHAIN TAMPER DETECTED at block {i}")
                enqueue_gui("notify", "Chain Tampered!", f"Break detected at block {i}")
                break

    def _request_file_from_network(self, fname, expected_hash):
        payload = {
            "type": "FILE_SYNC_REQUEST",
            "filename": fname,
            "expected_hash": expected_hash,
            "from": f"{self.host}:{self.port}"
        }
        self.broadcast(payload)
        enqueue_gui("print", f"📡 Requesting {fname} from network")

    def _request_network_file_verification(self, fname, expected_hash):
        file_info = {"filename": fname, "expected_hash": expected_hash}
        payload = {
            "type": "TAMPER_CHECK_REQUEST",
            "file_info": file_info,
            "from": f"{self.host}:{self.port}"
        }
        self.broadcast(payload)
        enqueue_gui("print", f"🔍 Requesting network verification for {fname}")

    def _hello_peers(self):
        payload = {
            "type": "HELLO",
            "host": self.host,
            "port": self.port,
            "name": self.name
        }
        with self.peers_lock:
            for (h, p) in list(self.peers):
                threading.Thread(target=send_json, args=(h, p, payload), daemon=True).start()

    def _request_chain(self, host, port):
        threading.Thread(
            target=send_json,
            args=(host, port, {"type": "REQUEST_CHAIN", "from": (self.host, self.port)}),
            daemon=True
        ).start()

    def _server_loop(self):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(8)
            sock.settimeout(1.0)
            while self.running:
                try:
                    conn, addr = sock.accept()
                    threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[server] accept error: {e}")
                    time.sleep(0.1)
        except Exception as e:
            if self.running:
                print(f"[server] fatal error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _handle_connection(self, conn, addr):
        try:
            conn.settimeout(RECV_TIMEOUT)
            data = b""
            while len(data) < MAX_MESSAGE_SIZE:
                try:
                    part = conn.recv(65536)
                    if not part:
                        break
                    data += part
                    if b"\n" in data:
                        break
                except socket.timeout:
                    break
            if len(data) >= MAX_MESSAGE_SIZE:
                print(f"[security] Message too large from {addr}")
                return
            for raw in data.splitlines():
                if not raw:
                    continue
                try:
                    msg = json.loads(raw.decode('utf-8', errors='ignore'))
                    peer_id = f"{addr[0]}:{addr[1]}"
                    if not self.rate_limiter.is_allowed(peer_id):
                        print(f"[security] Rate limit exceeded for {peer_id}")
                        continue
                    self._handle(msg, addr)
                except json.JSONDecodeError:
                    print(f"[error] Invalid JSON from {addr}")
                except Exception as e:
                    print(f"[error] Processing message: {e}")
        except Exception as e:
            print(f"[error] Connection handler: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle(self, msg, addr):
        if not isinstance(msg, dict):
            return

        # DEDUPLICATION CHECK
        if self._is_duplicate_message(msg):
            msg_type = msg.get("type", "unknown")
            print(f"[dedup] Dropped duplicate {msg_type} message from {addr}")
            return

        t = msg.get("type")

        if t == "HELLO":
            try:
                ph = msg.get("host", addr[0])
                pp = int(msg.get("port", addr[1]))
                pname = msg.get("name")
                with self.peers_lock:
                    self.peers.add((ph, pp))
                if pname:
                    ensure_peer_color(pname)
                ack = {"type": "HELLO_ACK", "host": self.host, "port": self.port, "name": self.name}
                threading.Thread(target=send_json, args=(ph, pp, ack), daemon=True).start()
                enqueue_gui("print", f"🤝 HELLO from {pname or ph+':'+str(pp)}")
            except Exception as e:
                print(f"[error] HELLO handler: {e}")

        elif t == "HELLO_ACK":
            try:
                ph = msg.get("host", addr[0])
                pp = int(msg.get("port", addr[1]))
                pname = msg.get("name")
                with self.peers_lock:
                    self.peers.add((ph, pp))
                if pname:
                    ensure_peer_color(pname)
                enqueue_gui("print", f"🤝 HELLO_ACK from {pname or ph+':'+str(pp)}")
            except Exception as e:
                print(f"[error] HELLO_ACK handler: {e}")

        elif t == "PING":
            name = msg.get("name")
            if name:
                ensure_peer_color(name)
            try:
                reply_payload = {"type": "ACK", "ping_id": msg.get("ping_id")}
                threading.Thread(
                    target=send_json,
                    args=(addr[0], msg.get("reply_port", self.port), reply_payload),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"[error] PING handler: {e}")

        elif t == "ACK":
            perf.end_latency(msg.get("ping_id"))

        elif t == "CHAT":
            tx = msg.get("tx")
            if tx and isinstance(tx, dict):
                sender = tx.get("sender")
                message = tx.get("msg", "")
                if sender and isinstance(message, str) and len(message) <= 10000:
                    ensure_peer_color(sender)
                    enqueue_gui("bubble", message, False, sender)
                    enqueue_gui("notify", "New chat", f"{sender}: {message[:50]}")

        elif t == "FILE_TRANSFER":
            try:
                data_b64 = msg.get("data_b64", "")
                if len(data_b64) > MAX_FILE_SIZE * 2:
                    enqueue_gui("print", "[security] File too large")
                    return
                data = base64.b64decode(data_b64)
                if len(data) > MAX_FILE_SIZE:
                    enqueue_gui("print", "[security] File exceeds size limit")
                    return
                fname = sanitize_filename(msg.get("filename", "file"))
                save_path = os.path.join(DOWNLOADS, fname)
                real_downloads = os.path.realpath(DOWNLOADS)
                real_save_path = os.path.realpath(save_path)
                if not real_save_path.startswith(real_downloads):
                    enqueue_gui("print", "[security] Path traversal attempt blocked")
                    return
                with open(save_path, "wb") as f:
                    f.write(data)
                fhash = hashlib.sha256(data).hexdigest()
                sender = msg.get("from")
                if sender:
                    ensure_peer_color(sender)
                enqueue_gui("bubble", f"📁 {fname} saved to Downloads", False, sender)
                enqueue_gui("notify", "File received", f"{fname} saved to Downloads")
                tx = {
                    "tx_id": msg.get("tx_id"),
                    "kind": "file",
                    "sender": sender,
                    "filename": fname,
                    "size": len(data),
                    "file_hash": fhash,
                    "sent_ts": time.time()
                }
                self.chain.append_tx_as_block(tx)
                ack_payload = {"type": "FILE_ACK", "tx_id": msg.get("tx_id")}
                threading.Thread(
                    target=send_json,
                    args=(addr[0], msg.get("reply_port", self.port), ack_payload),
                    daemon=True
                ).start()
            except Exception as e:
                enqueue_gui("print", f"[file error] {e}")

        elif t == "FILE_ACK":
            perf.end_throughput(msg.get("tx_id"))

        elif t == "BLOCK":
            blk = msg.get("block")
            if blk and isinstance(blk, dict):
                try:
                    required_fields = ["index", "prev_hash", "timestamp", "txs"]
                    if not all(field in blk for field in required_fields):
                        return
                    for tx in blk.get("txs", []):
                        if isinstance(tx, dict):
                            sname = tx.get("sender")
                            if sname:
                                ensure_peer_color(sname)
                    b = Block(
                        int(blk["index"]),
                        str(blk["prev_hash"]),
                        float(blk["timestamp"]),
                        blk["txs"],
                        int(blk.get("nonce", 0))
                    )
                    added = self.chain.add_block(b)
                    if added:
                        enqueue_gui("print", f"✅ Appended block {b.index}")
                        with self.peers_lock:
                            peers_copy = list(self.peers)
                        for (ph, pp) in peers_copy:
                            threading.Thread(
                                target=send_json,
                                args=(ph, pp, {"type": "BLOCK", "block": b.to_dict()}),
                                daemon=True
                            ).start()
                    else:
                        enqueue_gui("print", "⚠️ Block mismatch — requesting chain sync")
                        self._request_chain(addr[0], addr[1])
                except (ValueError, TypeError, KeyError) as e:
                    print(f"[error] Invalid block structure: {e}")

        elif t == "REQUEST_CHAIN":
            try:
                chain_copy = self.chain.get_chain_copy()
                chain_payload = {
                    "type": "RESPONSE_CHAIN",
                    "chain": [b.to_dict() for b in chain_copy]
                }
                threading.Thread(
                    target=send_json,
                    args=(addr[0], addr[1], chain_payload),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"[error] REQUEST_CHAIN handler: {e}")

        elif t == "RESPONSE_CHAIN":
            their_chain = msg.get("chain", [])
            if not isinstance(their_chain, list):
                return
            chain_blocks = []
            try:
                for b in their_chain:
                    if not isinstance(b, dict):
                        continue
                    chain_blocks.append(Block(
                        int(b["index"]),
                        str(b["prev_hash"]),
                        float(b["timestamp"]),
                        b["txs"],
                        int(b.get("nonce", 0))
                    ))
                if self.chain.replace_chain(chain_blocks):
                    enqueue_gui("print",
                        f"🔄 [SYNC] Replaced chain with longer peer chain (len={len(chain_blocks)})")
            except (ValueError, TypeError, KeyError) as e:
                print(f"[error] Invalid chain structure: {e}")

        elif t == "VERIFY_REQUEST":
            requester = msg.get("from")
            if not requester or not isinstance(requester, str):
                return
            result = self._local_verify_report()
            resp = {
                "type": "VERIFY_RESPONSE",
                "to": requester,
                "from": f"{self.host}:{self.port}",
                "result": result
            }
            try:
                ph, pp = requester.split(":")
                threading.Thread(
                    target=send_json,
                    args=(ph, int(pp), resp),
                    daemon=True
                ).start()
            except Exception:
                threading.Thread(
                    target=send_json,
                    args=(addr[0], addr[1], resp),
                    daemon=True
                ).start()

        elif t == "VERIFY_RESPONSE":
            enqueue_gui("verify_response", msg.get("from"), msg.get("result"))

        elif t == "TAMPER_ALERT":
            alert_data = msg.get("alert")
            if alert_data and isinstance(alert_data, dict):
                enqueue_gui("tamper_alert", alert_data)

        elif t == "TAMPER_CHECK_REQUEST":
            file_info = msg.get("file_info")
            requester = msg.get("from")
            if file_info and isinstance(file_info, dict):
                result = self._verify_specific_file(file_info)
                resp = {
                    "type": "TAMPER_CHECK_RESPONSE",
                    "from": f"{self.host}:{self.port}",
                    "file_info": file_info,
                    "result": result
                }
                try:
                    if requester:
                        req_host, req_port = requester.split(":")
                        threading.Thread(
                            target=send_json,
                            args=(req_host, int(req_port), resp),
                            daemon=True
                        ).start()
                    else:
                        threading.Thread(
                            target=send_json,
                            args=(addr[0], addr[1], resp),
                            daemon=True
                        ).start()
                except Exception as e:
                    print(f"[error] TAMPER_CHECK_REQUEST response: {e}")

        elif t == "TAMPER_CHECK_RESPONSE":
            enqueue_gui("tamper_check_response",
                        msg.get("from"),
                        msg.get("file_info"),
                        msg.get("result"))

        elif t == "FILE_SYNC_REQUEST":
            fname = msg.get("filename")
            expected_hash = msg.get("expected_hash")
            requester = msg.get("from")
            if fname and requester:
                self._send_file_to_peer(fname, expected_hash, requester)

        elif t == "FILE_SYNC_RESPONSE":
            try:
                data_b64 = msg.get("data_b64", "")
                if len(data_b64) > MAX_FILE_SIZE * 2:
                    enqueue_gui("print", "[security] Sync file too large")
                    return
                data = base64.b64decode(data_b64)
                if len(data) > MAX_FILE_SIZE:
                    enqueue_gui("print", "[security] Sync file exceeds size limit")
                    return
                fname = sanitize_filename(msg.get("filename", "file"))
                expected_hash = msg.get("expected_hash")
                save_path = os.path.join(DOWNLOADS, fname)
                real_downloads = os.path.realpath(DOWNLOADS)
                real_save_path = os.path.realpath(save_path)
                if not real_save_path.startswith(real_downloads):
                    enqueue_gui("print", "[security] Path traversal attempt blocked")
                    return
                actual_hash = hashlib.sha256(data).hexdigest()
                if expected_hash and actual_hash != expected_hash:
                    enqueue_gui("print", f"[sync] Hash mismatch for {fname}, discarding")
                    return
                with open(save_path, "wb") as f:
                    f.write(data)
                enqueue_gui("print", f"✅ [SYNC] Restored file: {fname}")
                enqueue_gui("notify", "File Synchronized", f"{fname} restored from peer")
            except Exception as e:
                enqueue_gui("print", f"[sync error] {e}")

    def _sync_loop(self):
        backoff = 1.0
        max_backoff = 60.0
        while self.running:
            time.sleep(backoff)
            with self.pending_lock:
                if not self.pending:
                    backoff = min(backoff * 1.5, max_backoff)
                    continue
                sent_any = False
                for _ in range(min(10, len(self.pending))):
                    if not self.pending:
                        break
                    payload = self.pending.popleft()
                    ok_any = False
                    with self.peers_lock:
                        peers_copy = list(self.peers)
                    for (h, p) in peers_copy:
                        if send_json(h, p, payload):
                            ok_any = True
                    if not ok_any:
                        self.pending.append(payload)
                    else:
                        sent_any = True
                if sent_any:
                    backoff = max(1.0, backoff * 0.5)
                else:
                    backoff = min(backoff * 2.0, max_backoff)

    def _cleanup_loop(self):
        while self.running:
            time.sleep(120)
            try:
                self.rate_limiter.cleanup_old_peers()
            except Exception as e:
                print(f"[cleanup] error: {e}")

    def _local_verify_report(self):
        issues = []
        chain_copy = self.chain.get_chain_copy()
        for i in range(1, len(chain_copy)):
            prev = chain_copy[i - 1]
            cur = chain_copy[i]
            try:
                prev_hash = prev.hash()
            except Exception:
                prev_hash = ""
            if cur.prev_hash != prev_hash:
                issues.append(f"chain_broken_at_{i}")
        for b in chain_copy:
            for tx in b.txs:
                if not isinstance(tx, dict):
                    continue
                if tx.get("kind") == "file":
                    fname = tx.get("filename")
                    expected = tx.get("file_hash")
                    if not fname:
                        continue
                    local_path = os.path.join(DOWNLOADS, fname)
                    if not os.path.exists(local_path):
                        issues.append(f"missing_file:{fname}:block{b.index}")
                    else:
                        try:
                            with open(local_path, "rb") as f:
                                h = hashlib.sha256(f.read()).hexdigest()
                            if expected and h != expected:
                                issues.append(f"tampered_file:{fname}:block{b.index}")
                        except Exception:
                            issues.append(f"err_read:{fname}:block{b.index}")
        return {"ok": len(issues) == 0, "issues": issues}

    def _verify_specific_file(self, file_info):
        fname = file_info.get("filename")
        expected_hash = file_info.get("expected_hash")
        if not fname or not expected_hash:
            return {"status": "error", "message": "Missing file info"}
        local_path = os.path.join(DOWNLOADS, fname)
        if not os.path.exists(local_path):
            return {"status": "missing", "message": f"File not found: {fname}"}
        try:
            with open(local_path, "rb") as f:
                actual_hash = hashlib.sha256(f.read()).hexdigest()
            if actual_hash == expected_hash:
                return {"status": "valid", "hash": actual_hash}
            else:
                return {"status": "tampered", "expected": expected_hash, "actual": actual_hash}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _send_file_to_peer(self, fname, expected_hash, requester):
        try:
            local_path = os.path.join(DOWNLOADS, fname)
            if not os.path.exists(local_path):
                enqueue_gui("print", f"[sync] Cannot send {fname}, file not found")
                return
            with open(local_path, "rb") as f:
                data = f.read()
            if len(data) > MAX_FILE_SIZE:
                enqueue_gui("print", f"[sync] File {fname} too large to send")
                return
            file_hash = hashlib.sha256(data).hexdigest()
            if expected_hash and file_hash != expected_hash:
                enqueue_gui("print", f"[sync] Our copy of {fname} is also tampered, cannot send")
                return
            payload = {
                "type": "FILE_SYNC_RESPONSE",
                "from": f"{self.host}:{self.port}",
                "filename": fname,
                "data_b64": base64.b64encode(data).decode(),
                "expected_hash": file_hash
            }
            try:
                req_host, req_port = requester.split(":")
                threading.Thread(
                    target=send_json,
                    args=(req_host, int(req_port), payload),
                    daemon=True
                ).start()
                enqueue_gui("print", f"📤 [SYNC] Sent {fname} to {requester}")
            except Exception as e:
                enqueue_gui("print", f"[sync] Failed to send to {requester}: {e}")
        except Exception as e:
            enqueue_gui("print", f"[sync] Error sending file: {e}")

    def broadcast(self, payload):
        with self.peers_lock:
            peers_copy = list(self.peers)
        failed_peers = []
        threads = []

        def send_with_tracking(host, port, data):
            if not send_json(host, port, data):
                failed_peers.append((host, port))

        for (h, p) in peers_copy:
            t = threading.Thread(target=send_with_tracking, args=(h, p, payload), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=CONNECT_TIMEOUT)
        if failed_peers:
            with self.pending_lock:
                if len(self.pending) < MAX_PENDING_MESSAGES:
                    self.pending.append(payload)

    def broadcast_tamper_alert(self, alert_data):
        payload = {"type": "TAMPER_ALERT", "alert": alert_data, "from": self.name}
        self.broadcast(payload)

    def send_chat(self, text):
        if not text or len(text) > 10000:
            enqueue_gui("print", "[error] Message too long or empty")
            return
        tx = {
            "tx_id": hashlib.sha256(f"{text}{time.time()}".encode()).hexdigest(),
            "kind": "chat",
            "sender": self.name,
            "msg": text,
            "sent_ts": time.time()
        }
        b = self.chain.append_tx_as_block(tx)
        self.broadcast({"type": "BLOCK", "from": self.name, "block": b.to_dict()})
        self.broadcast({"type": "CHAT", "tx": tx})
        ensure_peer_color(self.name)
        enqueue_gui("bubble", text, True, self.name)
        ping_id = str(uuid.uuid4())
        perf.start_latency(ping_id)
        self.broadcast({"type": "PING", "ping_id": ping_id, "reply_port": self.port})

    def send_file(self, path):
        if not os.path.exists(path):
            enqueue_gui("print", "File not found")
            return
        try:
            file_size = os.path.getsize(path)
            if file_size > MAX_FILE_SIZE:
                enqueue_gui("print", f"File too large (max {MAX_FILE_SIZE/1024/1024:.0f}MB)")
                return
            with open(path, "rb") as f:
                data = f.read()
            fname = sanitize_filename(os.path.basename(path))
            fhash = hashlib.sha256(data).hexdigest()
            tx_id = hashlib.sha256(f"{fname}{time.time()}".encode()).hexdigest()
            tx = {
                "tx_id": tx_id,
                "kind": "file",
                "sender": self.name,
                "filename": fname,
                "size": len(data),
                "file_hash": fhash,
                "sent_ts": time.time()
            }
            b = self.chain.append_tx_as_block(tx)
            self.broadcast({"type": "BLOCK", "from": self.name, "block": b.to_dict()})
            payload = {
                "type": "FILE_TRANSFER",
                "from": self.name,
                "tx_id": tx_id,
                "filename": fname,
                "data_b64": base64.b64encode(data).decode(),
                "reply_port": self.port
            }
            perf.start_throughput(tx_id, len(data))
            self.broadcast(payload)
            ensure_peer_color(self.name)
            enqueue_gui("bubble", f"📤 Sent file: {fname}", True, self.name)
        except Exception as e:
            enqueue_gui("print", f"[error] Failed to send file: {e}")

    def verify_network(self):
        results = {}
        local = self._local_verify_report()
        results[f"{self.host}:{self.port}"] = local
        with self.peers_lock:
            peers_copy = list(self.peers)
        for (h, p) in peers_copy:
            try:
                threading.Thread(
                    target=send_json,
                    args=(h, p, {"type": "VERIFY_REQUEST", "from": f"{self.host}:{self.port}"}),
                    daemon=True
                ).start()
            except Exception:
                pass
        return results

    def shutdown(self):
        self.running = False

# ==================== GUI Application ====================
class App:
    """Main GUI Application"""

    def __init__(self):
        load_peer_colors()
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.root = ctk.CTk()
        self.root.title("🔗 LAN Blockchain Chat — Multi-Node Network")
        self.root.geometry("1200x900")
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Header
        header = ctk.CTkFrame(self.root, height=60, fg_color=("#1f538d", "#14375e"), corner_radius=0)
        header.pack(fill="x", padx=0, pady=0)
        header.pack_propagate(False)

        title = ctk.CTkLabel(
            header,
            text="🔗 Blockchain P2P Network",
            font=("Arial", 22, "bold"),
            text_color="white"
        )
        title.pack(side="left", padx=20, pady=15)

        self.status_label = ctk.CTkLabel(
            header,
            text="⚪ Disconnected",
            font=("Arial", 13, "bold"),
            text_color="#ffb366"
        )
        self.status_label.pack(side="right", padx=20, pady=15)

        # Main container
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=20, pady=15)

        # Chat container
        chat_container = ctk.CTkFrame(main_container, fg_color=("#2b2b2b", "#1a1a1a"), corner_radius=12)
        chat_container.pack(fill="both", expand=True, pady=(0, 12))

        chat_header = ctk.CTkFrame(chat_container, fg_color="transparent", height=35)
        chat_header.pack(fill="x", padx=15, pady=(10, 5))
        chat_header.pack_propagate(False)

        ctk.CTkLabel(chat_header, text="💬 Messages", font=("Arial", 14, "bold"), anchor="w").pack(side="left")

        self.scroll_btn = ctk.CTkButton(
            chat_header,
            text="⬇ Scroll to Bottom",
            width=130,
            height=28,
            font=("Arial", 11),
            fg_color="transparent",
            hover_color=("#3b3b3b", "#2b2b2b"),
            border_width=1,
            border_color=("#4a4a4a", "#3a3a3a"),
            command=self._scroll_to_bottom
        )
        self.scroll_btn.pack(side="right")

        # Scrollable frame (fixed)
        self.chat_scroll_frame = ctk.CTkScrollableFrame(
            chat_container,
            fg_color="transparent",
            scrollbar_button_color=("#3b3b3b", "#2b2b2b"),
            scrollbar_button_hover_color=("#4a4a4a", "#3a3a3a")
        )
        self.chat_scroll_frame.pack(fill="both", expand=True, padx=15, pady=(5, 15))

        # Input area
        input_container = ctk.CTkFrame(main_container, fg_color="transparent")
        input_container.pack(fill="x", pady=(0, 10))

        input_frame = ctk.CTkFrame(input_container, fg_color=("#2b2b2b", "#1a1a1a"), corner_radius=12)
        input_frame.pack(fill="x", pady=5)

        self.entry = ctk.CTkEntry(
            input_frame,
            width=750,
            height=40,
            placeholder_text="Type your message here...",
            font=("Arial", 13),
            border_width=0,
            corner_radius=8
        )
        self.entry.pack(side="left", padx=15, pady=12)
        self.entry.bind("<Return>", lambda e: self._send_chat())

        btn_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        btn_frame.pack(side="left", padx=(0, 15), pady=12)

        ctk.CTkButton(
            btn_frame,
            text="📤 Send",
            width=100,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color=("#1f538d", "#14375e"),
            hover_color=("#2a6bb0", "#1a4a7a"),
            corner_radius=8,
            command=self._send_chat
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_frame,
            text="📎 File",
            width=90,
            height=40,
            font=("Arial", 12),
            fg_color=("#5a5a5a", "#3a3a3a"),
            hover_color=("#6a6a6a", "#4a4a4a"),
            corner_radius=8,
            command=self._send_file
        ).pack(side="left", padx=3)

        # Control panel
        controls = ctk.CTkFrame(main_container, fg_color=("#2b2b2b", "#1a1a1a"), corner_radius=12)
        controls.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(controls, text="🛠 Tools", font=("Arial", 13, "bold"), anchor="w").pack(side="left", padx=15, pady=12)

        btn_container = ctk.CTkFrame(controls, fg_color="transparent")
        btn_container.pack(side="left", padx=(10, 15), pady=10)

        ctk.CTkButton(
            btn_container,
            text="📊 Performance",
            width=125,
            height=35,
            font=("Arial", 11),
            fg_color=("#2a6bb0", "#1a4a7a"),
            hover_color=("#3a7bc0", "#2a5a8a"),
            corner_radius=8,
            command=self._show_graph
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_container,
            text="🔗 Explorer",
            width=125,
            height=35,
            font=("Arial", 11),
            fg_color=("#2a6bb0", "#1a4a7a"),
            hover_color=("#3a7bc0", "#2a5a8a"),
            corner_radius=8,
            command=self._show_blockchain_navigator
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_container,
            text="🔍 Verify Network",
            width=125,
            height=35,
            font=("Arial", 11),
            fg_color=("#6a4c93", "#5a3c83"),
            hover_color=("#7a5ca3", "#6a4c93"),
            corner_radius=8,
            command=self._verify_network
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_container,
            text="🛠 Fix Files",
            width=115,
            height=35,
            font=("Arial", 11),
            fg_color=("#c45f47", "#a44a37"),
            hover_color=("#d46f57", "#b45a47"),
            corner_radius=8,
            command=self._check_files_intuitive
        ).pack(side="left", padx=3)

        # Metrics cards
        metrics = ctk.CTkFrame(main_container, fg_color="transparent")
        metrics.pack(fill="x", pady=(0, 5))

        metric_style = {"corner_radius": 10, "height": 70, "fg_color": ("#2b2b2b", "#1a1a1a")}

        lat_card = ctk.CTkFrame(metrics, **metric_style)
        lat_card.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkLabel(lat_card, text="📶 LATENCY", font=("Arial", 10), text_color="#888").pack(pady=(8, 2))
        self.lat_label = ctk.CTkLabel(lat_card, text="0 ms", font=("Arial", 18, "bold"))
        self.lat_label.pack(pady=(0, 8))

        thr_card = ctk.CTkFrame(metrics, **metric_style)
        thr_card.pack(side="left", fill="x", expand=True, padx=4)
        ctk.CTkLabel(thr_card, text="🚀 THROUGHPUT", font=("Arial", 10), text_color="#888").pack(pady=(8, 2))
        self.thr_label = ctk.CTkLabel(thr_card, text="0 KB/s", font=("Arial", 18, "bold"))
        self.thr_label.pack(pady=(0, 8))

        loss_card = ctk.CTkFrame(metrics, **metric_style)
        loss_card.pack(side="left", fill="x", expand=True, padx=(8, 0))
        ctk.CTkLabel(loss_card, text="📉 PACKET LOSS", font=("Arial", 10), text_color="#888").pack(pady=(8, 2))
        self.loss_label = ctk.CTkLabel(loss_card, text="0%", font=("Arial", 18, "bold"))
        self.loss_label.pack(pady=(0, 8))

        # Active peers legend
        legend_frame = ctk.CTkFrame(main_container, fg_color=("#2b2b2b", "#1a1a1a"), corner_radius=10, height=85)
        legend_frame.pack(fill="x", pady=(5, 0))
        legend_frame.pack_propagate(False)

        legend_header = ctk.CTkFrame(legend_frame, fg_color="transparent", height=30)
        legend_header.pack(fill="x", padx=15, pady=(8, 2))
        legend_header.pack_propagate(False)

        ctk.CTkLabel(legend_header, text="👥 Active Peers", font=("Arial", 12, "bold"), anchor="w").pack(side="left")

        self.legend_scroll_frame = ctk.CTkScrollableFrame(
            legend_frame,
            orientation="horizontal",
            height=40,
            fg_color="transparent"
        )
        self.legend_scroll_frame.pack(fill="x", padx=10, pady=(0, 8))

        self.node = None
        self.verify_results = {}
        self.tamper_check_results = {}
        self.animation = None

        # Track highlighted blocks and explorer refs
        self.alert_blocks = set()
        self._explorer = None

        self.root.after(80, self._process_gui_queue)
        self.root.after(200, self._show_start_dialog)  # <-- now exists

    def _scroll_to_bottom(self):
        """Scroll chat to bottom - FIXED VERSION"""
        try:
            self.chat_scroll_frame.update_idletasks()
            self.chat_scroll_frame._parent_canvas.yview_moveto(1.0)
        except Exception as e:
            print(f"[scroll] error: {e}")

    def _clean_legend(self):
        with lock:
            now = time.time()
            dead = [n for n, t in active_peers.items() if now - t > PEER_TIMEOUT]
            for n in dead:
                active_peers.pop(n, None)
        enqueue_gui("update_legend")

    def _render_legend(self):
        try:
            for widget in self.legend_scroll_frame.winfo_children():
                widget.destroy()
            with lock:
                live = sorted(active_peers.items(), key=lambda x: x[1], reverse=True)
            if not live:
                no_peers_label = ctk.CTkLabel(
                    self.legend_scroll_frame,
                    text="No active peers - connect to other nodes to see them here",
                    font=("Arial", 11, "italic"),
                    text_color="#666"
                )
                no_peers_label.pack(side="left", padx=10, pady=8)
                return
            for name, _ in live:
                color = peer_colors.get(name, "#888")
                peer_frame = ctk.CTkFrame(
                    self.legend_scroll_frame,
                    fg_color=color,
                    corner_radius=15,
                    height=32,
                    width=140
                )
                peer_frame.pack(side="left", padx=5, pady=4)
                peer_frame.pack_propagate(False)
                short_name = name[:16] + "..." if len(name) > 16 else name
                peer_label = ctk.CTkLabel(
                    peer_frame,
                    text=short_name,
                    font=("Arial", 10, "bold"),
                    text_color="white",
                    wraplength=120
                )
                peer_label.pack(expand=True, fill="both", padx=10, pady=6)
        except Exception as e:
            print(f"[legend] render error: {e}")

    def _draw_explorer(self):
        """(Re)draw the explorer graph with highlighted blocks (tamper alerts in red)."""
        if not self.node or not self._explorer:
            return
        fig = self._explorer["fig"]
        ax = self._explorer["ax"]
        canvas = self._explorer["canvas"]
        chain = self.node.chain.get_chain_copy()
        self._explorer["chain"] = chain
        ax.clear()
        G = nx.DiGraph()
        pos = {}
        for i in range(len(chain)):
            G.add_node(i)
            pos[i] = (i * 170, 0)
            if i > 0:
                G.add_edge(i - 1, i)
        node_colors = [ALERT_COLOR if i in self.alert_blocks else "#2a9d8f" for i in range(len(chain))]
        nx.draw(
            G, pos,
            with_labels=True,
            node_color=node_colors,
            node_size=2300,
            font_color="white",
            font_weight="bold",
            ax=ax,
            arrows=True
        )
        ax.set_title("Blockchain Structure (Click blocks to inspect)", fontsize=14, color="white")
        fig.patch.set_facecolor('#1a1a1a')
        ax.set_facecolor('#1a1a1a')
        canvas.draw()

    def _check_files_intuitive(self):
        """Check file integrity and offer sync options"""
        if not self.node:
            messagebox.showwarning("Not Connected", "Start a node first!")
            return
        win = ctk.CTkToplevel(self.root)
        win.title("File Health & Sync")
        win.geometry("880x680")
        txt = ctk.CTkTextbox(win, font=("Consolas", 11))
        txt.pack(fill="both", expand=True, padx=15, pady=15)

        # Collect (block_index, tx) pairs
        files = [(b.index, tx) for b in self.node.chain.get_chain_copy() for tx in b.txs if tx.get("kind") == "file"]
        txt.insert("end", f"Scanning {len(files)} file(s)...\n\n")

        ok = tampered = missing = 0
        for block_idx, f in files:
            path = os.path.join(DOWNLOADS, f["filename"])
            if not os.path.exists(path):
                txt.insert("end", f"❌ MISSING: {f['filename']}\n")
                missing += 1
                self.alert_blocks.add(block_idx)
                continue
            try:
                with open(path, "rb") as file:
                    h = hashlib.sha256(file.read()).hexdigest()
                if h == f["file_hash"]:
                    txt.insert("end", f"✅ OK: {f['filename']}\n")
                    ok += 1
                else:
                    txt.insert("end", f"⚠️ TAMPERED: {f['filename']}\n")
                    tampered += 1
                    self.alert_blocks.add(block_idx)
            except Exception as e:
                txt.insert("end", f"❌ ERROR: {f['filename']} ({e})\n")
                missing += 1
                self.alert_blocks.add(block_idx)

        txt.insert("end", f"\n{'='*70}\n")
        txt.insert("end", f"SUMMARY: {ok} OK | {tampered} TAMPERED | {missing} MISSING\n")

        # Redraw explorer if it's open to reflect highlights
        if self._explorer:
            self._draw_explorer()

        def fix_all():
            btn.configure(state="disabled", text="Syncing...")
            for block_idx, f in files:
                path = os.path.join(DOWNLOADS, f["filename"])
                try:
                    if not os.path.exists(path):
                        needs_sync = True
                    else:
                        with open(path, "rb") as file:
                            h = hashlib.sha256(file.read()).hexdigest()
                        needs_sync = (h != f["file_hash"])
                    if needs_sync:
                        self.node.broadcast({
                            "type": "FILE_SYNC_REQUEST",
                            "filename": f["filename"],
                            "expected_hash": f["file_hash"],
                            "from": f"{self.node.host}:{self.node.port}"
                        })
                except Exception:
                    pass
            txt.insert("end", "\n✅ Sync requests sent to all peers!\n")
            txt.insert("end", "Waiting for responses...\n")

        btn = ctk.CTkButton(win, text="🔧 Fix All Problems", fg_color=ALERT_COLOR, command=fix_all)
        if tampered + missing > 0:
            btn.pack(pady=12)

    def _verify_network(self):
        """Initiate network-wide verification and display results"""
        if not self.node:
            messagebox.showwarning("Not Connected", "Start a node first!")
            return
        win = ctk.CTkToplevel(self.root)
        win.title("Network Verification")
        win.geometry("800x600")
        txt = ctk.CTkTextbox(win, font=("Consolas", 11))
        txt.pack(fill="both", expand=True, padx=15, pady=15)
        txt.insert("end", "🔍 Starting network-wide verification...\n\n")

        local_result = self.node._local_verify_report()
        txt.insert("end", f"LOCAL NODE ({self.node.name}):\n")
        if local_result["ok"]:
            txt.insert("end", "  ✅ All checks passed\n")
        else:
            txt.insert("end", f"  ⚠️ Found {len(local_result['issues'])} issue(s):\n")
            for issue in local_result["issues"]:
                txt.insert("end", f"    • {issue}\n")
        txt.insert("end", "\n" + "="*70 + "\n")
        txt.insert("end", "Requesting verification from peers...\n\n")
        self.node.verify_network()

    def _show_blockchain_navigator(self):
        """Display blockchain structure with interactive viewer"""
        if not self.node:
            messagebox.showwarning("No Chain", "Start a node first!")
            return

        win = ctk.CTkToplevel(self.root)
        win.title("Blockchain Navigator")
        win.geometry("1150x720")

        fig, ax = plt.subplots(figsize=(11, 6))
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.get_tk_widget().pack(fill="both", expand=True)

        # Remember explorer refs so other callbacks can trigger redraws
        self._explorer = {"win": win, "fig": fig, "ax": ax, "canvas": canvas, "chain": []}

        def on_click(event):
            chain = self._explorer.get("chain", [])
            if not chain or event.xdata is None:
                return
            idx = round(event.xdata / 170)
            if 0 <= idx < len(chain):
                b = chain[idx]
                det = ctk.CTkToplevel(win)
                det.title(f"Block {idx} Details")
                det.geometry("700x500")
                t = ctk.CTkTextbox(det, font=("Consolas", 11))
                t.pack(fill="both", expand=True, padx=12, pady=12)
                t.insert("end", f"{'='*60}\n")
                t.insert("end", f"BLOCK #{idx}\n")
                t.insert("end", f"{'='*60}\n\n")
                t.insert("end", f"Hash: {b.hash()}\n")
                t.insert("end", f"Prev: {b.prev_hash}\n")
                t.insert("end", f"Time: {datetime.fromtimestamp(b.timestamp).strftime('%Y-%m-%d %H:%M:%S')}\n")
                t.insert("end", f"Nonce: {b.nonce}\n\n")
                t.insert("end", f"{'='*60}\n")
                t.insert("end", f"TRANSACTIONS ({len(b.txs)})\n")
                t.insert("end", f"{'='*60}\n\n")
                for i, tx in enumerate(b.txs, 1):
                    t.insert("end", f"TX {i}:\n")
                    if tx.get("kind") == "file":
                        t.insert("end", f"  Type: FILE TRANSFER\n")
                        t.insert("end", f"  File: {tx['filename']}\n")
                        t.insert("end", f"  Size: {tx.get('size', 0)} bytes\n")
                        t.insert("end", f"  Hash: {tx.get('file_hash', 'N/A')[:32]}...\n")
                        t.insert("end", f"  From: {tx.get('sender', 'Unknown')}\n")
                    elif tx.get("kind") == "chat":
                        t.insert("end", f"  Type: CHAT MESSAGE\n")
                        t.insert("end", f"  From: {tx.get('sender', 'Unknown')}\n")
                        t.insert("end", f"  Text: {tx.get('msg', '')}\n")
                    else:
                        t.insert("end", f"  Type: {tx.get('type', 'UNKNOWN')}\n")
                        t.insert("end", f"  Data: {json.dumps(tx, indent=2)}\n")
                    t.insert("end", "\n")

        canvas.mpl_connect("button_press_event", on_click)

        # Initial draw + periodic refresh
        self._draw_explorer()

        def refresh():
            self._draw_explorer()
            win.after(3000, refresh)

        win.after(3000, refresh)

    def _show_start_dialog(self):
        """Display node configuration dialog (restored)."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("🚀 Start Your Node")
        dialog.geometry("500x550")
        dialog.transient(self.root)
        dialog.grab_set()

        # Header
        header = ctk.CTkFrame(dialog, fg_color=("#1f538d", "#14375e"), corner_radius=0, height=80)
        header.pack(fill="x", pady=0)
        header.pack_propagate(False)
        ctk.CTkLabel(
            header,
            text="🔗 Configure Your Node",
            font=("Arial", 22, "bold"),
            text_color="white"
        ).pack(pady=25)

        # Content
        content = ctk.CTkFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        # Node Name
        ctk.CTkLabel(content, text="Node Name", font=("Arial", 12, "bold"), anchor="w").pack(fill="x", pady=(10, 5))
        name_entry = ctk.CTkEntry(content, width=440, height=40, placeholder_text="e.g., Alice's Node",
                                  font=("Arial", 12), corner_radius=8, border_width=2)
        name_entry.pack(pady=(0, 15))

        # Port
        ctk.CTkLabel(content, text="Your Port", font=("Arial", 12, "bold"), anchor="w").pack(fill="x", pady=(5, 5))
        port_entry = ctk.CTkEntry(content, width=440, height=40, placeholder_text="1024 - 65535",
                                  font=("Arial", 12), corner_radius=8, border_width=2)
        port_entry.pack(pady=(0, 15))
        port_entry.insert(0, "5001")

        # Peers
        ctk.CTkLabel(content, text="Connect to Peers (Optional)", font=("Arial", 12, "bold"),
                     anchor="w").pack(fill="x", pady=(5, 5))
        peer_entry = ctk.CTkTextbox(content, width=440, height=80, font=("Arial", 12), corner_radius=8, border_width=2)
        peer_entry.pack(pady=(0, 5))
        peer_entry.insert("1.0",
                          "# Enter peer addresses (one per line or comma-separated)\n"
                          "# Examples:\n# 192.168.1.100:5001\n# localhost:5001, localhost:5002\n")
        ctk.CTkLabel(
            content,
            text="💡 Leave empty to start as first node | Enter multiple peers to join network",
            font=("Arial", 10, "italic"),
            text_color="#888",
            anchor="w"
        ).pack(fill="x", pady=(0, 20))

        def start_node():
            port_str = port_entry.get().strip()
            peer_text = peer_entry.get("1.0", "end").strip()
            name = name_entry.get().strip() or None

            try:
                port = int(port_str)
                if port < 1024 or port > 65535:
                    raise ValueError("Port must be between 1024-65535")
            except ValueError as e:
                messagebox.showerror("Invalid Port", str(e))
                return

            peers = []
            if peer_text:
                lines = [line.strip() for line in peer_text.split('\n')
                         if line.strip() and not line.strip().startswith('#')]
                for line in lines:
                    for peer_addr in [p.strip() for p in line.split(',') if p.strip()]:
                        try:
                            if ':' in peer_addr:
                                host, pport = peer_addr.split(':', 1)
                                peers.append((host.strip(), int(pport.strip())))
                            else:
                                messagebox.showerror("Invalid Peer", f"Invalid format: {peer_addr}\nExpected: host:port")
                                return
                        except ValueError:
                            messagebox.showerror("Invalid Peer", f"Invalid port in: {peer_addr}\nPort must be a number")
                            return
                peers = list(dict.fromkeys(peers))  # dedupe, preserve order

            try:
                self.node = Node("0.0.0.0", port, peers, name)
                self.status_label.configure(text=f"🟢 {self.node.name}", text_color="#99ff99")
                dialog.destroy()

                peer_count = len(peers)
                if peer_count == 0:
                    enqueue_gui("print", f"✅ Node started successfully on port {port} (First node)")
                elif peer_count == 1:
                    enqueue_gui("print", f"✅ Node started on port {port}, connecting to 1 peer")
                else:
                    enqueue_gui("print", f"✅ Node started on port {port}, connecting to {peer_count} peers")
                enqueue_gui("print", f"🔍 Automatic file verification enabled (every {VERIFICATION_INTERVAL}s)")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start node:\n{e}")

        ctk.CTkButton(
            content,
            text="🚀 Start Node",
            command=start_node,
            fg_color=("#1f538d", "#14375e"),
            hover_color=("#2a6bb0", "#1a4a7a"),
            height=45,
            font=("Arial", 14, "bold"),
            corner_radius=10
        ).pack(fill="x", pady=(10, 0))

    def _on_closing(self):
        if self.node:
            self.node.shutdown()
        if self.animation:
            try:
                self.animation.event_source.stop()
            except Exception:
                pass
        plt.close('all')
        self.root.destroy()

    def _send_chat(self):
        if not self.node:
            messagebox.showwarning("Not Connected", "Start a node first!")
            return
        text = self.entry.get().strip()
        if text:
            self.node.send_chat(text)
            self.entry.delete(0, "end")

    def _send_file(self):
        if not self.node:
            messagebox.showwarning("Not Connected", "Start a node first!")
            return
        path = filedialog.askopenfilename(title="Select File to Send")
        if path:
            threading.Thread(target=self.node.send_file, args=(path,), daemon=True).start()

    def _print_console(self, msg):
        frame = ctk.CTkFrame(
            self.chat_scroll_frame,
            fg_color=("#e9c46a", "#d4af37"),
            corner_radius=10,
            border_width=1,
            border_color=("#d4af37", "#b8941f")
        )
        frame.pack(fill="x", pady=4, padx=8)
        icon = "ℹ️"
        if "✅" in msg or "OK" in msg or "success" in msg.lower():
            icon = "✅"
        elif "⚠️" in msg or "warning" in msg.lower() or "mismatch" in msg.lower():
            icon = "⚠️"
        elif "❌" in msg or "error" in msg.lower() or "failed" in msg.lower():
            icon = "❌"
        elif "🔄" in msg or "SYNC" in msg:
            icon = "🔄"
        elif "🚨" in msg or "TAMPER" in msg or "ALERT" in msg:
            icon = "🚨"
        elif "🔍" in msg or "verify" in msg.lower() or "check" in msg.lower():
            icon = "🔍"
        label = ctk.CTkLabel(
            frame,
            text=f"{icon}  {msg}",
            anchor="w",
            font=("Arial", 11),
            text_color="#1a1a1a",
            wraplength=1050,
            justify="left"
        )
        label.pack(pady=7, padx=12, fill="x")
        self.root.after(50, self._scroll_to_bottom)

    def _add_bubble(self, text, is_self, sender_name):
        bubble_color = peer_colors.get(sender_name, SELF_COLOR if is_self else "#555")
        frame = ctk.CTkFrame(self.chat_scroll_frame, fg_color="transparent")
        frame.pack(fill="x", pady=5, padx=10)
        bubble = ctk.CTkFrame(frame, fg_color=bubble_color, corner_radius=15, border_width=0)
        if is_self:
            bubble.pack(side="right", padx=8, pady=2)
            anchor_style = "e"
        else:
            bubble.pack(side="left", padx=8, pady=2)
            anchor_style = "w"
        if not is_self and sender_name:
            header_frame = ctk.CTkFrame(bubble, fg_color="transparent")
            header_frame.pack(anchor="w", fill="x", padx=14, pady=(10, 2))
            ctk.CTkLabel(header_frame, text=f"@{sender_name}", font=("Arial", 10, "bold"), text_color="white").pack(side="left")
            ctk.CTkLabel(header_frame, text=datetime.now().strftime("%H:%M"), font=("Arial", 9), text_color="#cccccc").pack(side="right", padx=(10, 0))
        ctk.CTkLabel(bubble, text=text, anchor="w", font=("Arial", 12), text_color="white", wraplength=650, justify="left").pack(padx=14, pady=(2 if not is_self else 10, 10), anchor=anchor_style)
        if is_self:
            ctk.CTkLabel(bubble, text=datetime.now().strftime("%H:%M"), font=("Arial", 9), text_color="#cccccc").pack(anchor="e", padx=14, pady=(0, 8))
        self.root.after(50, self._scroll_to_bottom)

    def _update_metrics(self):
        lat = perf.avg_latency() * 1000.0
        thr = perf.avg_throughput() / 1024.0
        loss = perf.packet_loss_rate()
        lat_color = "#66b3ff" if lat < 100 else ("#ffb366" if lat < 500 else "#ff6b6b")
        thr_color = "#99ff99" if thr > 100 else ("#ffb366" if thr > 10 else "#ff6b6b")
        loss_color = "#99ff99" if loss < 5 else ("#ffb366" if loss < 15 else "#ff6b6b")
        self.lat_label.configure(text=f"{lat:.1f} ms", text_color=lat_color)
        self.thr_label.configure(text=f"{thr:.1f} KB/s", text_color=thr_color)
        self.loss_label.configure(text=f"{loss:.2f}%", text_color=loss_color)

    def _show_graph(self):
        if not self.node:
            messagebox.showwarning("Not Connected", "Start a node first!")
            return
        graph_win = ctk.CTkToplevel(self.root)
        graph_win.title("📊 Live Performance Metrics")
        graph_win.geometry("1000x700")

        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 7))
        fig.patch.set_facecolor('#1a1a1a')
        for ax in [ax1, ax2, ax3]:
            ax.set_facecolor('#2b2b2b')
            ax.tick_params(colors='white')
            ax.spines['bottom'].set_color('white')
            ax.spines['top'].set_color('white')
            ax.spines['left'].set_color('white')
            ax.spines['right'].set_color('white')

        canvas = FigureCanvasTkAgg(fig, master=graph_win)
        canvas.get_tk_widget().pack(fill="both", expand=True)

        def animate(_frame):
            snapshot = perf.get_history_snapshot()
            ax1.clear()
            ax1.set_title("Latency (ms)", color="white", fontsize=12)
            ax1.set_ylabel("ms", color="white")
            if snapshot["latency"]:
                ax1.plot(snapshot["latency"], linewidth=2)
                ax1.fill_between(range(len(snapshot["latency"])), snapshot["latency"], alpha=0.3)
            ax1.grid(True, alpha=0.2, color="white")

            ax2.clear()
            ax2.set_title("Throughput (KB/s)", color="white", fontsize=12)
            ax2.set_ylabel("KB/s", color="white")
            if snapshot["throughput"]:
                ax2.plot(snapshot["throughput"], linewidth=2)
                ax2.fill_between(range(len(snapshot["throughput"])), snapshot["throughput"], alpha=0.3)
            ax2.grid(True, alpha=0.2, color="white")

            ax3.clear()
            ax3.set_title("Packet Loss (%)", color="white", fontsize=12)
            ax3.set_ylabel("%", color="white")
            ax3.set_xlabel("Time", color="white")
            if snapshot["loss"]:
                ax3.plot(snapshot["loss"], linewidth=2)
                ax3.fill_between(range(len(snapshot["loss"])), snapshot["loss"], alpha=0.3)
            ax3.grid(True, alpha=0.2, color="white")
            plt.tight_layout()

        self.animation = FuncAnimation(fig, animate, interval=1000, cache_frame_data=False)
        canvas.draw()

    def _process_gui_queue(self):
        try:
            processed = 0
            while processed < 50:
                try:
                    action, args = gui_queue.get_nowait()
                    if action == "print":
                        self._print_console(*args)
                    elif action == "bubble":
                        self._add_bubble(*args)
                    elif action == "notify":
                        notify_user(*args)
                    elif action == "update_metrics":
                        self._update_metrics()
                    elif action == "update_legend":
                        self._render_legend()
                    elif action == "clean_legend":
                        self._clean_legend()
                    elif action == "verify_response":
                        self._handle_verify_response(*args)
                    elif action == "tamper_alert":
                        self._handle_tamper_alert(*args)
                    elif action == "tamper_check_response":
                        self._handle_tamper_check_response(*args)
                    gui_queue.task_done()
                    processed += 1
                except queue.Empty:
                    break
        except Exception as e:
            print(f"[gui] queue processing error: {e}")
        finally:
            self.root.after(100, self._process_gui_queue)

    def _handle_verify_response(self, from_peer, result):
        if not isinstance(result, dict):
            return
        self.verify_results[from_peer] = result
        ok = result.get("ok", False)
        issues = result.get("issues", [])
        status = "✅ OK" if ok else f"⚠️ {len(issues)} issue(s)"
        self._print_console(f"🔍 Verify response from {from_peer}: {status}")
        if issues:
            for issue in issues[:5]:
                self._print_console(f"  • {issue}")

    def _handle_tamper_alert(self, alert_data):
        """Handle tamper alert from network"""
        if not isinstance(alert_data, dict):
            return
        fname = alert_data.get("filename", "Unknown")
        from_peer = alert_data.get("from", "Unknown")
        expected = alert_data.get("expected_hash", "")[:16]
        actual = alert_data.get("actual_hash", "")[:16]
        self._print_console(f"🚨 TAMPER ALERT from {from_peer}: {fname}")
        self._print_console(f"   Expected: {expected}... | Actual: {actual}...")
        notify_user("Tamper Alert!", f"{fname} reported by {from_peer}")
        # Highlight the affected block, if provided
        try:
            block_idx = alert_data.get("block_index")
            if isinstance(block_idx, int):
                self.alert_blocks.add(block_idx)
                if self._explorer:
                    self._draw_explorer()
        except Exception:
            pass

    def _handle_tamper_check_response(self, from_peer, file_info, result):
        if not isinstance(result, dict) or not isinstance(file_info, dict):
            return
        fname = file_info.get("filename", "Unknown")
        status = result.get("status", "unknown")
        if status == "valid":
            self._print_console(f"✅ {from_peer} confirms {fname} is valid")
        elif status == "tampered":
            self._print_console(f"⚠️ {from_peer} reports {fname} is TAMPERED")
            expected = result.get("expected", "")[:16]
            actual = result.get("actual", "")[:16]
            self._print_console(f"   Expected: {expected}... | Got: {actual}...")
        elif status == "missing":
            self._print_console(f"❌ {from_peer} doesn't have {fname}")
        else:
            error_msg = result.get("message", "Unknown error")
            self._print_console(f"❓ {from_peer} error checking {fname}: {error_msg}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    try:
        load_peer_colors()
        app = App()
        app.run()
    except KeyboardInterrupt:
        print("\n[shutdown] Interrupted by user")
    except Exception as e:
        print(f"[fatal] {e}")
        import traceback
        traceback.print_exc()
    finally:
        plt.close('all')
