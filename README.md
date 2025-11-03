# 🚀 Performance Analysis of Blockchain-Based Decentralized Chat and File Transfer in Local Area Networks

### 🧠 Overview
This project implements a **decentralized chat and file transfer system** that uses **blockchain technology** to ensure integrity, security, and synchronization across all peers in a **Local Area Network (LAN)**.
It provides a **tamper-proof, peer-to-peer communication environment** where every message and file transaction is logged as a block on a shared distributed ledger.

---

## 🏗️ Features

- **Blockchain-Backed Messaging:** Every chat message is stored as a block with timestamp and cryptographic hash.
- **File Transfer System:** Send and receive files securely among peers.
- **Peer-to-Peer Communication:** No central server — all peers sync automatically over LAN.
- **Tamper Detection:** Alerts users when file integrity is compromised.
- **Real-Time Performance Graph:** Displays message throughput, latency, and blockchain growth.
- **Blockchain Visualizer:** Graphical representation of all connected nodes and blocks.
- **Persistent Peer Colors and IDs:** Each peer is color-coded for easy identification.
- **Cross-Platform Compatibility:** Runs on Windows, macOS, and Linux using Python.

---

## ⚙️ System Requirements

- **Python:** Version 3.10 or later
- **Operating System:** Windows / macOS / Linux
- **Network:** All peers connected to the same LAN (via WiFi or Ethernet)

---

## 🧩 Dependencies

Make sure these dependencies are installed (automatically handled via `requirements.txt`):

```
customtkinter==5.2.2
plyer==2.1.0
matplotlib==3.8.0
networkx==3.2.1
numpy==1.26.0
pandas==2.1.1
uuid==1.30
```

To install them manually:
```bash
pip install -r requirements.txt
```

---

## 🐳 Docker Support

If you prefer to run this project inside Docker:

```Dockerfile
# Use an official lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Copy all project files into the container
COPY . /app

# Install dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port used by the application (optional, adjust if needed)
EXPOSE 5000

# Default command to run the application
CMD ["python", "bccc.py"]
```

Build and run the container:
```bash
docker build -t blockchain-chat .
docker run -it --network host blockchain-chat
```

---

## 🧭 How to Use

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/blockchain-lan-chat.git
   cd blockchain-lan-chat
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the application:**
   ```bash
   python bccc.py
   ```
4. **Start chatting:**
   - Each device on the same LAN automatically detects peers.
   - Send messages or transfer files — all actions are securely logged to the blockchain.

---

## 🧪 Testing Scenarios

### 1. **Blockchain Synchronization Test**
- Run the app on **two or more computers** connected to the **same LAN**.
- Send messages or files between peers.
- Verify that each blockchain visualizer shows **identical blockchains** (same number of blocks, hashes, and timestamps).

### 2. **Tamper Detection Test**
- Manually modify a stored file or blockchain record.
- Observe the **tamper alert** in the blockchain visualizer.
- The affected block will be highlighted and the alert broadcast to all peers.

### 3. **Performance Analysis Test**
- Send multiple large files or frequent messages.
- Watch the **real-time graph** for throughput and latency performance.
- Compare different runs to analyze network behavior.

### 4. **File Transfer Verification**
- Upload a file using the chat interface.
- Confirm that all connected peers receive the file.
- Verify that a new blockchain block is created containing the file’s metadata.

---

## 📊 Results and Observations

- The blockchain remains **synchronized** across peers.
- **Tamper detection** triggers alerts in real-time.
- **Throughput and latency metrics** vary based on file size and number of peers.
- The decentralized design eliminates the need for a central server.

---

## 🏁 Conclusion

The project successfully demonstrates how **blockchain principles** can be applied to create a **secure, decentralized communication system** within a LAN.
It ensures **data integrity**, **peer-to-peer transparency**, and **real-time synchronization** — paving the way for more resilient local communication networks.
