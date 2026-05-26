# 🔍 Ping Sweep — Advanced Host Discovery Tool

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-black?style=for-the-badge&logo=flask)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Network%20Scanner-red?style=for-the-badge)
![Networking](https://img.shields.io/badge/Networking-Host%20Discovery-success?style=for-the-badge)
![Open Source](https://img.shields.io/badge/Open%20Source-GitHub-181717?style=for-the-badge&logo=github)
![Ethical Hacking](https://img.shields.io/badge/Ethical%20Hacking-Educational-orange?style=for-the-badge)

<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=24&pause=1000&color=1A6FD4&center=true&vCenter=true&width=1200&lines=Advanced+Ping+Sweep+%2F+Host+Discovery+Tool;Python+%2B+Flask+Cybersecurity+Project;ICMP+%2B+TCP+Fallback+Host+Scanning;OS+Fingerprinting+%2B+Port+Scanner;Educational+Network+Reconnaissance+Dashboard" />

### ⚡ Modern Network Discovery & Host Scanning Tool

### 🔥 ICMP Ping • TCP Fallback • Port Scanner • OS Detection • Flask Dashboard

</div>

---

# 📌 Overview

Ping Sweep is a modern cybersecurity-inspired host discovery and network reconnaissance tool built using:

- Python
- Flask
- socket programming
- threading
- concurrent scanning
- ICMP detection
- TCP fallback detection

This project provides:

✅ CLI mode  
✅ Advanced Flask dashboard  
✅ Real-time scan updates  
✅ Host discovery  
✅ Port scanning  
✅ OS fingerprinting  
✅ Reverse DNS lookup  
✅ Device type detection  

---

# ⚠️ LEGAL DISCLAIMER

```txt
This tool is STRICTLY for:

- educational purposes
- authorised security testing
- owned networks only
- cybersecurity research
- ethical hacking labs

Unauthorised network scanning may violate:

• Computer Fraud and Abuse Act (CFAA)
• Computer Misuse Act 1990
• Information Technology Act 2000
• Local cybersecurity laws

The author assumes ZERO LIABILITY for misuse.
```

---

# 🚀 Features

# 🔍 Host Discovery

- ICMP ping sweep
- TCP fallback scanning
- Real-time host detection
- Fast subnet scanning
- Multi-threaded scanning engine
- Live network mapping

---

# ⚡ TCP Fallback Detection

Detects hosts even when:

- ICMP is blocked
- firewalls block ping
- routers filter echo requests

Uses:

- TCP connect scanning
- common service probing

---

# 🌐 Flask Web Dashboard

Includes:

- 5-page web interface
- modern UI
- responsive dashboard
- animated scan progress
- live host updates
- activity logging

---

# 🔌 Built-in Port Scanner

Scan:

- SSH
- HTTP
- HTTPS
- FTP
- SMB
- RDP
- MySQL
- MongoDB
- Redis
- VNC

---

# 💻 OS Fingerprinting

Detects likely operating system using:

- TTL analysis
- open port signatures
- service fingerprints
- network heuristics

---

# 🧠 Device Type Detection

Can identify:

- routers
- switches
- Linux servers
- Windows machines
- printers
- database servers
- network appliances

---

# 🌍 Reverse DNS Lookup

Automatically performs:

- hostname resolution
- reverse DNS analysis
- network naming discovery

---

# 📊 Real-Time Statistics

Dashboard displays:

- live hosts
- scan progress
- RTT
- TTL
- device types
- open ports
- OS confidence

---

# 🧠 Educational Features

Learn:

- subnet scanning
- ICMP networking
- TCP scanning
- TTL fingerprinting
- OS detection
- network reconnaissance
- ethical hacking basics

---

# 🖥️ Modes

# 1️⃣ CLI Mode

Run from terminal:

```bash
python ping_sweep.py
```

---

# 2️⃣ Web Dashboard Mode

Launch Flask UI:

```bash
python ping_sweep.py --web
```

Open:

```txt
http://localhost:5000
```

---

# 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core backend |
| Flask | Web dashboard |
| socket | TCP scanning |
| subprocess | ICMP ping |
| threading | Parallel scanning |
| concurrent.futures | Multi-threading |
| argparse | CLI parsing |
| HTML/CSS/JS | Frontend UI |

---

# 📥 Installation Guide

# 🐍 Step 1 — Install Python

Download Python:

🔗 https://www.python.org/downloads/

IMPORTANT:

Enable:

```txt
Add Python to PATH
```

---

# 📦 Step 2 — Install Flask

Open terminal:

```bash
pip install flask
```

---

# 📂 Step 3 — Clone Repository

```bash
git clone https://github.com/mrshrivasta/Ping-sweep.git
```

---

# 📁 Step 4 — Open Project Folder

```bash
cd Ping-sweep
```

---

# 🚀 Step 5 — Run CLI Mode

```bash
python ping_sweep.py
```

---

# 🌐 Step 6 — Run Web Dashboard

```bash
python ping_sweep.py --web
```

---

# 🌍 Step 7 — Open Browser

```txt
http://localhost:5000
```

---

# ⚡ Quick Start

```bash
pip install flask
python ping_sweep.py --web
```

---

# 🖥️ CLI Usage

# Basic Scan

```bash
python ping_sweep.py
```

---

# Scan Specific Subnet

```bash
python ping_sweep.py --subnet 192.168.1
```

---

# Scan Custom Range

```bash
python ping_sweep.py --subnet 192.168.1 --start 1 --end 254
```

---

# Scan Specific Ports

```bash
python ping_sweep.py --ports 22,80,443,3389
```

---

# Enable All Common Ports

```bash
python ping_sweep.py --all-ports
```

---

# Export CSV

```bash
python ping_sweep.py --csv results.csv
```

---

# Export JSON

```bash
python ping_sweep.py --json results.json
```

---

# Full Example

```bash
python ping_sweep.py --subnet 192.168.1 --start 1 --end 254 --all-ports --workers 80
```

---

# 🌐 Web Dashboard Pages

# 🎯 Scanner Dashboard

Features:

- subnet targeting
- live scan progress
- host grid visualization
- scan controls
- live activity logs

---

# 📋 Results Dashboard

Displays:

- full scan results
- sorting
- filtering
- exports
- device analysis

---

# 🔌 Port Scanner Page

Scan:

- custom ports
- port ranges
- top 100 ports
- top 1024 ports
- full TCP range

---

# 💻 OS Detection Page

Fingerprint devices using:

- TTL analysis
- port signatures
- device heuristics

---

# ℹ️ About / Help Page

Explains:

- how ping sweep works
- TCP fallback
- subnet scanning
- OS detection
- networking concepts

---

# 🔒 Security Architecture

# ⚡ Multi-Threaded Engine

Uses:

```python
ThreadPoolExecutor
```

for:

- fast concurrent scanning
- efficient host discovery
- scalable subnet scanning

---

# 🌐 ICMP + TCP Hybrid Detection

Detection order:

1. ICMP ping
2. TCP fallback
3. Port scan
4. Reverse DNS
5. OS detection

---

# 🔍 TCP Fallback Scanner

If ping fails:

- attempts TCP connect
- checks common ports
- confirms host availability

---

# 🧠 OS Fingerprinting Logic

TTL-based detection:

| TTL Range | OS |
|---|---|
| 1–64 | Linux/macOS |
| 65–128 | Windows |
| 129–255 | Cisco/Network Device |

---

# 📡 Port Signatures

Detects:

| Ports | Likely Device |
|---|---|
| 3389 | Windows |
| 22 + 111 | Linux |
| 9100 | Printer |
| 80 + 53 + 23 | Router |

---

# 🌐 API Endpoints

# `/api/scan`

Performs:

- live subnet scanning
- SSE streaming
- host discovery

---

# `/api/results`

Returns scan results.

---

# `/api/portscan`

Performs TCP port scanning.

---

# `/api/osdetect`

Runs OS fingerprinting.

---

# `/api/subnets`

Auto-detects local subnet.

---

# 📂 Project Architecture

```txt
ping_sweep.py
│
├── ICMP Engine
├── TCP Fallback Scanner
├── Port Scanner
├── Reverse DNS Engine
├── OS Fingerprinting
├── Device Detection
├── Flask Dashboard
├── Real-time Event System
├── CLI Interface
└── Export System
```

---

# 📊 Supported Ports

Includes detection for:

| Port | Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 135 | RPC |
| 139 | NetBIOS |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |
| 5900 | VNC |
| 6379 | Redis |
| 8080 | HTTP-Alt |
| 8443 | HTTPS-Alt |
| 27017 | MongoDB |

---

# 🌍 Cross-Platform Support

Supports:

✅ Windows  
✅ Linux  
✅ macOS  

---

# 📈 Performance Features

- Fast concurrent scanning
- Low memory usage
- Thread-based parallelism
- Real-time updates
- Optimized socket handling

---

# 🧠 Learning Concepts

This project helps learn:

- subnet scanning
- ICMP networking
- TCP sockets
- host discovery
- port scanning
- OS fingerprinting
- threading
- Flask dashboards
- network reconnaissance

---

# ⚠️ Ethical Hacking Notice

```txt
ONLY use on:

- lab environments
- private networks
- owned systems
- authorised infrastructure

DO NOT:
- scan random public IPs
- attack systems
- abuse open ports
- scan without permission
```

---

# 🛠️ Troubleshooting

# ❌ Python not recognized

Reinstall Python and enable:

```txt
Add Python to PATH
```

---

# ❌ pip not recognized

Run:

```bash
python -m pip install flask
```

---

# ❌ Flask not installed

Run:

```bash
pip install flask
```

---

# ❌ Port 5000 already in use

Change:

```python
app.run(port=5000)
```

to:

```python
app.run(port=5050)
```

---

# ❌ Ping blocked

Some networks:

- disable ICMP
- filter echo requests
- block ping

TCP fallback scanning solves this.

---

# ❌ Slow scans

Increase workers:

```bash
--workers 100
```

---

# 🔥 Why This Project?

This is NOT a beginner calculator project.

This demonstrates:

✅ real networking concepts  
✅ host discovery  
✅ TCP scanning  
✅ OS detection  
✅ Flask engineering  
✅ threading  
✅ real-time dashboards  
✅ cybersecurity workflows  

---

# 🚀 Future Improvements

Planned:

- ARP scanning
- traceroute support
- live graphs
- dark mode
- Nmap integration
- vulnerability scanning
- packet capture
- device inventory
- Docker deployment

---

# 🤝 Contributing

Pull requests are welcome.

Steps:

1. Fork repository
2. Create branch
3. Commit changes
4. Push updates
5. Open pull request

---

# ⭐ Support

If you like this project:

⭐ Star the repository  
🍴 Fork the repository  
📢 Share the project  

---

# 👨‍💻 Author

# Karanam Shrivasta

### 🌐 GitHub

:contentReference[oaicite:0]{index=0}

### 💼 LinkedIn

:contentReference[oaicite:1]{index=1}

---

# 📜 License

MIT License

---

# 📚 Educational Note

This project is designed for:

- cybersecurity learners
- networking students
- ethical hacking labs
- Python developers
- Flask learners
- system programming education

---

# 🔥 Fun Fact

This entire advanced network scanner runs from:

```txt
One Python file.
```

---

# 📄 Source Reference

Core project functionality includes:

- ICMP ping sweep
- TCP fallback detection
- OS fingerprinting
- Flask 5-page dashboard
- port scanning engine
- reverse DNS lookup
- device type detection :contentReference[oaicite:2]{index=2}

---

<div align="center">

# 🔍 Ping Sweep

### ⚡ Advanced Host Discovery Tool

### 🚀 Built With Python + Flask

<img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=20&pause=1000&color=1A6FD4&center=true&vCenter=true&width=1000&lines=Made+By+Karanam+Shrivasta;Educational+Cybersecurity+Project;Advanced+Host+Discovery+Dashboard;Python+Networking+Reconnaissance+Tool" />

</div>
