# NetScope — Network Packet Analyzer

A Python-based network packet analyzer built to capture, 
dissect, and understand network traffic in real time.

Built as part of my CodeAlpha Cybersecurity internship.

## What It Does

- Captures live network packets from your network interface
- Parses and displays source/destination IPs, protocols, and ports
- Detects and labels TCP, UDP, ICMP, DNS, ARP, and HTTP traffic
- Shows TCP flag states (SYN, ACK, FIN, RST)
- Displays payload content in verbose mode
- Generates a session summary with protocol breakdown and top talkers
- Includes built-in protocol explainers for learning

## Requirements

- Python 3.x
- Scapy (optional but recommended for live capture)

Install Scapy:
pip install scapy


## How to Run

**Demo mode (no root needed):**
python packet_analyzer.py --demo


**Demo with payload bytes:**
python packet_analyzer.py --demo -v


**Live capture (requires root/admin):**
sudo python packet_analyzer.py --live -c 50


**Filter by protocol:**
sudo python packet_analyzer.py --live --bpf "tcp port 80"


**Protocol explainer:**
python packet_analyzer.py --explain TCP
python packet_analyzer.py --explain DNS


---

## Modes

| Mode | Description |
|------|-------------|
| `--demo` | Offline demo with 16 synthetic packets |
| `--live` | Live capture from your network interface |
| `--explain` | Deep-dive explainer for any protocol |

---

## Protocols Supported

TCP · UDP · ICMP · DNS · ARP · HTTP

## What I Learned

- How packets are structured at the byte level
- TCP 3-way handshake and connection teardown
- How DNS queries and responses work
- ARP resolution and why it's a security risk
- Difference between Scapy and raw socket capture
- Network forensics fundamentals


## Tools Used

- Python 3
- Scapy
- socket / struct (Python standard library)


## Ureh

**Ureh** — Cybersecurity enthusiast  
CodeAlpha Cybersecurity Intern  March 2026 -April 2026
[LinkedIn](#) · [GitHub](#)
