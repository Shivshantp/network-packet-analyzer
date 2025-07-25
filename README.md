
# 🛡️ Network Packet Analyzer — Python + Scapy

A powerful and extensible **network packet analyzer** built with Python and Scapy. This tool captures and analyzes live traffic on a selected network interface, offering deep visibility into IP, TCP, UDP, DNS, HTTP, and more.

> 🔍 Designed as part of a real-world cybersecurity project to understand traffic analysis, simulate threat detection, and develop packet inspection skills.

---

## 🚀 Key Features

- 📡 Live packet sniffing on any network interface
- 🔍 Protocol-level dissection: TCP, UDP, ICMP, DNS, HTTP/HTTPS
- 🌐 Support for IPv4 and IPv6 traffic
- 🧠 Intelligent parsing of HTTP requests and DNS queries
- 🧰 BPF filter support (e.g., `tcp port 80`) for precise captures
- 📝 Packet logging to file for offline analysis
- ⚙️ Modular code with detailed error handling and logging

---

## 🧪 Demo Screenshots

📸 ICMP, DNS, and TCP traffic capture:  
![Packet Capture](screenshots/packet-capture.png)

📸 Analysis with ping, Nmap, and Whois:  
![Ping, Whois](screenshots/ping-nmap-whois.png)

📸 BPF Filtering for Port 80 and HTTP/HTTPS traffic:  
![Filter TCP Port 80](screenshots/filter-port80.png)

---

## ⚙️ How to Use

> Ensure you have Python 3 and Scapy installed. Run with root/sudo privileges to access raw sockets.

```bash
# Basic usage
sudo python3 packet_analyzer.py -i eth0

# With a custom BPF filter (e.g., only port 80)
sudo python3 packet_analyzer.py -i eth0 -f "tcp port 80"

# Capture a limited number of packets (e.g., 100)
sudo python3 packet_analyzer.py -i eth0 -c 100

# Log captured packet summaries to a file
sudo python3 packet_analyzer.py -i eth0 -l capture_log.txt
```

---

## 📁 Project Structure

```
📦 network-packet-analyzer/
├── 📄 packet_analyzer.py      # Main script
├── 📁 screenshots/            # Demo images for documentation
│   ├── packet-capture.png
│   ├── ping-nmap-whois.png
│   └── filter-port80.png
├── 📄 README.md               # Project overview
├── 📄 LICENSE                 # MIT License
```

---

## 🛠️ Tech Stack

- **Language**: Python 3
- **Libraries**: Scapy
- **Tested With**: Wireshark, Nmap, curl, ping, dig

---

## 👨‍💻 Author

**Shivshant Patil**  
Cybersecurity Enthusiast | CEH v13 | Red Team Learner  
📧 shivshantp007@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/shivshant-patil-b58aaa281)
