  
<h1 align="center">🛡️ Python-Based Network Packet Analyzer</h1>
<p align="center"><i>A Scapy-powered tool for real-time packet capture and protocol analysis</i></p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Parrot-informational">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
</p>

---

> ⚠️ <strong>DISCLAIMER:</strong> This tool is intended <u>only</u> for educational and controlled lab environments.  
> Unauthorized use may be illegal or unethical.

---

## 📌 Features

✨ Real-time packet sniffing  
🔍 Deep inspection of IP, TCP, UDP, ICMP, HTTP, DNS  
🌐 IPv4 & IPv6 support  
🧠 BPF filtering (e.g., `tcp port 80`)  
📝 Log output to file  
📊 Clean output with timestamps and flags

---

## 🧰 Technologies Used

| Component       | Description                       |
|----------------|-----------------------------------|
| 🐍 Python 3     | Core language                     |
| 📦 Scapy       | Packet capture & dissection       |
| 🧪 Wireshark   | Packet validation tool            |
| 💻 Linux       | Tested on Kali & ParrotOS         |

---

## 🖥️ Screenshots

| Capture | Visual |
|--------|--------|
| ICMP, DNS, TCP Traffic | ![Packet Capture](screenshots/packet-capture.png) |
| Simulated Test Traffic | ![Traffic Test](screenshots/ping-nmap-whois.png) |
| TCP Port 80 Filtering | ![Filter Port 80](screenshots/filter-port80.png) |

---

## 🚀 Quick Start

```bash
# Basic capture
sudo python3 packet_analyzer.py -i eth0

# With filter
sudo python3 packet_analyzer.py -i eth0 -f "tcp port 80"

# Capture 100 packets only
sudo python3 packet_analyzer.py -i eth0 -c 100

# Log to file
sudo python3 packet_analyzer.py -i eth0 -l output.log
```

> 💡 Use `ip a` to list available interfaces on Linux.

---

## 📂 Folder Structure

```
📦 network-packet-analyzer/
├── 📄 packet_analyzer.py
├── 📄 README.md
├── 📄 LICENSE
├── 📁 screenshots/
│   ├── 📸 packet-capture.png
│   ├── 📸 ping-nmap-whois.png
│   └── 📸 filter-port80.png
```

---

## 📜 License

Licensed under the [MIT License](https://opensource.org/licenses/MIT)

---

## 👨‍💻 Author

**Shivshant Patil**  
Cybersecurity Enthusiast | CEH (v13) | Python & Linux | Packet Analysis  
📧 shivshantp007@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/shivshant-patil-b58aaa281)

---

> 💡 *This project was developed to simulate real-world packet sniffing scenarios for cybersecurity education.*
