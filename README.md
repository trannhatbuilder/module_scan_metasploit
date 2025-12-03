# 🔍 Researching & Developing a Vulnerability Scanning Module on Metasploit Framework

## 🚀 Overview
This project focuses on researching the **Metasploit Framework** and developing a custom **auxiliary scanning module** for detecting vulnerabilities through TCP service probing, SSH OS fingerprinting, and web server analysis.

The module demonstrates:
- Building a reliable TCP port scanner
- Extracting OS information using SSH banners
- Identifying web server technologies via HTTP response headers
- Proper socket handling for stability and accuracy
- Multi-threaded scanning with concurrency control

---

## 🧩 Features
- 🔎 **TCP Port Scanning** with configurable target ports
- 🖥 **OS Detection via SSH Banner Analysis**
- 🌐 **Web Server Identification** (Apache, Nginx, IIS, Lighttpd)
- ⚙️ **Concurrency Support** for faster multi-port scanning
- 🛡 **Safe Socket Handling** to avoid crashes and leaks
- 📡 **Integration with Metasploit Reporting System** (`report_service`, `report_note`)

---

## 📂 Module Structure
- `run_host`: Main logic — scans ports, triggers OS & web detection
- `detect_os_via_ssh`: Analyzes SSH banners to infer OS
- `detect_web_server`: Sends HTTP requests and extracts server info
- `parse_web_banner`: Normalizes server names and versions
- `extract_version`: Extracts version string from banner using regex

---

## 🛠 Configuration Options
| Option | Description | Default |
|--------|-------------|----------|
| `PORTS` | Comma-separated ports to scan | `21,22,23,25,80,443,3389` |
| `TIMEOUT` | Timeout per socket (ms) | `1000` |
| `CONCURRENCY` | Number of parallel scan threads | `5` |
| `OS_DETECTION` | Enable SSH OS detection | `true` |
| `WEB_DETECTION` | Enable web server detection | `true` |

---

## 📝 Requirements
- Metasploit Framework installed
- Target host reachable via network
- No authentication needed (banner-based detection)
- Optional: SSH service running (for OS detection)
- Optional: Web server running (for HTTP fingerprinting)

---

## 🕹️ Usage
Place this scanner module in:
```
~/.msf4/modules/auxiliary/scanner/custom/
```
Run with:
```
msfconsole
use auxiliary/scanner/custom/reliable_tcp_scanner
set RHOSTS <target_range>
set PORTS <custom_ports>
run
```

---

## 📊 Output Examples
- ✅ `192.168.1.10:22 - OPEN`
- 🖥 `192.168.1.10 - OS Detected: Linux (95% accuracy)`
- 🌐 `192.168.1.10:80 - Web Server: Apache 2.4.41`

---

## 📚 References
This project is based solely on:
- Metasploit Framework official APIs
- Custom detection logic built from raw socket analysis

(No external tools or external databases were used.)

---

## ⚠️ Disclaimer
This scanner is intended **strictly for educational, academic, and authorized pentesting purposes**.  
Do **NOT** use it on systems without explicit permission.

---

## 👨‍💻 Authors
- 🧑‍💻 NHAT
- 🧑‍💻 PHUOC

---

## ⭐ Goal of the Project
To provide a real-world demonstration of:
- How to design a custom reconnaissance module in Metasploit
- How to interact with TCP services safely and efficiently
- How banner‑based fingerprinting works in network security
- How to contribute new scanning modules to the MSF ecosystem

This project helps students and researchers understand how vulnerability scanners are built inside MSF, enabling further expansion into automated vulnerability detection modules.
