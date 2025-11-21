# Advanced Python SSL/TLS Scanner (py-sslscan)

A Python-based SSL/TLS scanner designed for **Penetration Testers** and **Security Auditors**. This tool mimics the functionality of `sslscan` but includes enhanced features for modern assessment environments (like Kali Linux 2024+).

## 🚀 Key Features

* **Color-Coded Risk Assessment:** Instantly highlights weak ciphers (Red for Critical, Yellow for Weak/CBC).
* **Cipher Enumeration:** Brute-forces cipher suites to find everything the server supports, not just the preferred ones.
* **Kali Linux / OpenSSL 3 Compatible:** Automatically handles `@SECLEVEL=0` overrides to allow scanning for legacy/weak protocols on modern OSs.
* **Protocol Summary:** Displays enabled/disabled status for SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, and 1.3.
* **Detailed Info:** Checks for HTTP/2 (ALPN), TLS Compression (CRIME risk), and server preferences.
* **Dependency Free:** Uses only standard Python libraries (`ssl`, `socket`, `threading`).

## 📦 Installation

No installation required. Just clone and run:
```bash
git clone https://github.com/ktppt/py-sslscan-audit.git
cd py-sslscan-audit
chmod +x adv_sslscan.py
```

## 🛠 Usage
# Basic Scan
```
python3 adv_sslscan.py target.com
```

# Scan specific port with increased threads
```
python3 adv_sslscan.py target.com -p 8443 -t 50
```

## 📸 Screenshot
<img width="830" height="718" alt="image" src="https://github.com/user-attachments/assets/0b30b378-f5ae-43b4-99bc-add86e6ad5cd" />

## ⚠️ Disclaimer
This tool is for educational purposes and security testing only. Use it only on systems you own or have permission to test.
