# 🛡️ UltraAnalyzer: Advanced Web Technology Fingerprinter

**UltraAnalyzer** is a high-performance, asynchronous engine designed for deep web reconnaissance. By combining **Python 3 AsyncIO** with **Headless Chromium**, it identifies modern web stacks (React, Vue, etc.) that traditional static tools often miss.

---

## 🎯 Program Goals

The primary objective of UltraAnalyzer is to bridge the gap between legacy scanning tools and the modern JavaScript-heavy web. Our goals include:
* **Accuracy over Speed:** Prioritizing the execution of client-side code to uncover "hidden" technologies.
* **Privacy-First Auditing:** Ensuring every request and DNS lookup is natively routed through the Tor network.
* **Operational Resilience:** Providing a tool that can handle thousands of targets without data loss or system exhaustion.
* **Modular Extensibility:** Allowing security researchers to add new fingerprints via simple JSON signatures without modifying the core engine.

## ✨ Key Features

* **🌐 Full JS Rendering:** Uses a Headless Chromium engine to hydrate and analyze Single Page Applications (SPAs).
* **🕵️ Zero-Leak Tor Integration:** Native `socks5h` support ensures absolute anonymity for both traffic and DNS resolution.
* **⚡ Asynchronous Concurrency:** Managed via `asyncio.Semaphore` to optimize hardware resources and prevent IP throttling.
* **🔍 Multi-Layer Fingerprinting:** Identifies technologies through HTTP headers, meta tags, script sources, and rendered DOM elements.
* **💾 Atomic JSONL Reporting:** Results are saved line-by-line; if the process is interrupted, all previous data remains intact.
* **🛡️ Stealth Engineering:** Mimics legitimate browser signals to reduce the footprint left on Web Application Firewalls (WAFs).

---

## 🛠️ Full System Installation (Linux/Debian/Kali)

Follow these steps to prepare your environment from scratch.

### 1. Install System Dependencies
First, install the Python stack, Tor, and Proxychains4:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv tor proxychains4
```

2. Configure Proxychains4

Ensure Proxychains is pointing to the local Tor SOCKS5 proxy.
```Bash

sudo nano /etc/proxychains4.conf
```

Scroll to the bottom and ensure the [ProxyList] contains:
Plaintext

```Bash
socks5  127.0.0.1 9050
```

3. Initialize Tor Service

Start Tor and verify it is listening on port 9050:
```Bash

sudo systemctl start tor
sudo systemctl enable tor
```
# Verify:
```Bash
ss -antlp | grep 9050
```

📦 Setting Up the Project
1. Clone & Virtual Environment
```Bash
git clone https://github.com/hiddendestroyer1945/ultra_analyzer.git
cd ultra_analyzer
```

# Create and Activate Virtual Environment
```Bash
python3 -m venv venv
source venv/bin/activate
```

2. Install Python Packages & Browsers
```Bash

pip install -r requirements.txt
playwright install chromium
```

🚦 Usage & Examples
Internal Tor Routing (Default)

The program is pre-configured to use socks5h://127.0.0.1:9050 internally to prevent DNS leaks.
```Bash

python3 ultra_analyzer.py "url"
python3 ultr_analyzer.py "url1 url2 url3"
```
Using with url list file. first create the list file in program root directory and enter the needed url list in one by one.

```Bash
touch list.txt
python3 ultra_analyzer.py list.txt
```

Real-World Use Cases
Use Case	Description
CMS Auditing	Identifying outdated WordPress/Joomla versions across a range of IPs.
Security Hardening	Verifying if your production servers are leaking Server or X-Powered-By headers.
Shadow IT Discovery	Finding unauthorized React or Vue apps deployed within a corporate subnet.
Privacy Validation	Ensuring your audit traffic is correctly masked via the Tor network.

📊 Example Output

The results are saved in reports/report.jsonl.
JSON

{
  "url": "[https://example.com](https://example.com)",
  "status": "online",
  "timestamp": "2026-03-31T10:00:00",
  "detections": [
    {"plugin": "Server: Nginx", "version": "1.18.0"},
    {"plugin": "Framework: React", "version": null},
    {"plugin": "Security: HSTS", "version": null}
  ]
}

⚖️ License

This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Users are responsible for complying with all applicable laws and regulations. Always obtain proper authorization before testing systems you do not own.

👤 Author

Created by a professional Python programmer with expertise in Linux system administration and penetration testing.