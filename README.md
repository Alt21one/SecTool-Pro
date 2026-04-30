# SecTool Pro

**SecTool Pro** is a comprehensive, Windows-native security automation and auditing suite built with Python and CustomTkinter. Designed for both offline local environments and deep cloud-based threat analysis, it unifies essential cybersecurity tools into a single, highly polished graphical interface.

<br>

<img width="1186" height="851" alt="Screenshot_67" src="https://github.com/user-attachments/assets/1f870c7a-ba02-4495-9054-02b91455584b" />

<br>

## Features

SecTool Pro is divided into seven core security modules, accessible via the sidebar navigation:

### 🗺️ Network Mapper
Discovers active devices on your local network using native Windows ARP and ping sweeps.  
* **Topology Visualization:** Displays devices in a clear, responsive network map.  
* **Smart Proximity:** Calculates the distance of nodes from the center based on ping latency (RTT).  
* **OS Fingerprinting:** Estimates the target's operating system based on TTL responses.

<br>

<img width="1186" height="848" alt="Screenshot_74" src="https://github.com/user-attachments/assets/c33511de-2244-458d-9776-687be4704687" />

<br>

### 🛡️ Malware Scanner
Perform lightning-fast offline signature scans using a local SHA-256 hash database, or execute deep cloud audits utilizing the VirusTotal API v3.  
* **Dynamic HTML Reports:** Generates stylized incident reports detailing total files scanned, threats detected, and specific malware signatures.  

<br>

<img width="1183" height="850" alt="Screenshot_68" src="https://github.com/user-attachments/assets/e415acba-95de-42d4-a7b1-729cd9322526" />

<br>

<img width="695" height="486" alt="Screenshot_69" src="https://github.com/user-attachments/assets/9c910359-d774-48f1-9bfc-434b6f673aff" />

<br>

<img width="1918" height="982" alt="Screenshot_71" src="https://github.com/user-attachments/assets/20661c8d-a529-4ece-98e2-a69a35443e26" />

<br>

### 🔍 System Vulnerability Scanner
An automated local security audit tool that inspects the host machine for misconfigurations and missing hardening policies.  
* **Checks Included:** Missing Windows patches, outdated/risky software (e.g., Python 2.7, Flash), disabled firewalls, inactive UAC, open SMBv1, and weak local account password policies.

<br>

<img width="1187" height="843" alt="Screenshot_73" src="https://github.com/user-attachments/assets/26b5c80d-792f-4cc5-b01b-da5da1edfd30" />

<br>

### 🚨 Host Intrusion Detection System (HIDS)
A real-time packet-level analysis engine powered by Scapy.  
* Detects network anomalies including SYN floods, port scans, ARP spoofing, and excessive DNS queries (potential tunneling/exfiltration).  
* Displays live traffic statistics (packets/sec, total alerts) and color-coded severity logs.

<br>

<img width="1187" height="850" alt="Screenshot_72" src="https://github.com/user-attachments/assets/1f0ba19c-c684-4602-a317-64dd04fcad30" />

<br>

### 🔌 Network Port Scanner
Executes multithreaded TCP and UDP port scans with banner grabbing to identify active services.  
* Highlights common security risks (e.g., open Telnet, FTP, SMB, or RDP ports).

<br>

<img width="1183" height="848" alt="Screenshot_75" src="https://github.com/user-attachments/assets/1c531d87-6628-4e98-b2ac-dd6d8d92e03b" />

<br>

### 📧 OSINT Email Analyzer
Validates target email domains and checks for public exposure.  
* Evaluates MX, SPF, and DMARC records to determine spoofing vulnerability.  
* Checks public databases (like XposedOrNot) for data breaches and identifies disposable/burner email providers.

<br>

<img width="1181" height="849" alt="Screenshot_76" src="https://github.com/user-attachments/assets/68e9f2c9-2454-4656-9c5c-aa454d15173e" />

<br>

---

## 🛠️ Installation & Prerequisites

**1. Clone the repository:**
```bash
git clone [https://github.com/YourUsername/SecTool-Pro.git](https://github.com/YourUsername/SecTool-Pro.git)
cd SecTool-Pro
