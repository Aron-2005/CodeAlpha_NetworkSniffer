# CodeAlpha_NetworkSniffer

### 🧠 Overview
This project is **Task 1 – Basic Network Sniffer** for the CodeAlpha Cyber-Security Internship.

The script captures live network packets, extracts key details such as source and destination IP addresses, ports, protocols, and payloads, and saves both a `.pcap` file and a summarized `.csv`.  
It helps you understand how network traffic flows and what data each packet carries.

---

### ⚙️ Features
- Real-time packet capture (requires **Npcap**)
- Shows source/destination IP, protocol, ports, payload (hexdump)
- Saves output to:
  - `captured_packets.pcap` – full packet capture
  - `packet_summary.csv` – structured summary
- Works on **Windows 10/11**, **Linux**, or **macOS**

---

### 🖥 Requirements
| Component | Version / Notes |
|------------|-----------------|
| Python | 3.8 or newer |
| Packages | `scapy`, `pandas` *(optional)* |
| Windows driver | **Npcap** (install in *WinPcap-compatible mode*) |
| Permissions | Run PowerShell / CMD / VS Code **as Administrator** |

---

### 📦 Installation
```powershell
# 1. Clone or open your project folder
cd C:\codealpha\CodeAlpha_NetworkSniffer

# 2. (Optional) Create and activate a virtual environment
python -m venv venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
python -m pip install --upgrade pip
pip install scapy pandas


