<div align="center">
  <img src="logo.png" alt="AirWave Logo" width="180" height="180">
  <h1>AirWave</h1>
  <p><strong>WiFi WPA2 安全测试自动化工具</strong></p>
  <p>
    <a href="https://github.com/proapgandistic/AirWave/releases">
      <img src="https://img.shields.io/badge/release-v0.2.1-blue.svg" alt="Release">
    </a>
    <a href="https://github.com/proapgandistic/AirWave/blob/master/LICENSE">
      <img src="https://img.shields.io/badge/license-GPLv3-green.svg" alt="License">
    </a>
    <img src="https://img.shields.io/badge/python-3.9+-yellow.svg" alt="Python">
    <img src="https://img.shields.io/badge/raspberry--pi-4B-red.svg" alt="Raspberry Pi">
    <img src="https://img.shields.io/badge/MT7612U-dual--band-orange.svg" alt="MT7612U">
    <img src="https://img.shields.io/badge/windows-GPU%20node-lightblue.svg" alt="Windows GPU">
  </p>
  <p>
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#hardware">Hardware</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#usage">Usage</a> •
    <a href="#changelog">Changelog</a>
  </p>
</div>

---

WiFi WPA2 安全测试自动化工具。Kali 树莓派负责扫描抓包，Windows GPU 节点负责离线破解，全程在浏览器 Web UI 操作。

## Features

### Dual-band Scanning
- 2.4G + 5G dual-band WiFi scanning
- Signal strength, encryption, channel, connected clients
- Click AP to view connected device MAC list
- Real-time refresh during scan
- Scan history save and load

### Automated Attack
- Auto deauth to force client reconnection, capture EAPOL 4-way handshake
- Auto convert to hc22000 hash format
- 4 Hashcat attack modes:
  - Mask brute force (-a 3)
  - Dictionary attack (-a 0)
  - Dictionary + Mask hybrid (-a 6)
  - Mask + Dictionary hybrid (-a 7)
- Dictionary pre-split by length and charset
- Real-time Hashcat progress, speed, ETA

### Multi-adapter Support
- Auto detect all wireless adapters on startup
- Choose which adapter to use for monitor mode
- Auto configure NetworkManager, doesn't affect daily use
- Compatible with MediaTek MT7612 and other monitor-mode adapters

### Windows Offline Cracking
- Hash uploaded to Windows node via SSH
- NVIDIA GPU accelerated cracking
- Support multiple compute nodes
- Even if node is offline, you can manually copy hash files to crack

### Assets & Records
- Captured handshake files auto-archived by SSID + BSSID
- Cracked WiFi auto-saved to known list
- All data persisted, survives reboot

## Architecture

```
┌─────────────────┐         SSH/SCP         ┌─────────────────┐
│  Raspberry Pi   │ ──────────────────────> │  Windows Node   │
│  (Web UI)       │ <────────────────────── │  (Hashcat GPU)  │
│                 │   Hash upload + result  │                 │
│  MT7612U USB    │                         │  NVIDIA GPU     │
│  Monitor Mode   │                         │  CUDA           │
└─────────────────┘                         └─────────────────┘
        │
        ▼
    Target WiFi AP
```

## Hardware

| Device | Requirement |
|--------|-------------|
| Capture device | Raspberry Pi 4/5 running Kali Linux |
| WiFi adapter | MediaTek MT7612U or other dual-band monitor-mode adapter |
| Cracking device | Windows 10/11 + NVIDIA GPU (RTX 30 series+ recommended) |
| Network | LAN connectivity between Kali and Windows |

## Quick Start

### 1. Kali Side

```bash
# Install dependencies
sudo apt update
sudo apt install python3 python3-pip aircrack-ng hcxtools -y
pip3 install fastapi uvicorn

# Clone project
git clone https://github.com/proapgandistic/AirWave.git
cd AirWave
```

### 2. Windows Side

1. Extract `hashcat-6.2.6-windows-gpu-node.7z`
2. Enable OpenSSH Server
3. Configure SSH passwordless login

### 3. Launch AirWave

**Method 1: Desktop Shortcut (Recommended)**
Double-click `AirWave.desktop` on desktop. Launcher will guide you:
1. Choose monitor adapter
2. Choose whether to stop NetworkManager
3. Start web service

**Method 2: CLI**
```bash
./airwave-launcher.sh
```

### 4. Web Config

Open browser: `http://<Kali-IP>:8000`

Go to "Config" page and fill in:
- Windows node IP
- SSH username & password
- Hashcat path

## Supporting Tools

### WiFi Connection Manager
When NetworkManager is stopped (for monitor mode), use this tool to connect to WiFi networks manually:
- Double-click `WiFi连接管理.desktop`
- Select a WiFi from the list
- Enter password to connect

### AP Hotspot Mode
When outdoors without a router, run this to make the Raspberry Pi a WiFi hotspot:
- Double-click `开启WiFi热点模式.desktop`
- Phone/other devices can directly connect to the Pi's hotspot
- Access AirWave web UI via `http://100.100.100.1:8000`

## Usage

### Scan
1. Open "Scan" tab
2. Click "Start Scan"
3. Wait for target APs to appear
4. Click AP row to expand client list

### Capture & Attack
1. Select target AP
2. Click "Start Attack"
3. Auto deauth + handshake capture
4. Auto upload to Windows for cracking

### Dictionary Attack
1. Open "Assets" tab
2. Find the .hc22000 file to crack
3. Click "Load" to jump to attack page
4. Choose dictionary and attack mode
5. Click "Start"

## Project Structure

```
AirWave/
├── main.py                  # FastAPI web UI (all-in-one)
├── airwave-launcher.sh      # CLI setup wizard
├── AirWave.desktop          # Desktop shortcut to launch AirWave
├── wifi-ap.sh               # AP hotspot mode script
├── wifi-connect.sh          # WiFi connection script
├── wifi-menu.sh             # WiFi connection menu UI
├── WiFi连接管理.desktop      # Desktop shortcut for WiFi connection manager
├── 开启WiFi热点模式.desktop   # Desktop shortcut for AP hotspot mode
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── LICENSE                  # GPL v3
└── hashcat-6.2.6-windows-gpu-node.7z  # Windows GPU node installer
```

## Changelog

### v0.2.1 (2026-09-22)
- Rebrand to AirWave, add About page
- Dictionary pre-split by length + charset
- Real-time Hashcat progress display
- Fix history scan loading bug
- Unify English font to Cascadia Code

### v0.2.0 (2026-09-21)
- Full Hashcat parameter integration on attack page
- Asset archive & attack from assets
- Client MAC list on scan page
- Scan history save & load
- WPS detection & encryption type identification
- Outdoor AP hotspot direct connect mode

### v0.1.0 (2026-09-20)
- First release
- Basic WiFi scan + deauth capture
- SSH upload to Windows Hashcat cracking

## Related Projects

- [PiSubGhz](https://github.com/proapgandistic/PiSubGhz) - Raspberry Pi Sub-GHz tool

## Disclaimer

This project is for educational and authorized testing only. Unauthorized cracking of WiFi networks is illegal. Test only on networks you own or have written permission to test.

The author is not responsible for any misuse of this tool.

## License

GPL v3
