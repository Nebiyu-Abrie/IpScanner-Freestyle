# 🖥️ IP Scanner (Windows & macOS)

A cross-platform GUI network scanner built with Python, Scapy, and Tkinter.
The app discovers devices on your local network using ARP scanning and provides basic device classification (router, phone, IP camera, printer, etc.).

Supports:
- ✅ Windows (`.exe`)
- ✅ macOS (`.app` / `.dmg`)

---

## ✨ Features

- ARP-based local network discovery
- GUI interface (Tkinter)
- Automatic admin privilege prompt
- Device type detection:
  - Router
  - Phones
  - IP Cameras
  - Printers
  - Network devices
- No external configuration required
- Single-file executables for both platforms

---

## 📦 Downloads

> Prebuilt binaries are available in the **Releases** section.

- **Windows**: `ipScanner.exe`
- **macOS**: `IPScanner.dmg`

---

## 🪟 Windows Usage

### Requirements
- Windows 10 / 11
- **Npcap** (WinPcap compatible mode)

Download:
https://nmap.org/npcap/

### Run the App

1. Right-click `ipScanner.exe`
2. Select **Run as Administrator**
3. Click **Scan Network**

> Admin privileges are required for ARP scanning.

### Build from Source (Windows)

```cmd
pip install scapy pyinstaller
pyinstaller --clean --onefile --windowed ipScanner.py
