# =========================
# AUTO-SUDO (MUST BE FIRST)
# =========================
import os
import sys
import subprocess
import shlex

def relaunch_as_root():
    if os.geteuid() == 0:
        return

    if getattr(sys, 'frozen', False):
        cmd = shlex.quote(sys.executable)
    else:
        script = shlex.quote(os.path.abspath(sys.argv[0]))
        cmd = f"python3 {script}"

    applescript = f'do shell script "{cmd}" with administrator privileges'

    subprocess.run(
        ["osascript", "-e", applescript],
        check=False
    )
    sys.exit(0)

relaunch_as_root()

# =========================
# IMPORTS
# =========================
import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import socket
import ipaddress

# =========================
# NETWORK AUTO-DETECTION
# =========================
def get_network_info():
    output = subprocess.check_output(
        ["ifconfig"],
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    iface = None
    ip = None
    netmask = None

    for line in output.splitlines():
        if not line.startswith("\t") and ":" in line:
            iface = line.split(":")[0]

        if "inet " in line and "127.0.0.1" not in line:
            parts = line.strip().split()
            ip = parts[1]
            mask_hex = parts[3]
            netmask = socket.inet_ntoa(
                int(mask_hex, 16).to_bytes(4, "big")
            )
            return iface, ip, netmask

    raise RuntimeError("Could not detect network interface")


INTERFACE, IP_ADDR, NETMASK = get_network_info()
NETWORK_RANGE = str(ipaddress.IPv4Network(f"{IP_ADDR}/{NETMASK}", strict=False))
TIMEOUT = 2

# =========================
# ROUTER DETECTION
# =========================
def get_default_gateway():
    output = subprocess.check_output(
        ["netstat", "-rn"],
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    for line in output.splitlines():
        if line.startswith("default"):
            return line.split()[1]
    return None

DEFAULT_GATEWAY = get_default_gateway()

# =========================
# DEVICE CLASSIFICATION
# =========================
def is_port_open(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        return sock.connect_ex((ip, port)) == 0
    except:
        return False
    finally:
        sock.close()

def classify_device(ip, mac):
    mac = mac.upper()

    if ip == DEFAULT_GATEWAY:
        return "Router"

    if mac.startswith(("F4:5C:89", "D0:03:4B", "B8:27:EB", "C4:85:08")):
        return "Phone"

    if mac.startswith(("00:1A:79", "BC:AD:28", "AC:CC:8E", "E0:62:67")):
        return "IP Camera"

    if is_port_open(ip, 9100):
        return "Printer"

    if is_port_open(ip, 53) or is_port_open(ip, 67):
        return "Network Device"

    return "Unknown"

# =========================
# NETWORK SCAN
# =========================
def scan_network():
    for row in tree.get_children():
        tree.delete(row)

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=NETWORK_RANGE)

    result = srp(
        packet,
        timeout=TIMEOUT,
        verbose=False,
        iface=INTERFACE
    )[0]

    for _, rcv in result:
        ip = rcv.psrc
        mac = rcv.hwsrc
        dtype = classify_device(ip, mac)
        tree.insert("", "end", values=(ip, mac, dtype))

# =========================
# GUI
# =========================
root = tk.Tk()
root.title("IP Scanner")
root.geometry("650x420")

btn = tk.Button(root, text="Scan Network", command=scan_network)
btn.pack(pady=10)

tree = ttk.Treeview(
    root,
    columns=("IP Address", "MAC Address", "Device Type"),
    show="headings"
)

for col in ("IP Address", "MAC Address", "Device Type"):
    tree.heading(col, text=col)
    tree.column(col, width=200)

tree.pack(expand=True, fill="both", padx=10, pady=10)

root.mainloop()
