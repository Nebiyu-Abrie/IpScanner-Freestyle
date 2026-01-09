import tkinter as tk
from tkinter import ttk
import socket
import ipaddress
import subprocess
import re
from scapy.all import ARP, Ether, srp, conf

# Force Scapy to use Npcap
conf.use_pcap = True

# =========================
# NETWORK AUTO-DETECTION
# =========================
def get_network_range():
    """
    Detect active IPv4 network and subnet using Windows ipconfig
    """
    output = subprocess.check_output("ipconfig", text=True, encoding="utf-8", errors="ignore")

    ip = None
    mask = None

    for line in output.splitlines():
        if "IPv4 Address" in line or "IPv4-Adresse" in line:
            ip = line.split(":")[-1].strip()
        if "Subnet Mask" in line or "Subnetzmaske" in line:
            mask = line.split(":")[-1].strip()

        if ip and mask:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return str(network)

    raise RuntimeError("Could not detect network range")


NETWORK_RANGE = get_network_range()
TIMEOUT = 2

# =========================
# DEVICE TYPE GUESSING
# =========================
def guess_device_type(mac):
    mac = mac.upper()

    if mac.startswith(("00:1A:4B", "3C:2A:F4", "BC:AE:C5")):
        return "Printer"
    if mac.startswith(("C8:3A:35", "FC:FB:FB", "44:D9:E7")):
        return "Access Point"
    if mac.startswith(("D8:3A:DD", "F0:99:BF", "A4:83:E7")):
        return "Computer / Phone"
    if mac.startswith(("00:15:6D", "24:A4:3C", "74:83:C2")):
        return "Camera Device"

    return "Unknown"


# =========================
# PORT CHECKING
# =========================
def is_port_open(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def improve_guess(ip, dtype):
    if dtype == "Unknown":
        if is_port_open(ip, 9100):
            return "Printer"
        if is_port_open(ip, 80) or is_port_open(ip, 443):
            return "Network Device / AP"
    return dtype


# =========================
# NETWORK SCAN FUNCTION
# =========================
def scan_network():
    for row in tree.get_children():
        tree.delete(row)

    arp = ARP(pdst=NETWORK_RANGE)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # DO NOT force iface on Windows
    result = srp(packet, timeout=TIMEOUT, verbose=False)[0]

    for _, received in result:
        ip = received.psrc
        mac = received.hwsrc
        dtype = improve_guess(ip, guess_device_type(mac))
        tree.insert("", "end", values=(ip, mac, dtype))


# =========================
# GUI SETUP
# =========================
root = tk.Tk()
root.title("Simple Network Scanner (Windows)")
root.geometry("600x400")

btn = tk.Button(root, text="Scan Network", command=scan_network)
btn.pack(pady=10)

columns = ("IP Address", "MAC Address", "Device Type")
tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=180)

tree.pack(expand=True, fill="both", padx=10, pady=10)

root.mainloop()
