#!/usr/bin/env python3
"""
Dead Man's Switch - Network Intruder Detection Tool
Author: You
Description: Scans your local network using ARP, compares found devices
             against a whitelist, logs intruders, and optionally sends email alerts.
"""

import csv
import json
import os
import smtplib
import socket
import subprocess
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ─── Try to import scapy (preferred) or fall back to nmap ───────────────────
try:
    from scapy.all import ARP, Ether, srp
    SCAN_ENGINE = "scapy"
except ImportError:
    try:
        import nmap
        SCAN_ENGINE = "nmap"
    except ImportError:
        SCAN_ENGINE = "none"
        print("[WARNING] Neither scapy nor python-nmap is installed.")
        print("          Install one:  pip install scapy   OR   pip install python-nmap")


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIG  ─ edit these values before running
# ═══════════════════════════════════════════════════════════════════════════════
CONFIG = {
    # Network range to scan – adjust to match your router's subnet
    "network_range": "192.168.0.0/24",

    # File paths
    "whitelist_file": "known_devices.txt",
    "log_file":       "intruder_log.csv",
    "scan_history":   "scan_history.json",

    # How often to scan (seconds).  3600 = every hour
    "scan_interval":  3600,

    # ── Email alert settings (optional) ──────────────────────────────────────
    "email_alerts": True,          # Set True to enable
    "smtp_server":  "smtp.gmail.com",
    "smtp_port":    587,
    "sender_email": "sharmayash6006@gmail.com",
    "sender_password": "adfs vewv jnbw gsnm",   # Use a Gmail App Password, NOT your real password
    "recipient_email": "sharmayash6006@gmail.com",
}
# ═══════════════════════════════════════════════════════════════════════════════


# ──────────────────────────────────────────────────────────────────────────────
#  UTILITY HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Detect the machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def auto_detect_network_range() -> str:
    """Attempt to auto-detect the /24 subnet from the local IP."""
    local_ip = get_local_ip()
    parts = local_ip.rsplit(".", 1)
    return f"{parts[0]}.0/24"


def normalize_mac(mac: str) -> str:
    """Lowercase and strip whitespace from a MAC address."""
    return mac.strip().lower()


# ──────────────────────────────────────────────────────────────────────────────
#  WHITELIST MANAGEMENT
# ──────────────────────────────────────────────────────────────────────────────

def load_whitelist(path: str) -> set:
    """
    Load MAC addresses from the whitelist file.
    Lines starting with '#' are comments and are ignored.
    """
    whitelist = set()
    if not os.path.exists(path):
        print(f"[INFO] Whitelist file '{path}' not found – creating a blank one.")
        print("       Add your devices' MAC addresses to it (one per line).")
        with open(path, "w") as f:
            f.write("# Dead Man's Switch – Whitelist of known/trusted devices\n")
            f.write("# Format: one MAC address per line (e.g. aa:bb:cc:dd:ee:ff)\n")
            f.write("# Lines starting with '#' are comments.\n\n")
        return whitelist

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                whitelist.add(normalize_mac(line))

    print(f"[✓] Whitelist loaded – {len(whitelist)} known device(s).")
    return whitelist


def add_to_whitelist(mac: str, path: str):
    """Append a new MAC address to the whitelist file."""
    mac = normalize_mac(mac)
    with open(path, "a") as f:
        f.write(f"{mac}\n")
    print(f"[+] Added {mac} to whitelist.")


# ──────────────────────────────────────────────────────────────────────────────
#  NETWORK SCANNING
# ──────────────────────────────────────────────────────────────────────────────

def scan_with_scapy(network_range: str) -> list:
    """
    ARP scan using Scapy.
    Returns a list of dicts: [{"ip": ..., "mac": ...}, ...]
    """
    print(f"[→] Scanning {network_range} with Scapy (ARP)…")
    arp_request = ARP(pdst=network_range)
    broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet      = broadcast / arp_request

    answered, _ = srp(packet, timeout=3, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({
            "ip":  received.psrc,
            "mac": normalize_mac(received.hwsrc),
        })
    return devices


def scan_with_nmap(network_range: str) -> list:
    """
    ARP/ping scan using python-nmap.
    Returns a list of dicts: [{"ip": ..., "mac": ...}, ...]
    """
    print(f"[→] Scanning {network_range} with Nmap…")
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments="-sn")   # ping scan

    devices = []
    for host in nm.all_hosts():
        mac = "unknown"
        if "addresses" in nm[host] and "mac" in nm[host]["addresses"]:
            mac = normalize_mac(nm[host]["addresses"]["mac"])
        devices.append({"ip": host, "mac": mac})
    return devices


def scan_with_arp_command(network_range: str) -> list:
    """
    Fallback: parse the ARP table using the system `arp -a` command.
    Note: only shows devices the OS has recently communicated with.
    """
    print("[→] Falling back to system ARP table (limited accuracy)…")
    devices = []
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip  = parts[1].strip("()")
                mac = normalize_mac(parts[3])
                if ":" in mac and mac != "<incomplete>":
                    devices.append({"ip": ip, "mac": mac})
    except Exception as e:
        print(f"[ERROR] ARP command failed: {e}")
    return devices


def scan_network(network_range: str) -> list:
    """Choose the best available scan engine and return discovered devices."""
    if SCAN_ENGINE == "scapy":
        return scan_with_scapy(network_range)
    elif SCAN_ENGINE == "nmap":
        return scan_with_nmap(network_range)
    else:
        return scan_with_arp_command(network_range)


# ──────────────────────────────────────────────────────────────────────────────
#  INTRUDER DETECTION & LOGGING
# ──────────────────────────────────────────────────────────────────────────────

def check_intruders(devices: list, whitelist: set) -> list:
    """Compare scanned devices against whitelist. Return a list of intruders."""
    intruders = []
    for device in devices:
        if device["mac"] not in whitelist and device["mac"] != "unknown":
            intruders.append(device)
    return intruders


def log_intruder(device: dict, log_file: str):
    """Append an intruder record to the CSV log file."""
    file_exists = os.path.exists(log_file)
    with open(log_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "ip", "mac"])
        if not file_exists:
            writer.writeheader()   # write column headers on first run
        writer.writerow({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip":        device["ip"],
            "mac":       device["mac"],
        })


def save_scan_history(devices: list, history_file: str):
    """Save the latest scan result to a JSON file for reference."""
    history = []
    if os.path.exists(history_file):
        with open(history_file, "r") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []

    history.append({
        "scan_time": datetime.now().isoformat(),
        "devices":   devices,
    })

    # Keep only the last 50 scans
    history = history[-50:]

    with open(history_file, "w") as f:
        json.dump(history, f, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
#  EMAIL ALERTS
# ──────────────────────────────────────────────────────────────────────────────

def send_email_alert(intruders: list, config: dict):
    """Send an email alert listing all detected intruders."""
    if not config.get("email_alerts"):
        return

    subject = f"⚠ INTRUDER ALERT – {len(intruders)} Unknown Device(s) Detected!"
    body_lines = [
        "Dead Man's Switch – Network Intruder Alert",
        "=" * 45,
        f"Scan time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Network   : {config['network_range']}",
        "",
        "UNKNOWN DEVICES FOUND:",
    ]
    for d in intruders:
        body_lines.append(f"  • IP: {d['ip']}   MAC: {d['mac']}")

    body_lines += [
        "",
        "Check your router's admin panel for more details.",
        "Consider blocking the device if you do not recognise it.",
    ]
    body = "\n".join(body_lines)

    msg = MIMEMultipart()
    msg["From"]    = config["sender_email"]
    msg["To"]      = config["recipient_email"]
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(config["smtp_server"], config["smtp_port"]) as server:
            server.starttls()
            server.login(config["sender_email"], config["sender_password"])
            server.sendmail(config["sender_email"], config["recipient_email"], msg.as_string())
        print("[✉] Email alert sent successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")


# ──────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    banner = r"""
  ____                _   __  __             _
 |  _ \  ___  __ _  __| | |  \/  | __ _ _ __( )___
 | | | |/ _ \/ _` |/ _` | | |\/| |/ _` | '_ \// __|
 | |_| |  __/ (_| | (_| | | |  | | (_| | | | | \__ \
 |____/ \___|\__,_|\__,_| |_|  |_|\__,_|_| |_| |___/

         Switch  —  Network Intruder Detection
    """
    print(banner)


def run_single_scan(config: dict):
    """Execute one full scan cycle."""
    print(f"\n{'─'*55}")
    print(f"  Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*55}")

    whitelist = load_whitelist(config["whitelist_file"])
    devices   = scan_network(config["network_range"])

    print(f"[✓] {len(devices)} device(s) found on the network.")

    # Print all found devices
    for d in devices:
        tag = "✓ KNOWN" if d["mac"] in whitelist else "⚠ UNKNOWN"
        print(f"    {tag:<12}  IP: {d['ip']:<18}  MAC: {d['mac']}")

    # Check for intruders
    intruders = check_intruders(devices, whitelist)

    if intruders:
        print(f"\n  🚨  {len(intruders)} INTRUDER(S) DETECTED!")
        for d in intruders:
            print(f"      IP: {d['ip']}   MAC: {d['mac']}")
            log_intruder(d, config["log_file"])

        send_email_alert(intruders, config)
        print(f"  [✓] Intruder(s) logged to '{config['log_file']}'")
    else:
        print("\n  [✓] All clear – no unknown devices found.")

    save_scan_history(devices, config["scan_history"])
    return intruders


def continuous_monitor(config: dict):
    """Run scans on a repeating schedule (every scan_interval seconds)."""
    print_banner()
    print(f"  Monitoring: {config['network_range']}")
    print(f"  Interval  : every {config['scan_interval']}s ({config['scan_interval']//60} min)")
    print(f"  Log file  : {config['log_file']}")
    print(f"  Engine    : {SCAN_ENGINE}")

    total_intruders = 0
    scan_count = 0

    try:
        while True:
            scan_count += 1
            print(f"\n  [Scan #{scan_count}]")
            found = run_single_scan(config)
            total_intruders += len(found)

            print(f"\n  Next scan in {config['scan_interval']}s … (Ctrl+C to stop)")
            time.sleep(config["scan_interval"])

    except KeyboardInterrupt:
        print(f"\n\n  Monitoring stopped by user.")
        print(f"  Total scans     : {scan_count}")
        print(f"  Total intruders : {total_intruders}")


# ──────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dead Man's Switch – Network Monitor")
    parser.add_argument("--scan-once",  action="store_true", help="Run one scan and exit")
    parser.add_argument("--add-device", metavar="MAC",       help="Add a MAC address to the whitelist")
    parser.add_argument("--show-log",   action="store_true", help="Print the intruder log")
    parser.add_argument("--network",    metavar="CIDR",      help="Override network range (e.g. 192.168.0.0/24)")
    parser.add_argument("--auto-range", action="store_true", help="Auto-detect network range")
    args = parser.parse_args()

    # Apply CLI overrides
    if args.network:
        CONFIG["network_range"] = args.network
    if args.auto_range:
        CONFIG["network_range"] = auto_detect_network_range()
        print(f"[Auto] Detected network range: {CONFIG['network_range']}")

    # Sub-commands
    if args.add_device:
        add_to_whitelist(args.add_device, CONFIG["whitelist_file"])

    elif args.show_log:
        if os.path.exists(CONFIG["log_file"]):
            with open(CONFIG["log_file"]) as f:
                print(f.read())
        else:
            print("No intruder log found yet.")

    elif args.scan_once:
        print_banner()
        run_single_scan(CONFIG)

    else:
        continuous_monitor(CONFIG)
