import customtkinter as ctk
import threading
import gui_theme as gt
import subprocess
import re
import socket
import time
import requests
import ipaddress
import math
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
import utils

# ==========================================
# HELPERS
# ==========================================

def run_command(cmd):
    try:
        return subprocess.check_output(
            cmd,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW # <--- ADD THIS
        )
    except Exception:
        return ""

def normalize_subnet(subnet_text):
    """
    Accepts:
      192.168.0
      192.168.0.0
      192.168.0.0/24
    Returns IPv4Network or None
    """
    subnet_text = (subnet_text or "").strip()
    if not subnet_text:
        return None

    try:
        if "/" in subnet_text:
            return ipaddress.ip_network(subnet_text, strict=False)

        parts = subnet_text.split(".")
        if len(parts) == 3:
            subnet_text += ".0/24"
        elif len(parts) == 4:
            subnet_text += "/24"
        else:
            return None

        return ipaddress.ip_network(subnet_text, strict=False)
    except ValueError:
        return None


def get_windows_adapters():
    """
    Parse `ipconfig` and return active IPv4 adapters with subnet info.
    """
    output = run_command(["ipconfig"])
    adapters = []

    current_name = None
    current_ip = None
    current_mask = None

    def flush_current():
        nonlocal current_name, current_ip, current_mask, adapters

        if not current_name or not current_ip or not current_mask:
            return

        try:
            ip_obj = ipaddress.ip_address(current_ip)
            network = ipaddress.ip_network(f"{current_ip}/{current_mask}", strict=False)

            # Skip loopback and APIPA
            if ip_obj.is_loopback or str(ip_obj).startswith("169.254."):
                return

            adapters.append({
                "name": current_name,
                "ipv4": current_ip,
                "mask": current_mask,
                "network": network,
                "is_private": ip_obj.is_private
            })
        except Exception:
            pass

    for raw_line in output.splitlines():
        line = raw_line.rstrip()

        # Adapter header, e.g. "Wireless LAN adapter Wi-Fi:"
        if line and not raw_line.startswith(" "):
            if current_name or current_ip or current_mask:
                flush_current()

            current_name = line[:-1] if line.endswith(":") else line
            current_ip = None
            current_mask = None
            continue

        if current_name:
            m_ip = re.search(r"IPv4[^:]*:\s*([\d.]+)", line)
            if m_ip:
                current_ip = m_ip.group(1)

            m_mask = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", line)
            if m_mask:
                current_mask = m_mask.group(1)

    flush_current()

    # Deduplicate by adapter IP
    seen = set()
    unique = []
    for ad in adapters:
        if ad["ipv4"] not in seen:
            seen.add(ad["ipv4"])
            unique.append(ad)

    return unique


def get_default_subnet_text():
    adapters = get_windows_adapters()

    # 1. Prioritize Wi-Fi subnets first (Matches your interface hint logic)
    for ad in adapters:
        if ad["is_private"]:
            name = ad["name"].lower()
            if "wi-fi" in name or "wifi" in name or "wireless" in name:
                return str(ad["network"])
                
    # 2. Prioritize standard physical Ethernet next (Ignore Virtual/VMware adapters)
    for ad in adapters:
        if ad["is_private"]:
            name = ad["name"].lower()
            if "ethernet" in name and "vmware" not in name and "virtual" not in name and "vbox" not in name:
                return str(ad["network"])

    # 3. Fallback to the first private adapter it finds (e.g., your VirtualBox Ethernet 2)
    for ad in adapters:
        if ad["is_private"]:
            return str(ad["network"])

    # 4. Absolute fallback
    if adapters:
        return str(adapters[0]["network"])

    return "192.168.0.0/24"


def get_default_interface_hint():
    adapters = get_windows_adapters()

    for ad in adapters:
        if ad["is_private"]:
            name = ad["name"].lower()
            if "wi-fi" in name or "wifi" in name or "wireless" in name:
                return ad["name"]
    for ad in adapters:
        if ad["is_private"]:
            name = ad["name"].lower()
            if "ethernet" in name:
                return ad["name"]

    return ""


def sweep_ip(ip):
    """
    Use native Windows traffic to encourage ARP resolution.
    Some devices reply to ping, some don't, so we try multiple low-cost methods.
    """
    try:
        subprocess.run(
            ["ping", "-n", "1", "-w", "180", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.sendto(b"\x00", (ip, 137))  # NetBIOS hint
        s.close()
    except Exception:
        pass

    for port in (80, 443, 445):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            s.connect_ex((ip, port))
            s.close()
            break
        except Exception:
            pass


def parse_arp_table():
    """
    Parse `arp -a` and return:
    {
      "192.168.0.5": [
         {"ip": "192.168.0.1", "mac": "AA:BB:CC:DD:EE:FF", "type": "dynamic"},
         ...
      ]
    }
    keyed by interface IP from the ARP output section.
    """
    output = run_command(["arp", "-a"])
    sections = {}
    current_iface = None

    for line in output.splitlines():
        line = line.strip()

        m_iface = re.match(r"Interface:\s+(\d+\.\d+\.\d+\.\d+)\s+---", line, re.IGNORECASE)
        if m_iface:
            current_iface = m_iface.group(1)
            sections.setdefault(current_iface, [])
            continue

        if not current_iface:
            continue

        m_entry = re.match(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]+)\s+(dynamic|static)",
            line,
            re.IGNORECASE
        )
        if m_entry:
            ip = m_entry.group(1)
            mac = m_entry.group(2).replace("-", ":").upper()
            entry_type = m_entry.group(3).lower()
            sections[current_iface].append({
                "ip": ip,
                "mac": mac,
                "type": entry_type
            })

    return sections


_vendor_cache = {}

def lookup_vendor(mac):
    if mac in _vendor_cache:
        return _vendor_cache[mac]

    vendor = "Unknown"
    try:
        res = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if res.status_code == 200 and res.text.strip():
            vendor = res.text.strip()
    except Exception:
        pass

    _vendor_cache[mac] = vendor
    return vendor

def get_hostname(ip):
    """Attempt to resolve the hostname via DNS/NetBIOS."""
    try:
        # gethostbyaddr returns a tuple: (hostname, aliaslist, ipaddrlist)
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"
    except Exception:
        return "Unknown"

def guess_os(ip):
    """
    Estimate the OS family based on Ping TTL.
    This is a heuristic and not 100% accurate, but works natively without Nmap.
    """
    try:
        output = run_command(["ping", "-n", "1", "-w", "500", ip])
        m = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:
                return "Linux / macOS / Android"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Router / Network Device"
        return "Unknown"
    except Exception:
        return "Unknown"


def get_default_gateway():
    """Return the default gateway IP from `route print`."""
    try:
        output = run_command(["route", "print", "0.0.0.0"])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return None


def measure_rtt(ip):
    """Return average ping RTT in ms, or -1 on failure."""
    try:
        output = run_command(["ping", "-n", "2", "-w", "500", ip])
        m = re.search(r"Average\s*=\s*(\d+)\s*ms", output, re.IGNORECASE)
        if m:
            return float(m.group(1))
        # Fallback: try to find any "time=" or "time<" value
        times = re.findall(r"time[<=](\d+)\s*ms", output, re.IGNORECASE)
        if times:
            return sum(float(t) for t in times) / len(times)
    except Exception:
        pass
    return -1

# ==========================================
# LOGIC: NETWORK MAPPER
# ==========================================

def run_arp_scan(interface_filter, log_callback, subnet=None, device_callback=None):
    all_devices = []
    try:
        adapters = get_windows_adapters()

        if not adapters:
            log_callback("❌ No active IPv4 adapters found from ipconfig.")
            log_callback("💡 Make sure you're connected to Wi-Fi or Ethernet.")
            log_callback("-" * 50 + "\n✅ Discovery Complete.")
            if device_callback:
                device_callback([], None)
            return

        requested_network = normalize_subnet(subnet)

        if subnet and not requested_network:
            log_callback(f"❌ Invalid subnet: {subnet}")
            log_callback("💡 Use formats like 192.168.0 or 192.168.0.0/24")
            log_callback("-" * 50 + "\n✅ Discovery Complete.")
            if device_callback:
                device_callback([], None)
            return

        log_callback("🧩 Detected adapters:")
        for ad in adapters:
            priv = "Private" if ad["is_private"] else "Non-private"
            log_callback(f" └ {ad['name']} | IP: {ad['ipv4']} | Net: {ad['network']} [{priv}]")
        log_callback("-" * 50)

        # Adapter selection
        if interface_filter and interface_filter.strip() and interface_filter.lower() != "default":
            selected = [
                ad for ad in adapters
                if interface_filter.lower() in ad["name"].lower()
            ]
            if not selected:
                log_callback(f"❌ No adapter matched interface filter: {interface_filter}")
                log_callback("💡 Try typing part of the name exactly as shown above, like Wi-Fi or Ethernet.")
                log_callback("-" * 50 + "\n✅ Discovery Complete.")
                if device_callback:
                    device_callback([], None)
                return
        else:
            selected = [ad for ad in adapters if ad["is_private"]]
            if not selected:
                selected = adapters

        # If the user gave a subnet, keep only adapters that overlap that subnet
        if requested_network:
            overlap = [ad for ad in selected if ad["network"].overlaps(requested_network)]
            if overlap:
                selected = overlap
            else:
                log_callback(f"⚠️ No local adapter overlaps {requested_network}.")
                log_callback("💡 Scanning with selected adapters anyway may not discover anything on that subnet.")

        all_found = {}
        local_ip = None

        for ad in selected:
            target_network = requested_network if requested_network else ad["network"]
            local_ip = ad["ipv4"]

            # Avoid gigantic accidental scans
            if target_network.num_addresses > 1024:
                log_callback(f"⚠️ {target_network} is large ({target_network.num_addresses} addresses).")
                log_callback("💡 Please use a smaller subnet like /24.")
                continue

            log_callback(f"🛰️ Scanning on adapter: {ad['name']}")
            log_callback(f"🎯 Target subnet: {target_network}")
            log_callback(f"📍 Local adapter IP: {ad['ipv4']}")
            log_callback("⚡ Sweeping hosts to populate ARP table...")

            hosts = [str(ip) for ip in target_network.hosts() if str(ip) != ad["ipv4"]]

            with ThreadPoolExecutor(max_workers=64) as executor:
                executor.map(sweep_ip, hosts)

            time.sleep(1.2)

            arp_sections = parse_arp_table()
            iface_entries = arp_sections.get(ad["ipv4"], [])

            # Fallback: if Windows grouped differently, search all sections
            if not iface_entries:
                for section_entries in arp_sections.values():
                    iface_entries.extend(section_entries)

            found_here = {}

            for entry in iface_entries:
                try:
                    ip_obj = ipaddress.ip_address(entry["ip"])
                    if ip_obj in target_network and entry["ip"] != ad["ipv4"]:
                        found_here[entry["ip"]] = entry["mac"]
                        all_found[entry["ip"]] = entry["mac"]
                except Exception:
                    pass

            if not found_here:
                log_callback("⚠️ No active neighbors found on this adapter/subnet.")
                log_callback("💡 Possible reasons: device sleep, client isolation, or wrong subnet.")
            else:
                log_callback(f"✅ Found {len(found_here)} device(s) on this adapter:")
                for ip in sorted(found_here.keys(), key=lambda x: socket.inet_aton(x)):
                    mac = found_here[ip]
                    vendor = lookup_vendor(mac)
                    log_callback(f" └ IP: {ip:15} | MAC: {mac} [{vendor}]")

            log_callback("-" * 50)

        if all_found:
            log_callback(f"🏁 Total unique devices found: {len(all_found)}")
            # Resolve hostnames and OS in parallel
            log_callback("🔍 Resolving hostnames, OS fingerprints & latency...")

            gateway_ip = get_default_gateway()
            if gateway_ip:
                log_callback(f"🌐 Default gateway: {gateway_ip}")

            def enrich_device(ip_mac):
                ip, mac = ip_mac
                vendor = lookup_vendor(mac)
                hostname = get_hostname(ip)
                os_g = guess_os(ip)
                rtt = measure_rtt(ip)
                is_gw = (ip == gateway_ip) if gateway_ip else False
                # Force router OS for gateway
                if is_gw and os_g == "Unknown":
                    os_g = "Router / Network Device"
                return {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "os_guess": os_g,
                    "rtt_ms": rtt,
                    "is_gateway": is_gw,
                }

            with ThreadPoolExecutor(max_workers=16) as executor:
                all_devices = list(executor.map(enrich_device, all_found.items()))

            log_callback(f"✅ Enriched {len(all_devices)} device(s) with hostname/OS/latency data.")
        else:
            log_callback("⚠️ No devices found on any scanned adapter.")

    except Exception as e:
        log_callback(f"❌ Mapper Error: {e}")

    log_callback("-" * 50 + "\n✅ Discovery Complete.")

    if device_callback:
        device_callback(all_devices, local_ip)


# ==========================================
# UI HELPERS: TOPOLOGY
# ==========================================

OS_COLORS = {
    "Windows":                  "#3d7dd4",
    "Linux / macOS / Android":  "#4caf50",
    "Router / Network Device":  "#e05555",
    "Unknown":                  "#e6a23c",
}

def _os_color(os_guess):
    for key, color in OS_COLORS.items():
        if key.lower() in os_guess.lower():
            return color
    return "#e6a23c"


def _proximity_label(rtt):
    """Human-friendly distance estimate from RTT."""
    if rtt < 0:
        return "Unknown"
    if rtt <= 1:
        return "Very Close (same switch)"
    if rtt <= 3:
        return "Close (local network)"
    if rtt <= 10:
        return "Nearby"
    if rtt <= 50:
        return "Moderate distance"
    return "Far away"


class _CanvasTooltip:
    """Floating tooltip that follows the mouse over canvas items."""

    def __init__(self, canvas):
        self._canvas = canvas
        self._tw = None

    def show(self, event, text):
        self.hide()
        tw = tk.Toplevel(self._canvas)
        tw.wm_overrideredirect(True)
        tw.wm_attributes("-topmost", True)
        tw.configure(bg="#1a1a22")
        x = event.x_root + 14
        y = event.y_root + 10
        tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            tw, text=text, justify="left",
            bg="#1a1a22", fg="#d8d8e0",
            font=("Consolas", 10),
            padx=10, pady=6,
            relief="solid", borderwidth=1,
            highlightbackground="#3d7dd4",
        )
        lbl.pack()
        self._tw = tw

    def hide(self):
        if self._tw:
            self._tw.destroy()
            self._tw = None


def _draw_topology(canvas, devices, local_ip, scale=1.0, offset=(0, 0), tooltip=None):
    """Draw a radial network topology on *canvas* with RTT-based distance."""
    canvas.delete("all")

    w = canvas.winfo_width() or 700
    h = canvas.winfo_height() or 450
    cx = w / 2 + offset[0]
    cy = h / 2 + offset[1]

    # ----- background concentric rings with distance labels -----
    ring_labels = ["< 1ms", "1-3ms", "3-10ms", "10-50ms", "50ms+"]
    for i, r_base in enumerate(range(60, 380, 70)):
        r = r_base * scale
        canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                           outline="#2a2a34", width=1, dash=(3, 6))
        if i < len(ring_labels):
            canvas.create_text(cx + r - 4, cy - 6, text=ring_labels[i],
                               anchor="e", fill="#3a3a48",
                               font=("Consolas", 7))

    # ----- central node (YOU) -----
    cr = int(28 * scale)
    if cr < 12:
        cr = 12
    canvas.create_oval(cx - cr, cy - cr, cx + cr, cy + cr,
                       fill="#3d7dd4", outline="#5c9fd4", width=2,
                       tags="center_node")
    label_text = f"You ({local_ip})" if local_ip else "You"
    canvas.create_text(cx, cy + cr + 14 * scale,
                       text=label_text, fill="#8cb8e8",
                       font=("Consolas", max(8, int(10 * scale)), "bold"))
    canvas.create_text(cx, cy,
                       text="⬢", fill="#d8d8e0",
                       font=("Segoe UI", max(10, int(16 * scale)), "bold"))

    if not devices:
        canvas.create_text(cx, cy + cr + 42,
                           text="No devices discovered yet — run a scan.",
                           fill="#6a6a7a", font=("Segoe UI", 12))
        return

    # ----- separate gateway from other devices -----
    gateway = None
    others = []
    for dev in devices:
        if dev.get("is_gateway"):
            gateway = dev
        else:
            others.append(dev)

    # ----- compute RTT-based radius for each device -----
    # Map RTT to a radius: low RTT = close to center, high RTT = far
    max_radius = min(w, h) * 0.42 * scale
    min_radius = 80 * scale

    def rtt_to_radius(rtt):
        if rtt < 0:
            return max_radius * 0.7  # unknown → medium distance
        # Log scale: 0ms→min_radius, 100ms+→max_radius
        clamped = max(0.1, min(rtt, 100))
        t = math.log10(clamped + 1) / math.log10(101)
        return min_radius + t * (max_radius - min_radius)

    node_r = int(18 * scale)
    if node_r < 8:
        node_r = 8

    if tooltip is None:
        tooltip = _CanvasTooltip(canvas)
    tooltip.hide()

    # ----- draw gateway node (between you and devices) -----
    if gateway:
        gw_r = int(24 * scale)
        if gw_r < 10:
            gw_r = 10
        gw_radius = rtt_to_radius(gateway.get("rtt_ms", -1))
        gw_angle = -math.pi / 2  # top
        gw_x = cx + gw_radius * 0.5 * math.cos(gw_angle)
        gw_y = cy + gw_radius * 0.5 * math.sin(gw_angle)

        # Line from you to router
        canvas.create_line(cx, cy, gw_x, gw_y,
                           fill="#e05555", width=3, dash=(6, 3))

        # Glow
        glow = gw_r + 8
        canvas.create_oval(gw_x - glow, gw_y - glow, gw_x + glow, gw_y + glow,
                           fill="", outline="#e05555", width=2, dash=(3, 4))

        # Router node
        canvas.create_oval(gw_x - gw_r, gw_y - gw_r, gw_x + gw_r, gw_y + gw_r,
                           fill="#e05555", outline="#ff7777", width=2,
                           tags="gateway_node")

        canvas.create_text(gw_x, gw_y, text="📡",
                           font=("Segoe UI", 12), anchor="center")

        rtt_val = gateway.get("rtt_ms", -1)
        rtt_str = f"{rtt_val:.0f}ms" if rtt_val >= 0 else "N/A"
        canvas.create_text(gw_x, gw_y + gw_r + 12 * scale,
                           text=f"🌐 Router ({gateway['ip']})",
                           fill="#ff9999",
                           font=("Consolas", max(8, int(10 * scale)), "bold"))
        canvas.create_text(gw_x, gw_y + gw_r + 25 * scale,
                           text=f"RTT: {rtt_str} — {_proximity_label(rtt_val)}",
                           fill="#9898a8",
                           font=("Consolas", max(7, int(8 * scale))))

        # Gateway tooltip
        gw_tip = (
            f"🌐 DEFAULT GATEWAY / ROUTER\n"
            f"IP:        {gateway['ip']}\n"
            f"MAC:       {gateway['mac']}\n"
            f"Vendor:    {gateway.get('vendor', 'Unknown')}\n"
            f"Hostname:  {gateway.get('hostname', 'Unknown')}\n"
            f"RTT:       {rtt_str}\n"
            f"Proximity: {_proximity_label(rtt_val)}"
        )

        def _gw_enter(evt, t=gw_tip):
            tooltip.show(evt, t)
        def _gw_leave(evt):
            tooltip.hide()
        def _gw_motion(evt, t=gw_tip):
            tooltip.show(evt, t)

        canvas.tag_bind("gateway_node", "<Enter>", _gw_enter)
        canvas.tag_bind("gateway_node", "<Leave>", _gw_leave)
        canvas.tag_bind("gateway_node", "<Motion>", _gw_motion)

    # ----- device nodes -----
    n = len(others)
    if n == 0:
        # Only gateway, no other devices
        pass
    else:
        devices_sorted = sorted(others, key=lambda d: socket.inet_aton(d["ip"]))

        for i, dev in enumerate(devices_sorted):
            angle = (2 * math.pi * i / n) - math.pi / 2
            # Skip the gateway angle region if gateway exists
            if gateway:
                angle = (2 * math.pi * i / n)  # start from right

            dev_radius = rtt_to_radius(dev.get("rtt_ms", -1))
            nx = cx + dev_radius * math.cos(angle)
            ny = cy + dev_radius * math.sin(angle)

            color = _os_color(dev.get("os_guess", "Unknown"))

            # Connection line — to gateway if it exists, otherwise to center
            if gateway:
                gw_radius_val = rtt_to_radius(gateway.get("rtt_ms", -1))
                gw_angle_val = -math.pi / 2
                gw_lx = cx + gw_radius_val * 0.5 * math.cos(gw_angle_val)
                gw_ly = cy + gw_radius_val * 0.5 * math.sin(gw_angle_val)
                canvas.create_line(gw_lx, gw_ly, nx, ny,
                                   fill="#2e3a4a", width=1, dash=(4, 4))
            else:
                canvas.create_line(cx, cy, nx, ny,
                                   fill="#2e3a4a", width=2, dash=(5, 3))

            # Glow circle
            glow_r = node_r + int(5 * scale)
            canvas.create_oval(nx - glow_r, ny - glow_r, nx + glow_r, ny + glow_r,
                               fill="", outline=color, width=1, dash=(2, 4))

            # Main node circle
            tag = f"node_{i}"
            canvas.create_oval(nx - node_r, ny - node_r, nx + node_r, ny + node_r,
                               fill=color, outline="#1a1a22", width=2, tags=tag)

            # Hostname or IP label
            hostname = dev.get("hostname", "Unknown")
            short_label = dev["ip"]
            if hostname and hostname != "Unknown":
                short_label = hostname.split(".")[0]
                if len(short_label) > 14:
                    short_label = short_label[:12] + "…"

            fs_label = max(7, int(9 * scale))
            fs_sub = max(6, int(8 * scale))

            canvas.create_text(nx, ny + node_r + 12 * scale,
                               text=short_label, fill="#c0c0cc",
                               font=("Consolas", fs_label))
            if hostname and hostname != "Unknown":
                canvas.create_text(nx, ny + node_r + 24 * scale,
                                   text=dev["ip"], fill="#6a6a7a",
                                   font=("Consolas", fs_sub))

            # RTT distance label
            rtt_val = dev.get("rtt_ms", -1)
            rtt_str = f"{rtt_val:.0f}ms" if rtt_val >= 0 else ""
            if rtt_str:
                canvas.create_text(nx, ny - node_r - 8 * scale,
                                   text=rtt_str, fill="#5a5a6a",
                                   font=("Consolas", max(6, int(7 * scale))))

            # Icon inside node
            os_icon = "🖥"
            os_g = dev.get("os_guess", "").lower()
            if "router" in os_g or "network" in os_g:
                os_icon = "📡"
            elif "linux" in os_g or "android" in os_g or "mac" in os_g:
                os_icon = "🐧"
            elif "windows" in os_g:
                os_icon = "🖥"
            canvas.create_text(nx, ny, text=os_icon,
                               font=("Segoe UI", 11), anchor="center")

            # Tooltip
            prox = _proximity_label(rtt_val)
            tip_text = (
                f"IP:        {dev['ip']}\n"
                f"MAC:       {dev['mac']}\n"
                f"Vendor:    {dev.get('vendor', 'Unknown')}\n"
                f"Hostname:  {dev.get('hostname', 'Unknown')}\n"
                f"OS Guess:  {dev.get('os_guess', 'Unknown')}\n"
                f"RTT:       {rtt_str if rtt_str else 'N/A'}\n"
                f"Proximity: {prox}"
            )

            def _enter(evt, t=tip_text):
                tooltip.show(evt, t)
            def _leave(evt):
                tooltip.hide()
            def _motion(evt, t=tip_text):
                tooltip.show(evt, t)

            canvas.tag_bind(tag, "<Enter>", _enter)
            canvas.tag_bind(tag, "<Leave>", _leave)
            canvas.tag_bind(tag, "<Motion>", _motion)

    # ----- legend -----
    lx, ly = 14, h - 110
    canvas.create_text(lx, ly, text="Legend", anchor="w",
                       fill="#8888a0", font=("Segoe UI", 10, "bold"))
    for j, (os_name, clr) in enumerate(OS_COLORS.items()):
        yy = ly + 18 + j * 18
        canvas.create_oval(lx, yy - 5, lx + 10, yy + 5, fill=clr, outline="")
        canvas.create_text(lx + 16, yy, text=os_name, anchor="w",
                           fill="#9898a8", font=("Segoe UI", 9))
    # Proximity note
    py = ly + 18 + len(OS_COLORS) * 18 + 4
    canvas.create_text(lx, py, text="📏 Distance = ping latency",
                       anchor="w", fill="#5a5a6a", font=("Segoe UI", 8))


# ==========================================
# UI: NETWORK MAPPER FRAME
# ==========================================

def create_netmapper_frame(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")

    gt.section_header(
        frame,
        "Network Mapper",
        "Windows-native ARP discovery with adapter detection.",
    ).pack(anchor="w", pady=(0, 14))

    # --- Controls card ---
    card = gt.control_card(frame)
    card.pack(fill="x", pady=(0, 12))
    ctrl = ctk.CTkFrame(card, fg_color="transparent")
    ctrl.pack(fill="x", padx=14, pady=12)

    ent_iface = gt.create_styled_entry(
        ctrl,
        width=220,
        placeholder_text="Interface filter (e.g. Wi-Fi)"
    )
    default_iface = get_default_interface_hint()
    if default_iface:
        ent_iface.insert(0, default_iface)
    ent_iface.pack(side="left", padx=(0, 10))

    ent_subnet = gt.create_styled_entry(
        ctrl,
        width=240,
        placeholder_text="Subnet (e.g. 192.168.0.0/24)"
    )
    ent_subnet.insert(0, get_default_subnet_text())
    ent_subnet.pack(side="left", padx=(0, 10))

    # --- Tabview: Log + Topology ---
    tabview = ctk.CTkTabview(
        frame,
        fg_color=gt.CARD_BG,
        segmented_button_fg_color="#1a1a22",
        segmented_button_selected_color=gt.ACCENT_BLUE,
        segmented_button_unselected_color="#2a2a34",
        segmented_button_selected_hover_color=gt.ACCENT_BLUE_HOVER,
        segmented_button_unselected_hover_color="#3a3a44",
        corner_radius=14,
        border_width=1,
        border_color=gt.CARD_BORDER,
    )

    tab_log = tabview.add("  📋 Log  ")
    tab_topo = tabview.add("  🗺️ Topology  ")

    # Log tab
    txt_log = gt.create_log_textbox(tab_log)
    txt_log.pack(fill="both", expand=True, padx=4, pady=4)

    # Topology tab
    canvas_frame = ctk.CTkFrame(tab_topo, fg_color="#14141a", corner_radius=12)
    canvas_frame.pack(fill="both", expand=True, padx=4, pady=4)

    topo_canvas = tk.Canvas(
        canvas_frame, bg="#14141a",
        highlightthickness=0, bd=0,
    )
    topo_canvas.pack(fill="both", expand=True)

    # Single shared tooltip — created once, reused across redraws
    _shared_tooltip = _CanvasTooltip(topo_canvas)

    # --- Zoom / Pan state ---
    _state = {
        "devices": [],
        "local_ip": None,
        "scale": 1.0,
        "offset_x": 0.0,
        "offset_y": 0.0,
        "drag_start_x": 0,
        "drag_start_y": 0,
    }

    def _redraw():
        _shared_tooltip.hide()
        _draw_topology(
            topo_canvas, _state["devices"], _state["local_ip"],
            scale=_state["scale"],
            offset=(_state["offset_x"], _state["offset_y"]),
            tooltip=_shared_tooltip,
        )
        # Zoom indicator (top-right, drawn after topology)
        w = topo_canvas.winfo_width() or 700
        pct = int(_state["scale"] * 100)
        topo_canvas.create_text(
            w - 14, 18,
            text=f"🔍 {pct}%", anchor="e",
            fill="#6a6a7a", font=("Consolas", 10, "bold"),
        )
        topo_canvas.create_text(
            w - 14, 34,
            text="Scroll to zoom · Drag to pan · Dbl-click to reset", anchor="e",
            fill="#3a3a48", font=("Consolas", 8),
        )

    def _on_canvas_resize(event):
        if _state["devices"] or _state["local_ip"]:
            _redraw()

    def _on_mouse_wheel(event):
        # Windows: event.delta is ±120 per notch
        if event.delta > 0:
            _state["scale"] = min(3.0, _state["scale"] * 1.15)
        else:
            _state["scale"] = max(0.3, _state["scale"] / 1.15)
        _redraw()

    def _on_drag_start(event):
        _state["drag_start_x"] = event.x
        _state["drag_start_y"] = event.y

    def _on_drag_move(event):
        dx = event.x - _state["drag_start_x"]
        dy = event.y - _state["drag_start_y"]
        _state["offset_x"] += dx
        _state["offset_y"] += dy
        _state["drag_start_x"] = event.x
        _state["drag_start_y"] = event.y
        _redraw()

    def _on_double_click(event):
        _state["scale"] = 1.0
        _state["offset_x"] = 0.0
        _state["offset_y"] = 0.0
        _redraw()

    topo_canvas.bind("<Configure>", _on_canvas_resize)
    topo_canvas.bind("<MouseWheel>", _on_mouse_wheel)
    topo_canvas.bind("<ButtonPress-1>", _on_drag_start)
    topo_canvas.bind("<B1-Motion>", _on_drag_move)
    topo_canvas.bind("<Double-Button-1>", _on_double_click)
    topo_canvas.bind("<Leave>", lambda e: _shared_tooltip.hide())

    def log_msg(message):
        txt_log.after(0, lambda: txt_log.insert("end", message + "\n"))
        txt_log.after(0, lambda: txt_log.see("end"))

    def on_devices_ready(devices, local_ip):
        """Called from scan thread when enrichment is done."""
        _state["devices"] = devices
        _state["local_ip"] = local_ip
        _state["scale"] = 1.0
        _state["offset_x"] = 0.0
        _state["offset_y"] = 0.0

        def _draw():
            _redraw()
            tabview.set("  🗺️ Topology  ")

        topo_canvas.after(100, _draw)

    def start_scan():
        txt_log.delete("1.0", "end")
        iface = ent_iface.get().strip()
        subnet_text = ent_subnet.get().strip()
        threading.Thread(
            target=run_arp_scan,
            args=(iface, log_msg, subnet_text, on_devices_ready),
            daemon=True
        ).start()

    ctk.CTkButton(
        ctrl,
        text="Refresh Map",
        width=120,
        height=38,
        corner_radius=12,
        font=gt.FONT_BTN,
        fg_color=gt.ACCENT_BLUE,
        hover_color=gt.ACCENT_BLUE_HOVER,
        command=start_scan,
    ).pack(side="left")

    ctk.CTkButton(
        ctrl,
        text="Export Report",
        width=120,
        height=38,
        corner_radius=12,
        font=gt.FONT_BTN,
        fg_color="#333333",
        hover_color="#444444",
        command=lambda: utils.export_log(txt_log.get("1.0", "end"), "Network_Map")
    ).pack(side="right", padx=(10, 0))

    tabview.pack(fill="both", expand=True, pady=(4, 0))

    frame.after(1000, start_scan)

    return frame