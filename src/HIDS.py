import customtkinter as ctk
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, conf
from scapy.interfaces import IFACES
import threading
import time
import socket
from collections import defaultdict
from datetime import datetime
import os
import ctypes
import ipaddress
import json
import math
import tkinter as tk
import requests
import gui_theme as gt
import utils
import re

# ==========================================
# DETECTION ENGINE
# ==========================================

# Well-known suspicious ports
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    5555: "Android ADB",
    1337: "Elite/backdoor",
    31337: "Back Orifice",
    6667: "IRC (C2 channel)",
    6697: "IRC/SSL (C2)",
    8080: "HTTP Proxy",
    9090: "Web proxy",
    1080: "SOCKS Proxy",
    3127: "MyDoom backdoor",
    12345: "NetBus trojan",
    27374: "Sub7 trojan",
    65535: "Common scan target",
}


class HIDSEngine:
    """Packet-level intrusion detection engine with multiple threat detectors."""

    _SEV_RANK = {"critical": 4, "medium": 2, "low": 1, "info": 0}

    def __init__(self, on_alert, on_stat):
        self.on_alert = on_alert   # callback(severity, category, message)
        self.on_stat = on_stat     # callback(stats_dict)

        self.is_sniffing = False
        self.sniffer = None
        self.lock = threading.RLock()

        # Thresholds
        self.TIME_WINDOW = 5       # seconds per analysis window
        self.SYN_THRESHOLD = 20
        self.PORT_THRESHOLD = 15
        self.CONN_THRESHOLD = 100
        self.DNS_THRESHOLD = 30
        self.ARP_THRESHOLD = 20

        # Tracking (reset each time window)
        self.syn_counts = defaultdict(int)
        self.port_scans = defaultdict(set)
        self.conn_counts = defaultdict(int)
        self.dns_counts = defaultdict(int)
        self.arp_counts = defaultdict(int)
        self.alerted = defaultdict(set)
        self.last_reset = time.time()

        # Stats
        self.total_packets = 0
        self.total_alerts = 0
        self.alert_breakdown = defaultdict(int)
        self.start_time = None
        self._stats_timer = None

        # DNS cache (ip -> display string)
        self._dns_cache = {}

        # Route trace tracking
        self.external_ips = set()
        self.ip_packet_counts = defaultdict(int)
        self.ip_max_severity = {}

        # Error tracking
        self._error_count = 0
        self._last_error_time = 0
        self._restart_count = 0
        self._current_iface = None

        # Available interfaces
        self.interfaces = self._get_interfaces()

    # --- Interface discovery ---
    def _get_interfaces(self):
        try:
            clean = []
            for iface in IFACES.values():
                name = str(iface.name)
                if name and name != "unknown" and "Pseudo-Interface" not in name:
                    if name not in clean:
                        clean.append(name)
            return clean if clean else ["Software Loopback Interface 1"]
        except Exception:
            return ["Wi-Fi", "Ethernet"]

    def get_default_interface(self):
        for keyword in ["Wi-Fi", "Ethernet", "Loopback"]:
            for iface in self.interfaces:
                if keyword.lower() in iface.lower():
                    return iface
        return self.interfaces[0] if self.interfaces else ""

    # --- DNS resolution (non-blocking) ---
    def _resolve(self, ip):
        """Return cached hostname or raw IP. Never blocks the sniffer thread."""
        cached = self._dns_cache.get(ip)
        if cached:
            return cached
        # Schedule async resolution, return raw IP for now
        self._dns_cache[ip] = ip  # prevent re-scheduling
        threading.Thread(target=self._do_resolve, args=(ip,), daemon=True).start()
        return ip

    def _do_resolve(self, ip):
        """Background DNS resolution with 1s timeout."""
        try:
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)
            hostname = socket.gethostbyaddr(ip)[0]
            socket.setdefaulttimeout(old)
            self._dns_cache[ip] = f"{ip} ({hostname})"
        except Exception:
            try:
                socket.setdefaulttimeout(None)
            except Exception:
                pass
            self._dns_cache[ip] = ip

    # --- Tracker reset ---
    def _reset_window(self):
        with self.lock:
            self.syn_counts.clear()
            self.port_scans.clear()
            self.conn_counts.clear()
            self.dns_counts.clear()
            self.arp_counts.clear()
            self.alerted.clear()
            self.last_reset = time.time()

    # --- Stats push + sniffer watchdog ---
    def _stats_loop(self):
        """Push stats every 2 seconds. Also monitors sniffer health."""
        if not self.is_sniffing:
            return

        # --- Watchdog: check if sniffer thread is still alive ---
        try:
            sniffer_alive = (
                self.sniffer is not None
                and hasattr(self.sniffer, 'thread')
                and self.sniffer.thread is not None
                and self.sniffer.thread.is_alive()
            )
            if not sniffer_alive and self.is_sniffing and self._current_iface:
                self._restart_count += 1
                self.on_alert("error", "engine",
                              f"Sniffer thread died — auto-restarting "
                              f"(restart #{self._restart_count})")
                self._start_sniffer(self._current_iface)
        except Exception:
            pass

        # --- Push stats ---
        try:
            elapsed = time.time() - self.start_time if self.start_time else 0
            pps = self.total_packets / elapsed if elapsed > 0 else 0
            self.on_stat({
                "packets": self.total_packets,
                "alerts": self.total_alerts,
                "pps": pps,
                "elapsed": elapsed,
                "breakdown": dict(self.alert_breakdown),
            })
        except Exception:
            pass

        # Reschedule
        if self.is_sniffing:
            self._stats_timer = threading.Timer(2.0, self._stats_loop)
            self._stats_timer.daemon = True
            self._stats_timer.start()

    # --- Internal sniffer start (used by start and watchdog) ---
    def _start_sniffer(self, iface):
        """Create and start the AsyncSniffer. Can be called for restarts."""
        try:
            # Stop old sniffer if any
            if self.sniffer:
                try:
                    self.sniffer.stop()
                except Exception:
                    pass
            self.sniffer = AsyncSniffer(
                iface=iface,
                prn=self._process,
                store=False,
                filter="tcp or icmp or udp or arp",
            )
            self.sniffer.start()
        except Exception as e:
            self.on_alert("error", "system", f"Sniffer restart failed: {e}")

    # --- Start / Stop ---
    def start(self, iface):
        if self.is_sniffing:
            return
        self._reset_window()
        self.total_packets = 0
        self.total_alerts = 0
        self.alert_breakdown.clear()
        self.external_ips.clear()
        self.ip_packet_counts.clear()
        self.ip_max_severity.clear()
        self._dns_cache.clear()
        self._error_count = 0
        self._restart_count = 0
        self._current_iface = iface
        self.start_time = time.time()
        self.is_sniffing = True

        self.on_alert("info", "system", f"Starting packet capture on: {iface}")

        try:
            self._start_sniffer(iface)
            # Start stats + watchdog timer
            self._stats_loop()
        except Exception as e:
            self.is_sniffing = False
            self.on_alert("error", "system", f"Sniffer failed: {e}")

    def stop(self):
        if not self.is_sniffing:
            return
        self.is_sniffing = False
        # Cancel stats timer
        if self._stats_timer:
            self._stats_timer.cancel()
            self._stats_timer = None
        # Grab reference and clear it immediately
        sniffer_ref = self.sniffer
        self.sniffer = None
        time.sleep(0.3)
        try:
            if sniffer_ref:
                sniffer_ref.stop()
        except Exception:
            pass
        self.on_alert("info", "system", "Intrusion detection engine stopped.")

    # --- Alert helper ---
    def _fire(self, severity, category, msg, src_ip=None):
        try:
            if src_ip:
                with self.lock:
                    if src_ip in self.alerted[category]:
                        return
                    self.alerted[category].add(src_ip)
                # Track severity for route trace
                cur = self.ip_max_severity.get(src_ip, "normal")
                if self._SEV_RANK.get(severity, 0) > self._SEV_RANK.get(cur, 0):
                    self.ip_max_severity[src_ip] = severity
            self.total_alerts += 1
            self.alert_breakdown[category] += 1
            self.on_alert(severity, category, msg)
        except Exception:
            pass

    # --- Packet processing (fully wrapped in try/except) ---
    def _process(self, packet):
        try:
            if not self.is_sniffing:
                return

            self.total_packets += 1

            # Periodic traffic summary
            if self.total_packets % 500 == 0:
                try:
                    ext = len(self.external_ips)
                    src = len(self.conn_counts)
                    self.on_alert("info", "traffic",
                                  f"Traffic summary: {self.total_packets:,} packets, "
                                  f"{src} sources, {ext} external IPs, "
                                  f"{self.total_alerts} alerts")
                except Exception:
                    pass

            # Time window reset
            now = time.time()
            if now - self.last_reset > self.TIME_WINDOW:
                self._reset_window()

            # === ARP spoofing ===
            if ARP in packet:
                try:
                    op = packet[ARP].op
                    arp_src = packet[ARP].psrc
                    if op == 2:
                        with self.lock:
                            self.arp_counts[arp_src] += 1
                            if self.arp_counts[arp_src] >= self.ARP_THRESHOLD:
                                self._fire("critical", "arp_spoof",
                                           f"Possible ARP Spoofing from {self._resolve(arp_src)} "
                                           f"({self.arp_counts[arp_src]} gratuitous replies)",
                                           arp_src)
                except Exception:
                    pass
                return

            if IP not in packet:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Track external IPs for route trace + connection count
            with self.lock:
                self.conn_counts[src_ip] += 1
                try:
                    ip_obj = ipaddress.ip_address(src_ip)
                    if not (ip_obj.is_private or ip_obj.is_loopback or
                            ip_obj.is_link_local or ip_obj.is_multicast or
                            ip_obj.is_reserved):
                        self.external_ips.add(src_ip)
                        self.ip_packet_counts[src_ip] += 1
                except ValueError:
                    pass

            # === ICMP detection ===
            if ICMP in packet:
                try:
                    icmp_type = packet[ICMP].type
                    if icmp_type == 8:  # Echo request
                        self.on_alert("low", "icmp",
                                      f"ICMP Ping from {self._resolve(src_ip)}")
                except Exception:
                    pass
                return

            # === DNS tunneling / exfiltration ===
            if UDP in packet and DNS in packet:
                try:
                    if packet[UDP].dport == 53 and DNSQR in packet:
                        qname = packet[DNSQR].qname.decode(errors="ignore")
                        with self.lock:
                            self.dns_counts[src_ip] += 1
                            if self.dns_counts[src_ip] >= self.DNS_THRESHOLD:
                                self._fire("critical", "dns_flood",
                                           f"Excessive DNS queries from {self._resolve(src_ip)} "
                                           f"({self.dns_counts[src_ip]} in {self.TIME_WINDOW}s) "
                                           f"— possible DNS tunneling",
                                           src_ip)
                        if len(qname) > 80:
                            self._fire("critical", "dns_exfil",
                                       f"Suspiciously long DNS query from "
                                       f"{self._resolve(src_ip)}: {qname[:60]}...",
                                       src_ip)
                except Exception:
                    pass
                return

            # === TCP analysis ===
            if TCP in packet:
                try:
                    dst_port = packet[TCP].dport
                    flags = int(packet[TCP].flags)
                    is_syn = (flags & 0x02) and not (flags & 0x10)

                    # Suspicious port
                    if dst_port in SUSPICIOUS_PORTS:
                        desc = SUSPICIOUS_PORTS[dst_port]
                        self._fire("critical", f"port_{dst_port}",
                                   f"Connection to suspicious port {dst_port} ({desc}) "
                                   f"from {self._resolve(src_ip)}",
                                   src_ip)

                    if is_syn:
                        with self.lock:
                            self.syn_counts[src_ip] += 1
                            self.port_scans[src_ip].add(dst_port)

                            if self.syn_counts[src_ip] >= self.SYN_THRESHOLD:
                                self._fire("critical", "syn_flood",
                                           f"SYN Flood from {self._resolve(src_ip)} "
                                           f"({self.syn_counts[src_ip]} SYNs in "
                                           f"{self.TIME_WINDOW}s)", src_ip)

                            scanned = len(self.port_scans[src_ip])
                            if scanned >= self.PORT_THRESHOLD:
                                self._fire("critical", "port_scan",
                                           f"Port scan from {self._resolve(src_ip)} "
                                           f"({scanned} ports probed)", src_ip)
                except Exception:
                    pass

            # === High traffic volume ===
            try:
                with self.lock:
                    if self.conn_counts[src_ip] >= self.CONN_THRESHOLD:
                        self._fire("medium", "high_traffic",
                                   f"High traffic from {self._resolve(src_ip)} "
                                   f"({self.conn_counts[src_ip]} pkts in "
                                   f"{self.TIME_WINDOW}s)", src_ip)
            except Exception:
                pass

        except Exception as e:
            # Catch-all: log the first few errors, then suppress
            self._error_count += 1
            now = time.time()
            if self._error_count <= 5 or (now - self._last_error_time > 30):
                self._last_error_time = now
                try:
                    self.on_alert("error", "engine",
                                  f"Packet processing error #{self._error_count}: {e}")
                except Exception:
                    pass


# ==========================================
# ROUTE TRACE — WORLD MAP
# ==========================================

# Accurate world coastlines from Natural Earth 110m dataset
# Lazy-loaded on first Route Trace open to keep startup fast
_COASTLINES = None

# Severity color for dots on the map
_SEV_COLORS = {
    "critical": "#ff4444", "medium": "#ffca28",
    "low": "#00e5ff", "normal": "#4caf7a",
}


def _geolocate_ips(ip_list):
    """Geolocate IPs via ipwho.is (free, no key). Returns list of dicts."""
    results = []
    lock = threading.Lock()

    def _lookup(ip):
        try:
            resp = requests.get(f"https://ipwho.is/{ip}", timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    item = {
                        "query": data.get("ip", ip),
                        "lat": data.get("latitude", 0),
                        "lon": data.get("longitude", 0),
                        "city": data.get("city", "Unknown"),
                        "country": data.get("country", "Unknown"),
                        "isp": data.get("connection", {}).get("isp", "")
                                if isinstance(data.get("connection"), dict) else "",
                        "regionName": data.get("region", ""),
                    }
                    with lock:
                        results.append(item)
        except Exception as e:
            print(f"[RouteTrace] Geo lookup failed for {ip}: {e}")

    # Use thread pool for parallel lookups (max 10 concurrent)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_lookup, ip) for ip in ip_list]
        for f in as_completed(futures):
            pass  # results collected via closure

    return results


def _get_my_location():
    """Get the user's own public IP geolocation."""
    try:
        resp = requests.get("https://ipwho.is/", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                return {
                    "query": data.get("ip"),
                    "lat": data.get("latitude"),
                    "lon": data.get("longitude"),
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                }
    except Exception as e:
        print(f"[RouteTrace] My-location lookup failed: {e}")
    return None


def _project(lat, lon, w, h, scale=1.0, ox=0.0, oy=0.0):
    """Equirectangular projection → canvas coords."""
    x = (lon + 180) / 360 * w * scale + ox
    y = (90 - lat) / 180 * h * scale + oy
    return x, y


def _draw_arc(canvas, x1, y1, x2, y2, color, width=1.5):
    """Draw a curved arc (quadratic bezier) between two points."""
    dx, dy = x2 - x1, y2 - y1
    length = math.sqrt(dx * dx + dy * dy)
    if length < 2:
        return
    offset = min(length * 0.35, 120)
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    px = -dy / length * offset
    py = dx / length * offset
    cx, cy = mx + px, my + py
    pts = []
    for i in range(21):
        t = i / 20
        bx = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * cx + t ** 2 * x2
        by = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * cy + t ** 2 * y2
        pts.extend([bx, by])
    canvas.create_line(pts, fill=color, width=width, smooth=True, dash=(6, 4))


class _MapTooltip:
    """Floating tooltip for map canvas items."""
    def __init__(self, canvas):
        self._c = canvas
        self._tw = None

    def show(self, event, text):
        self.hide()
        tw = tk.Toplevel(self._c)
        tw.wm_overrideredirect(True)
        tw.wm_attributes("-topmost", True)
        tw.configure(bg="#12121a")
        tw.wm_geometry(f"+{event.x_root + 14}+{event.y_root + 10}")
        lbl = tk.Label(tw, text=text, justify="left", bg="#12121a", fg="#d8d8e0",
                       font=("Consolas", 10), padx=10, pady=6, relief="solid",
                       borderwidth=1, highlightbackground="#3d7dd4")
        lbl.pack()
        self._tw = tw

    def hide(self):
        if self._tw:
            self._tw.destroy()
            self._tw = None


def _draw_world_map(canvas, geo_data, user_loc, engine, scale=1.0, ox=0.0, oy=0.0, tooltip=None):
    """Render the world map with traffic origin arcs on the canvas."""
    canvas.delete("all")
    w = canvas.winfo_width() or 1000
    h = canvas.winfo_height() or 600

    # Dark ocean background
    canvas.create_rectangle(0, 0, w, h, fill="#0a0e14", outline="")

    # Grid lines
    for lat in range(-60, 90, 30):
        _, y1 = _project(lat, -180, w, h, scale, ox, oy)
        _, y2 = _project(lat, 180, w, h, scale, ox, oy)
        x1p, _ = _project(lat, -180, w, h, scale, ox, oy)
        x2p, _ = _project(lat, 180, w, h, scale, ox, oy)
        canvas.create_line(x1p, y1, x2p, y2, fill="#151a22", width=1)
    for lon in range(-180, 210, 30):
        x1, y1 = _project(90, lon, w, h, scale, ox, oy)
        x2, y2 = _project(-90, lon, w, h, scale, ox, oy)
        canvas.create_line(x1, y1, x2, y2, fill="#151a22", width=1)

    # Equator
    ex1, ey = _project(0, -180, w, h, scale, ox, oy)
    ex2, _ = _project(0, 180, w, h, scale, ox, oy)
    canvas.create_line(ex1, ey, ex2, ey, fill="#1a2030", width=1, dash=(8, 4))

    global _COASTLINES
    if _COASTLINES is None:
        from coastline_data import _COASTLINES
    # Coastlines
    for poly in _COASTLINES:
        pts = []
        for lat, lon in poly:
            px, py = _project(lat, lon, w, h, scale, ox, oy)
            pts.extend([px, py])
        if len(pts) >= 4:
            canvas.create_polygon(pts, fill="#151c28", outline="#2a3a50", width=1, smooth=False)

    if not user_loc:
        canvas.create_text(w / 2, h / 2, text="Could not determine your location",
                           fill="#6a6a7a", font=("Segoe UI", 14))
        return

    # User location dot
    ux, uy = _project(user_loc["lat"], user_loc["lon"], w, h, scale, ox, oy)

    # Pulsing rings for user
    for ring_r in [28, 20, 12]:
        r = ring_r * scale
        canvas.create_oval(ux - r, uy - r, ux + r, uy + r,
                           fill="", outline="#3d7dd4", width=1, dash=(3, 3))
    ur = 7 * scale
    canvas.create_oval(ux - ur, uy - ur, ux + ur, uy + ur,
                       fill="#3d7dd4", outline="#5c9fd4", width=2, tags="user_dot")
    canvas.create_text(ux, uy + 18 * scale,
                       text=f"📍 You ({user_loc.get('city', '')}, {user_loc.get('country', '')})",
                       fill="#5c9fd4", font=("Segoe UI", max(8, int(10 * scale)), "bold"))

    if tooltip is None:
        tooltip = _MapTooltip(canvas)
    tooltip.hide()

    # Cluster nearby points — group by rounded lat/lon
    clusters = {}
    for item in geo_data:
        key = (round(item["lat"], 1), round(item["lon"], 1))
        if key not in clusters:
            clusters[key] = []
        clusters[key].append(item)

    # Draw arcs and dots
    for key, items in clusters.items():
        lat, lon = items[0]["lat"], items[0]["lon"]
        dx, dy = _project(lat, lon, w, h, scale, ox, oy)

        # Determine severity color
        max_sev = "normal"
        total_pkts = 0
        for item in items:
            ip = item["query"]
            sev = engine.ip_max_severity.get(ip, "normal")
            total_pkts += engine.ip_packet_counts.get(ip, 0)
            if sev == "critical":
                max_sev = "critical"
            elif sev == "medium" and max_sev not in ("critical",):
                max_sev = "medium"

        arc_color = _SEV_COLORS.get(max_sev, "#4caf7a")

        # Arc from user to this source
        _draw_arc(canvas, ux, uy, dx, dy, arc_color, width=1.5)

        # Dot at source
        tag = f"geo_{key[0]}_{key[1]}"
        dr = max(4, min(10, 4 + len(items))) * scale
        canvas.create_oval(dx - dr, dy - dr, dx + dr, dy + dr,
                           fill=arc_color, outline="#0a0e14", width=1, tags=tag)

        # Cluster count badge
        if len(items) > 1:
            br = max(8, 6 + len(str(len(items)))) * scale
            canvas.create_oval(dx + dr * 0.5, dy - dr - br,
                               dx + dr * 0.5 + br * 2, dy - dr + br,
                               fill="#1a1a2a", outline=arc_color, width=1)
            canvas.create_text(dx + dr * 0.5 + br, dy - dr,
                               text=str(len(items)), fill=arc_color,
                               font=("Segoe UI", max(7, int(8 * scale)), "bold"))

        # Tooltip
        tip_lines = []
        city = items[0].get("city", "Unknown")
        country = items[0].get("country", "Unknown")
        tip_lines.append(f"📍 {city}, {country}")
        tip_lines.append(f"{'─' * 30}")
        for item in items[:8]:
            ip = item["query"]
            pkts = engine.ip_packet_counts.get(ip, 0)
            isp = item.get("isp", "")
            tip_lines.append(f"  {ip}  ({pkts:,} pkts)  {isp}")
        if len(items) > 8:
            tip_lines.append(f"  ... and {len(items) - 8} more")
        tip_lines.append(f"{'─' * 30}")
        tip_lines.append(f"Total packets: {total_pkts:,}")
        tip_text = "\n".join(tip_lines)

        def _enter(evt, t=tip_text):
            tooltip.show(evt, t)
        def _leave(evt):
            tooltip.hide()
        def _motion(evt, t=tip_text):
            tooltip.show(evt, t)

        canvas.tag_bind(tag, "<Enter>", _enter)
        canvas.tag_bind(tag, "<Leave>", _leave)
        canvas.tag_bind(tag, "<Motion>", _motion)

    # Legend
    lx, ly = 12, h - 90
    canvas.create_rectangle(lx - 4, ly - 14, lx + 170, ly + 78,
                            fill="#0d1118", outline="#1a2030", width=1)
    canvas.create_text(lx, ly, text="Severity Legend", anchor="w",
                       fill="#7a7a8a", font=("Segoe UI", 9, "bold"))
    for j, (sev_name, clr) in enumerate(_SEV_COLORS.items()):
        yy = ly + 16 + j * 14
        canvas.create_oval(lx + 2, yy - 4, lx + 10, yy + 4, fill=clr, outline="")
        canvas.create_text(lx + 16, yy, text=sev_name.capitalize(), anchor="w",
                           fill="#9898a8", font=("Segoe UI", 8))

    # Zoom indicator
    pct = int(scale * 100)
    canvas.create_text(w - 14, 16, text=f"🔍 {pct}%", anchor="e",
                       fill="#5a5a6a", font=("Consolas", 10, "bold"))
    canvas.create_text(w - 14, 32, text="Scroll=Zoom  Drag=Pan  DblClick=Reset", anchor="e",
                       fill="#2a3040", font=("Consolas", 8))

    # IP count
    canvas.create_text(w / 2, h - 12, text=f"{len(geo_data)} IPs geolocated from"
                       f" {len(engine.external_ips)} unique external sources",
                       fill="#3a3a4a", font=("Segoe UI", 9))


def _open_route_trace(engine, parent):
    """Open the Route Trace world-map window with live auto-update."""
    with engine.lock:
        has_ips = bool(engine.external_ips)
    if not has_ips:
        popup = ctk.CTkToplevel(parent)
        popup.title("Route Trace")
        popup.geometry("420x160")
        popup.configure(fg_color="#12121a")
        popup.attributes("-topmost", True)
        ctk.CTkLabel(popup, text="🌍  No external IPs captured yet.",
                     font=("Segoe UI", 15, "bold"), text_color="#c0c0cc"
                     ).place(relx=0.5, rely=0.35, anchor="center")
        ctk.CTkLabel(popup, text="Start the IDS and let it capture traffic first.",
                     font=("Segoe UI", 11), text_color="#6a6a7a"
                     ).place(relx=0.5, rely=0.6, anchor="center")
        return

    win = ctk.CTkToplevel(parent)
    win.title("🌍 Route Trace — Traffic Origins")
    win.geometry("1100x700")
    win.configure(fg_color="#0a0e14")
    win.attributes("-topmost", True)

    def _win_alive():
        """Check if the window still exists (prevents TclError)."""
        try:
            return win.winfo_exists()
        except Exception:
            return False

    # Status bar
    status_bar = ctk.CTkFrame(win, fg_color="#0d1118", height=38, corner_radius=0)
    status_bar.pack(fill="x")
    status_bar.pack_propagate(False)

    status_lbl = ctk.CTkLabel(status_bar, text="  ⏳ Geolocating IPs...",
                              font=("Segoe UI", 11), text_color="#9898a8")
    status_lbl.pack(side="left", padx=8)

    ip_count_lbl = ctk.CTkLabel(
        status_bar, text=f"{len(engine.external_ips)} unique external IPs  ",
        font=("Consolas", 10), text_color="#3d7dd4")
    ip_count_lbl.pack(side="right", padx=8)

    # Canvas
    map_canvas = tk.Canvas(win, bg="#0a0e14", highlightthickness=0, bd=0)
    map_canvas.pack(fill="both", expand=True)

    _tip = _MapTooltip(map_canvas)

    _st = {"scale": 1.0, "ox": 0.0, "oy": 0.0, "dx": 0, "dy": 0,
           "geo": [], "user": None, "known_ips": set(), "busy": False}

    def _redraw():
        if not _win_alive():
            return
        _tip.hide()
        _draw_world_map(map_canvas, _st["geo"], _st["user"], engine,
                        _st["scale"], _st["ox"], _st["oy"], _tip)

    def _on_resize(evt):
        if _st["geo"] or _st["user"]:
            _redraw()

    def _on_scroll(evt):
        if evt.delta > 0:
            _st["scale"] = min(4.0, _st["scale"] * 1.15)
        else:
            _st["scale"] = max(0.3, _st["scale"] / 1.15)
        _redraw()

    def _on_press(evt):
        _st["dx"], _st["dy"] = evt.x, evt.y

    def _on_drag(evt):
        _st["ox"] += evt.x - _st["dx"]
        _st["oy"] += evt.y - _st["dy"]
        _st["dx"], _st["dy"] = evt.x, evt.y
        _redraw()

    def _on_dbl(evt):
        _st["scale"], _st["ox"], _st["oy"] = 1.0, 0.0, 0.0
        _redraw()

    map_canvas.bind("<Configure>", _on_resize)
    map_canvas.bind("<MouseWheel>", _on_scroll)
    map_canvas.bind("<ButtonPress-1>", _on_press)
    map_canvas.bind("<B1-Motion>", _on_drag)
    map_canvas.bind("<Double-Button-1>", _on_dbl)
    map_canvas.bind("<Leave>", lambda e: _tip.hide())

    def _do_geo(only_new=False):
        """Geolocate IPs. Limits display to top 50 IPs by traffic volume."""
        if _st["busy"]:
            return
        _st["busy"] = True

        MAX_DISPLAY = 50  # Keep map readable

        with engine.lock:
            current_ips = set(engine.external_ips)
            # Get top IPs by packet count for display
            ip_counts = dict(engine.ip_packet_counts)

        new_ips = current_ips - _st["known_ips"]

        if only_new and not new_ips:
            _st["busy"] = False
            # Still redraw to update packet counts, but prune to top N
            if _win_alive():
                def _refresh():
                    _prune_geo(ip_counts, MAX_DISPLAY)
                    _redraw()
                map_canvas.after(0, _refresh)
            _schedule_refresh()
            return

        ips_to_lookup = list(new_ips) if only_new else list(current_ips)[:200]

        # Get user location on first run only
        if _st["user"] is None:
            _st["user"] = _get_my_location()

        if ips_to_lookup:
            new_results = _geolocate_ips(ips_to_lookup[:200])
            _st["geo"].extend(new_results)
            _st["known_ips"].update(ips_to_lookup)

        total_ext = len(current_ips)

        def _done():
            if not _win_alive():
                return
            _prune_geo(ip_counts, MAX_DISPLAY)
            now = datetime.now().strftime("%H:%M:%S")
            shown = len(_st["geo"])
            status_lbl.configure(
                text=f"  ✅ {shown} / {total_ext} IPs shown  •  Last refresh: {now}",
                text_color="#4caf7a")
            ip_count_lbl.configure(text=f"{total_ext} unique external IPs  ")
            _redraw()

        if _win_alive():
            map_canvas.after(0, _done)

        _st["busy"] = False
        _schedule_refresh()

    def _prune_geo(ip_counts, max_n):
        """Keep only the top N IPs by packet count in the geo list."""
        if len(_st["geo"]) <= max_n:
            return
        # Sort geo results by packet count (highest first)
        for g in _st["geo"]:
            g["_pkt"] = ip_counts.get(g.get("query", ""), 0)
        _st["geo"].sort(key=lambda g: g.get("_pkt", 0), reverse=True)
        _st["geo"] = _st["geo"][:max_n]

    def _schedule_refresh():
        """Schedule next auto-refresh in 15 seconds."""
        if _win_alive():
            map_canvas.after(15000, lambda: threading.Thread(
                target=_do_geo, args=(True,), daemon=True).start())

    # Initial geolocation
    threading.Thread(target=_do_geo, daemon=True).start()


# ==========================================
# UI: HIDS FRAME
# ==========================================

ALERT_ICONS = {
    "critical": "🔥",
    "medium":   "⚠️",
    "low":      "🏓",
    "info":     "ⓘ",
    "error":    "❌",
}

ALERT_COLORS = {
    "critical": "#ff4444",
    "medium":   "#ffca28",
    "low":      "#00e5ff",
    "info":     "#69f0ae",
    "error":    "#ff5252",
}

STAT_CARD_DEFS = [
    {"key": "packets", "icon": "📦", "label": "Packets"},
    {"key": "alerts",  "icon": "🚨", "label": "Alerts"},
    {"key": "pps",     "icon": "⚡", "label": "Pkts/sec"},
    {"key": "uptime",  "icon": "⏱️", "label": "Uptime"},
]


def is_admin():
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def create_hids_frame(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")

    gt.section_header(
        frame,
        "Host Intrusion Detection System",
        "Real-time packet analysis — SYN floods, port scans, ARP spoofing & DNS tunneling.",
    ).pack(anchor="w", pady=(0, 10))

    # Admin warning
    if not is_admin():
        ctk.CTkLabel(
            frame,
            text="⚠️ Run as Administrator to capture packets.",
            text_color="#FFC107", font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 10))
    else:
        ctk.CTkFrame(frame, height=10, fg_color="transparent").pack(pady=(0, 10))

    # --- Stats cards row ---
    stats_frame = ctk.CTkFrame(frame, fg_color="transparent")
    stats_frame.pack(fill="x", pady=(0, 8))
    stats_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

    stat_widgets = {}
    for col, sd in enumerate(STAT_CARD_DEFS):
        card = ctk.CTkFrame(
            stats_frame, fg_color=gt.CARD_BG, corner_radius=14,
            border_width=1, border_color=gt.CARD_BORDER, height=72,
        )
        card.grid(row=0, column=col, padx=4, sticky="nsew")
        card.grid_propagate(False)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text=f"{sd['icon']} {sd['label']}",
                     font=("Segoe UI", 10), text_color="#7a7a8a").pack()
        val_lbl = ctk.CTkLabel(inner, text="—",
                               font=("Segoe UI", 18, "bold"), text_color="#6a6a7a")
        val_lbl.pack(pady=(2, 0))

        stat_widgets[sd["key"]] = val_lbl

    # --- Sparkline card (5th column) ---
    spark_card = ctk.CTkFrame(
        stats_frame, fg_color=gt.CARD_BG, corner_radius=14,
        border_width=1, border_color=gt.CARD_BORDER, height=72,
    )
    spark_card.grid(row=0, column=4, padx=4, sticky="nsew")
    spark_card.grid_propagate(False)

    ctk.CTkLabel(spark_card, text="📈 Traffic",
                 font=("Segoe UI", 10), text_color="#7a7a8a"
                 ).place(relx=0.5, y=6, anchor="n")

    spark_canvas = tk.Canvas(spark_card, bg="#1a1a2e", highlightthickness=0,
                             height=38, width=120)
    spark_canvas.place(relx=0.5, rely=0.65, anchor="center")

    _spark_data = []  # rolling pps history (last 60 samples)

    def _draw_sparkline(pps):
        _spark_data.append(pps)
        if len(_spark_data) > 60:
            _spark_data.pop(0)
        spark_canvas.delete("all")
        w = spark_canvas.winfo_width() or 120
        h = spark_canvas.winfo_height() or 38
        n = len(_spark_data)
        if n < 2:
            return
        max_val = max(_spark_data) or 1
        points = []
        for i, v in enumerate(_spark_data):
            x = (i / (n - 1)) * w
            y = h - (v / max_val) * (h - 4) - 2
            points.append((x, y))
        # Fill area under curve
        fill_pts = [(0, h)] + points + [(w, h)]
        spark_canvas.create_polygon(
            *[c for p in fill_pts for c in p],
            fill="#1a3d5c", outline="", smooth=True)
        # Line
        spark_canvas.create_line(
            *[c for p in points for c in p],
            fill="#3d9dea", width=1.5, smooth=True)

    # Status indicator
    status_dot = ctk.CTkFrame(
        stats_frame, width=12, height=12, corner_radius=6,
        fg_color="#ff5252",
    )
    status_dot.place(relx=1.0, rely=0.0, anchor="ne", x=-8, y=4)

    # --- Stats update ---
    def _update_stats(stats):
        def _do():
            stat_widgets["packets"].configure(
                text=f"{stats['packets']:,}", text_color="#d8d8e0")
            stat_widgets["alerts"].configure(
                text=str(stats["alerts"]),
                text_color="#ff5252" if stats["alerts"] > 0 else "#4caf7a")
            stat_widgets["pps"].configure(
                text=f"{stats['pps']:.0f}", text_color="#d8d8e0")
            mins = int(stats["elapsed"] // 60)
            secs = int(stats["elapsed"] % 60)
            stat_widgets["uptime"].configure(
                text=f"{mins}m {secs}s", text_color="#d8d8e0")
            _draw_sparkline(stats["pps"])
        frame.after(0, _do)

    # --- Controls card ---
    ctrl_card = gt.control_card(frame)
    ctrl_card.pack(fill="x", pady=(0, 4))
    ctrl_row = ctk.CTkFrame(ctrl_card, fg_color="transparent")
    ctrl_row.pack(fill="x", padx=14, pady=10)

    # --- Filter bar (severity toggles + whitelist) ---
    filter_bar = ctk.CTkFrame(frame, fg_color="#14141e", corner_radius=10, height=36)
    filter_bar.pack(fill="x", pady=(0, 4))
    filter_bar.pack_propagate(False)

    # Severity filter state
    _filter = {"active": "all"}  # "all", "critical", "medium", "low", "info"
    _log_entries = []  # list of (severity, full_text) for re-filtering

    _filter_btns = {}
    filter_defs = [
        ("all",      "All",      "#3a3a4a"),
        ("critical", "🔥 Crit",  "#ff4444"),
        ("medium",   "⚠️ Med",   "#ffca28"),
        ("low",      "🏓 Low",   "#00e5ff"),
        ("info",     "ⓘ Info",   "#69f0ae"),
    ]

    ctk.CTkLabel(filter_bar, text="  Filter:",
                 font=("Segoe UI", 10, "bold"), text_color="#7a7a8a"
                 ).pack(side="left", padx=(6, 4))

    def _set_filter(sev):
        _filter["active"] = sev
        # Update button styles
        for key, btn in _filter_btns.items():
            if key == sev:
                btn.configure(fg_color="#2e2e40", border_width=1)
            else:
                btn.configure(fg_color="transparent", border_width=0)
        # Re-render the log
        _refilter_log()

    for key, label, color in filter_defs:
        btn = ctk.CTkButton(
            filter_bar, text=label, width=60, height=26,
            corner_radius=8, font=("Segoe UI", 10),
            fg_color="#2e2e40" if key == "all" else "transparent",
            hover_color="#3a3a50", text_color=color if key != "all" else "#d8d8e0",
            border_width=1 if key == "all" else 0,
            border_color="#4a4a5a",
            command=lambda k=key: _set_filter(k),
        )
        btn.pack(side="left", padx=2)
        _filter_btns[key] = btn

    # --- Whitelist controls ---
    _whitelist = set()  # IPs to suppress from log

    ctk.CTkLabel(filter_bar, text="│",
                 font=("Segoe UI", 12), text_color="#3a3a4a"
                 ).pack(side="left", padx=(8, 4))

    wl_entry = ctk.CTkEntry(
        filter_bar, width=130, height=26, corner_radius=8,
        font=("Consolas", 10), fg_color="#1a1a28",
        border_color="#3a3a4a", border_width=1,
        placeholder_text="IP to whitelist...",
        placeholder_text_color="#4a4a5a",
    )
    wl_entry.pack(side="left", padx=(0, 4))

    def _add_whitelist():
        ip = wl_entry.get().strip()
        if ip:
            _whitelist.add(ip)
            wl_entry.delete(0, "end")
            wl_count.configure(text=f"🛡 {len(_whitelist)}")
            _refilter_log()

    ctk.CTkButton(
        filter_bar, text="+WL", width=40, height=26,
        corner_radius=8, font=("Segoe UI", 9, "bold"),
        fg_color="#1a3d2e", hover_color="#24593a",
        command=_add_whitelist,
    ).pack(side="left", padx=(0, 4))

    wl_count = ctk.CTkLabel(filter_bar, text="🛡 0",
                            font=("Segoe UI", 10), text_color="#4caf7a")
    wl_count.pack(side="left", padx=(0, 6))

    # --- Log textbox ---
    txt_log = gt.create_log_textbox(frame)

    # Color tags
    for sev, color in ALERT_COLORS.items():
        txt_log.tag_config(sev, foreground=color)

    def _wl_match(text):
        """Check if text contains any whitelisted IP as a complete token."""
        for wl_ip in _whitelist:
            # Use word boundary so '192.168.0.1' won't match '192.168.0.107'
            if re.search(r'(?<!\d)' + re.escape(wl_ip) + r'(?!\d)', text):
                return True
        return False

    def _refilter_log():
        """Re-render the log with current filter & whitelist applied."""
        txt_log.configure(state="normal")
        txt_log.delete("1.0", "end")
        active = _filter["active"]
        for sev, text in _log_entries:
            if _wl_match(text):
                continue
            # Check severity filter
            if active != "all" and sev != active:
                continue
            txt_log.insert("end", text, sev)
        txt_log.see("end")

    def log_alert(severity, category, message):
        icon = ALERT_ICONS.get(severity, "")
        ts = datetime.now().strftime("%H:%M:%S")
        cat_label = category.replace("_", " ").upper()
        full = f"[{ts}] {icon} [{cat_label}] {message}\n"

        # Store for filtering
        _log_entries.append((severity, full))
        # Keep max 2000 entries to prevent memory bloat
        if len(_log_entries) > 2000:
            _log_entries.pop(0)

        def _append():
            active = _filter["active"]
            if _wl_match(full):
                return
            # Check filter
            if active != "all" and severity != active:
                return
            txt_log.insert("end", full, severity)
            txt_log.see("end")
        txt_log.after(0, _append)

    # --- Engine ---
    engine = HIDSEngine(log_alert, _update_stats)

    # Auto-whitelist local gateway
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-c",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
             "Select-Object -First 1).NextHop"],
            capture_output=True, text=True, timeout=3)
        gw = result.stdout.strip()
        if gw:
            _whitelist.add(gw)
            wl_count.configure(text=f"🛡 {len(_whitelist)}")
    except Exception:
        pass

    # --- Interface combo ---
    combo_iface = gt.create_styled_combo(
        ctrl_row, values=engine.interfaces, width=240, height=38,
    )
    combo_iface.set(engine.get_default_interface())
    combo_iface.pack(side="left", padx=(0, 10))

    def _set_ui_running():
        btn_start.configure(state="disabled", fg_color="#333333")
        btn_stop.configure(state="normal", fg_color="#E53935", hover_color="#C62828")
        combo_iface.configure(state="disabled")
        status_dot.configure(fg_color="#4caf7a")

    def _set_ui_stopped():
        btn_start.configure(state="normal", fg_color=gt.ACCENT_BLUE,
                            hover_color=gt.ACCENT_BLUE_HOVER)
        btn_stop.configure(state="disabled", fg_color="#333333")
        combo_iface.configure(state="normal")
        status_dot.configure(fg_color="#ff5252")

    def _on_start():
        iface = combo_iface.get()
        frame.after(0, _set_ui_running)
        engine.start(iface)
        if not engine.is_sniffing:
            frame.after(0, _set_ui_stopped)

    def _on_stop():
        def _do_stop():
            engine.stop()
            frame.after(0, _set_ui_stopped)
        threading.Thread(target=_do_stop, daemon=True).start()

    btn_start = ctk.CTkButton(
        ctrl_row, text="▶ Start IDS", width=120, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color=gt.ACCENT_BLUE, hover_color=gt.ACCENT_BLUE_HOVER,
        command=lambda: threading.Thread(target=_on_start, daemon=True).start(),
    )
    btn_start.pack(side="left", padx=(0, 8))

    btn_stop = ctk.CTkButton(
        ctrl_row, text="⏹ Stop IDS", width=120, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color="#333333", state="disabled",
        command=_on_stop,
    )
    btn_stop.pack(side="left", padx=(0, 8))

    # Clear log button
    def _clear_log():
        _log_entries.clear()
        txt_log.delete("1.0", "end")

    ctk.CTkButton(
        ctrl_row, text="🗑 Clear", width=80, height=34,
        corner_radius=10, font=("Segoe UI", 11, "bold"),
        fg_color="#333333", hover_color="#444444",
        command=_clear_log,
    ).pack(side="left", padx=(0, 8))

    # Route Trace
    ctk.CTkButton(
        ctrl_row, text="🌍 Route Trace", width=130, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color="#1a3d2e", hover_color="#24593a",
        command=lambda: _open_route_trace(engine, frame),
    ).pack(side="left", padx=(0, 8))

    txt_log.pack(fill="both", expand=True, pady=(4, 0))

    def _init_log():
        txt_log.delete("1.0", "end")
        log_alert("info", "system", "Engine initialized. Ready to start.")

    frame.after(200, _init_log)

    # Auto-start after 3 seconds
    def auto_start():
        log_alert("info", "system", "Auto-starting IDS engine...")
        threading.Thread(target=_on_start, daemon=True).start()

    frame.after(3000, auto_start)

    return frame