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
import gui_theme as gt
import utils

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
    def __init__(self, on_alert, on_stat):
        self.on_alert = on_alert
        self.on_stat = on_stat

        self.is_sniffing = False
        self.sniffer = None
        self.lock = threading.Lock()

        self.TIME_WINDOW = 5
        self.SYN_THRESHOLD = 20
        self.PORT_THRESHOLD = 15
        self.CONN_THRESHOLD = 100
        self.DNS_THRESHOLD = 30
        self.ARP_THRESHOLD = 20

        self.syn_counts = defaultdict(int)
        self.port_scans = defaultdict(set)
        self.conn_counts = defaultdict(int)
        self.dns_counts = defaultdict(int)
        self.arp_counts = defaultdict(int)
        self.alerted = defaultdict(set)
        self.last_reset = time.time()

        self.total_packets = 0
        self.total_alerts = 0
        self.alert_breakdown = defaultdict(int)
        self.start_time = None

        self.dns_cache = {}

        self.interfaces = self._get_interfaces()

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

    def resolve_ip(self, ip):
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = f"{ip} ({hostname})"
        except Exception:
            self.dns_cache[ip] = ip
        return self.dns_cache[ip]

    def _reset_window(self):
        with self.lock:
            self.syn_counts.clear()
            self.port_scans.clear()
            self.conn_counts.clear()
            self.dns_counts.clear()
            self.arp_counts.clear()
            self.alerted.clear()
            self.last_reset = time.time()

    def start(self, iface):
        if self.is_sniffing:
            return
        self._reset_window()
        self.total_packets = 0
        self.total_alerts = 0
        self.alert_breakdown.clear()
        self.start_time = time.time()
        self.is_sniffing = True

        self.on_alert("info", "system", f"Starting packet capture on: {iface}")

        try:
            self.sniffer = AsyncSniffer(
                iface=iface,
                prn=self._process,
                store=False,
            )
            self.sniffer.start()
        except Exception as e:
            self.is_sniffing = False
            self.on_alert("error", "system", f"Sniffer failed: {e}")

    def stop(self):
        if not self.is_sniffing:
            return
        self.is_sniffing = False
        sniffer_ref = self.sniffer
        self.sniffer = None
        time.sleep(0.3)
        try:
            if sniffer_ref:
                sniffer_ref.stop()
        except Exception:
            pass
        self.on_alert("info", "system", "Intrusion detection engine stopped.")

    def _push_stats(self):
        elapsed = time.time() - self.start_time if self.start_time else 0
        pps = self.total_packets / elapsed if elapsed > 0 else 0
        self.on_stat({
            "packets": self.total_packets,
            "alerts": self.total_alerts,
            "pps": pps,
            "elapsed": elapsed,
            "breakdown": dict(self.alert_breakdown),
        })

    def _fire(self, severity, category, msg, src_ip=None):
        if src_ip:
            with self.lock:
                if src_ip in self.alerted[category]:
                    return
                self.alerted[category].add(src_ip)
        self.total_alerts += 1
        self.alert_breakdown[category] += 1
        self.on_alert(severity, category, msg)

    def _process(self, packet):
        if not self.is_sniffing:
            return

        self.total_packets += 1
        if self.total_packets % 100 == 0:
            self._push_stats()

        now = time.time()
        if now - self.last_reset > self.TIME_WINDOW:
            self._reset_window()

        if ARP in packet:
            op = packet[ARP].op
            src_ip = packet[ARP].psrc
            if op == 2:
                with self.lock:
                    self.arp_counts[src_ip] += 1
                    if self.arp_counts[src_ip] >= self.ARP_THRESHOLD:
                        resolved = self.resolve_ip(src_ip)
                        self._fire("critical", "arp_spoof",
                                   f"Possible ARP Spoofing from {resolved} "
                                   f"({self.arp_counts[src_ip]} gratuitous replies)",
                                   src_ip)
            return

        if IP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        with self.lock:
            self.conn_counts[src_ip] += 1

        if ICMP in packet:
            icmp_type = packet[ICMP].type
            if icmp_type == 8:
                resolved = self.resolve_ip(src_ip)
                self.on_alert("low", "icmp", f"ICMP Ping from {resolved}")
            elif icmp_type == 3:
                pass
            return

        if UDP in packet and packet[UDP].dport == 53 and DNS in packet:
            if DNSQR in packet:
                qname = packet[DNSQR].qname.decode(errors="ignore")
                with self.lock:
                    self.dns_counts[src_ip] += 1
                    if self.dns_counts[src_ip] >= self.DNS_THRESHOLD:
                        resolved = self.resolve_ip(src_ip)
                        self._fire("high", "dns_flood",
                                   f"Excessive DNS queries from {resolved} "
                                   f"({self.dns_counts[src_ip]} in {self.TIME_WINDOW}s) "
                                   f"— possible DNS tunneling",
                                   src_ip)
                if len(qname) > 80:
                    resolved = self.resolve_ip(src_ip)
                    self._fire("high", "dns_exfil",
                               f"Suspiciously long DNS query from {resolved}: "
                               f"{qname[:60]}...",
                               src_ip)
            return

        if TCP in packet:
            dst_port = packet[TCP].dport
            flags = int(packet[TCP].flags)
            is_syn = (flags & 0x02) and not (flags & 0x10)

            if dst_port in SUSPICIOUS_PORTS:
                desc = SUSPICIOUS_PORTS[dst_port]
                resolved = self.resolve_ip(src_ip)
                alert_key = f"port_{dst_port}"
                self._fire("high", alert_key,
                           f"Connection to suspicious port {dst_port} ({desc}) "
                           f"from {resolved}",
                           src_ip)

            if is_syn:
                with self.lock:
                    self.syn_counts[src_ip] += 1
                    self.port_scans[src_ip].add(dst_port)

                    if self.syn_counts[src_ip] >= self.SYN_THRESHOLD:
                        resolved = self.resolve_ip(src_ip)
                        self._fire("critical", "syn_flood",
                                   f"SYN Flood detected from {resolved} "
                                   f"({self.syn_counts[src_ip]} SYNs in {self.TIME_WINDOW}s)",
                                   src_ip)

                    scanned = len(self.port_scans[src_ip])
                    if scanned >= self.PORT_THRESHOLD:
                        resolved = self.resolve_ip(src_ip)
                        self._fire("high", "port_scan",
                                   f"Port scan detected from {resolved} "
                                   f"({scanned} ports probed)",
                                   src_ip)

        with self.lock:
            if self.conn_counts[src_ip] >= self.CONN_THRESHOLD:
                resolved = self.resolve_ip(src_ip)
                self._fire("medium", "high_traffic",
                           f"High traffic volume from {resolved} "
                           f"({self.conn_counts[src_ip]} pkts in {self.TIME_WINDOW}s)",
                           src_ip)

ALERT_ICONS = {
    "critical": "🔥",
    "high":     "🚨",
    "medium":   "⚠️",
    "low":      "🏓",
    "info":     "ⓘ",
    "error":    "❌",
}

ALERT_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8844",
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

    if not is_admin():
        ctk.CTkLabel(
            frame,
            text="⚠️ Run as Administrator to capture packets.",
            text_color="#FFC107", font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 10))
    else:
        ctk.CTkFrame(frame, height=10, fg_color="transparent").pack(pady=(0, 10))

    stats_frame = ctk.CTkFrame(frame, fg_color="transparent")
    stats_frame.pack(fill="x", pady=(0, 8))
    stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

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

    status_dot = ctk.CTkFrame(
        stats_frame, width=12, height=12, corner_radius=6,
        fg_color="#ff5252",
    )
    status_dot.place(relx=1.0, rely=0.0, anchor="ne", x=-8, y=4)

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
        frame.after(0, _do)

    ctrl_card = gt.control_card(frame)
    ctrl_card.pack(fill="x", pady=(0, 8))
    ctrl_row = ctk.CTkFrame(ctrl_card, fg_color="transparent")
    ctrl_row.pack(fill="x", padx=14, pady=10)

    txt_log = gt.create_log_textbox(frame)

    for sev, color in ALERT_COLORS.items():
        txt_log.tag_config(sev, foreground=color)

    def log_alert(severity, category, message):
        icon = ALERT_ICONS.get(severity, "")
        ts = datetime.now().strftime("%H:%M:%S")
        cat_label = category.replace("_", " ").upper()
        full = f"[{ts}] {icon} [{cat_label}] {message}\n"

        def _append():
            txt_log.insert("end", full, severity)
            txt_log.see("end")
        txt_log.after(0, _append)

    engine = HIDSEngine(log_alert, _update_stats)

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

    ctk.CTkButton(
        ctrl_row, text="🗑 Clear", width=80, height=34,
        corner_radius=10, font=("Segoe UI", 11, "bold"),
        fg_color="#333333", hover_color="#444444",
        command=lambda: txt_log.delete("1.0", "end"),
    ).pack(side="left", padx=(0, 8))

    ctk.CTkButton(
        ctrl_row, text="Export Log", width=100, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color="#333333", hover_color="#444444",
        command=lambda: utils.export_log(txt_log.get("1.0", "end"), "HIDS_Log"),
    ).pack(side="right")

    txt_log.pack(fill="both", expand=True, pady=(4, 0))

    def _init_log():
        txt_log.delete("1.0", "end")
        log_alert("info", "system", "Engine initialized. Ready to start.")

    frame.after(200, _init_log)

    def auto_start():
        log_alert("info", "system", "Auto-starting IDS engine...")
        threading.Thread(target=_on_start, daemon=True).start()

    frame.after(3000, auto_start)

    return frame
