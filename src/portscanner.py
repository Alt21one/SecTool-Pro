import customtkinter as ctk
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import gui_theme as gt
import utils

# ==========================================
# COMMON PORT DATABASE
# ==========================================

WELL_KNOWN_PORTS = {
    21: ("FTP", "File Transfer"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Remote Login (insecure)"),
    25: ("SMTP", "Email Sending"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web Server"),
    110: ("POP3", "Email Retrieval"),
    111: ("RPCBind", "RPC Port Mapper"),
    135: ("MSRPC", "Windows RPC"),
    139: ("NetBIOS", "Windows Sharing"),
    143: ("IMAP", "Email Access"),
    443: ("HTTPS", "Secure Web Server"),
    445: ("SMB", "Windows File Sharing"),
    993: ("IMAPS", "Secure IMAP"),
    995: ("POP3S", "Secure POP3"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5900: ("VNC", "Virtual Network Computing"),
    5985: ("WinRM", "Windows Remote Mgmt"),
    6379: ("Redis", "Redis Cache"),
    8080: ("HTTP-Proxy", "Web Proxy / Alt HTTP"),
    8443: ("HTTPS-Alt", "Alt Secure Web"),
    9090: ("Proxy", "Web Proxy"),
    27017: ("MongoDB", "MongoDB Database"),
}

# Ports that are security-relevant
RISKY_PORTS = {23, 21, 135, 139, 445, 1433, 3389, 5900, 5985, 6379, 27017}


# ==========================================
# SCAN LOGIC
# ==========================================

def scan_single_port(target_ip, port, protocol, timeout):
    """Scan a single port. Returns dict with results or None if closed."""
    result = {
        "port": port,
        "protocol": protocol,
        "state": "closed",
        "service": "",
        "banner": "",
        "risky": port in RISKY_PORTS,
    }

    if protocol == "TCP":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((target_ip, port)) == 0:
                    result["state"] = "open"

                    # Service name
                    if port in WELL_KNOWN_PORTS:
                        result["service"] = WELL_KNOWN_PORTS[port][0]
                    else:
                        try:
                            result["service"] = socket.getservbyport(port, "tcp")
                        except Exception:
                            result["service"] = "unknown"

                    # Banner grab
                    try:
                        if port in (80, 443, 8080, 8443):
                            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                        else:
                            sock.sendall(b"\r\n")
                        sock.settimeout(0.8)
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                        if banner:
                            result["banner"] = banner.split("\n")[0][:80]
                    except Exception:
                        pass
                else:
                    return None
        except Exception:
            return None

    elif protocol == "UDP":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(b"\x00", (target_ip, port))
                data, _ = sock.recvfrom(1024)
                result["state"] = "open"
                if port in WELL_KNOWN_PORTS:
                    result["service"] = WELL_KNOWN_PORTS[port][0]
                else:
                    result["service"] = "unknown"
        except Exception:
            return None

    return result


def run_scan(target, protocol, port_spec, timeout, on_port_found, on_progress, on_complete):
    """Run the full scan in a worker thread."""
    try:
        target_ip = socket.gethostbyname(target)
    except Exception:
        on_complete(None, "Invalid target — could not resolve hostname.")
        return

    # Determine port list
    if port_spec == "Top 1024":
        ports = list(range(1, 1025))
    elif port_spec == "All 65535":
        ports = list(range(1, 65536))
    elif port_spec == "Common":
        ports = sorted(WELL_KNOWN_PORTS.keys())
    else:
        ports = list(range(1, 1025))

    total = len(ports)
    protos = []
    if protocol in ("TCP", "BOTH"):
        protos.append("TCP")
    if protocol in ("UDP", "BOTH"):
        protos.append("UDP")

    total_tasks = total * len(protos)
    found = []
    done_count = [0]
    start_time = time.time()

    def _task(port, proto):
        return scan_single_port(target_ip, port, proto, timeout)

    with ThreadPoolExecutor(max_workers=500) as executor:
        futures = {}
        for proto in protos:
            for port in ports:
                f = executor.submit(_task, port, proto)
                futures[f] = (port, proto)

        for future in as_completed(futures):
            done_count[0] += 1
            if done_count[0] % 200 == 0 or done_count[0] == total_tasks:
                pct = int(done_count[0] / total_tasks * 100)
                on_progress(pct, done_count[0], total_tasks)

            result = future.result()
            if result and result["state"] == "open":
                found.append(result)
                on_port_found(result)

    elapsed = time.time() - start_time
    found_sorted = sorted(found, key=lambda r: r["port"])
    on_complete(found_sorted, None, target_ip, elapsed)


# ==========================================
# UI: PORT SCANNER FRAME
# ==========================================

def create_port_scanner_frame(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")

    gt.section_header(
        frame,
        "Network Port Scanner",
        "TCP/UDP port discovery with banner grabbing and service identification.",
    ).pack(anchor="w", pady=(0, 14))

    # --- Summary cards ---
    cards_frame = ctk.CTkFrame(frame, fg_color="transparent")
    cards_frame.pack(fill="x", pady=(0, 8))
    cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

    card_defs = [
        {"key": "target",  "icon": "🎯", "label": "Target"},
        {"key": "open",    "icon": "🔓", "label": "Open Ports"},
        {"key": "risky",   "icon": "⚠️", "label": "Risky Ports"},
        {"key": "time",    "icon": "⏱️", "label": "Scan Time"},
    ]

    card_widgets = {}
    for col, cd in enumerate(card_defs):
        c = ctk.CTkFrame(
            cards_frame, fg_color=gt.CARD_BG, corner_radius=14,
            border_width=1, border_color=gt.CARD_BORDER, height=72,
        )
        c.grid(row=0, column=col, padx=4, sticky="nsew")
        c.grid_propagate(False)

        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text=f"{cd['icon']} {cd['label']}",
                     font=("Segoe UI", 10), text_color="#7a7a8a").pack()
        val = ctk.CTkLabel(inner, text="—",
                           font=("Segoe UI", 22, "bold"), text_color="#6a6a7a")
        val.pack(pady=(2, 0))

        card_widgets[cd["key"]] = {"card": c, "value": val}

    def _set_card(key, text, fg="#d8d8e0", bg=None, border=None):
        w = card_widgets[key]
        w["value"].configure(text=text, text_color=fg)
        if bg:
            w["card"].configure(fg_color=bg)
        if border:
            w["card"].configure(border_color=border)

    def _reset_cards():
        for k, w in card_widgets.items():
            w["card"].configure(fg_color=gt.CARD_BG, border_color=gt.CARD_BORDER)
            w["value"].configure(text="—", text_color="#6a6a7a")

    # --- Controls card ---
    card = gt.control_card(frame)
    card.pack(fill="x", pady=(0, 8))
    ctrl = ctk.CTkFrame(card, fg_color="transparent")
    ctrl.pack(fill="x", padx=14, pady=10)

    ent_target = gt.create_styled_entry(
        ctrl, width=220, placeholder_text="Target IP or domain"
    )
    ent_target.pack(side="left", padx=(0, 8))

    combo_protocol = gt.create_styled_combo(
        ctrl, values=["TCP", "UDP", "BOTH"], width=90, height=38,
    )
    combo_protocol.set("TCP")
    combo_protocol.pack(side="left", padx=(0, 8))

    combo_range = gt.create_styled_combo(
        ctrl, values=["Common", "Top 1024", "All 65535"], width=120, height=38,
    )
    combo_range.set("Top 1024")
    combo_range.pack(side="left", padx=(0, 8))

    # --- Progress bar below controls ---
    progress_row = ctk.CTkFrame(frame, fg_color="transparent", height=18)
    progress_row.pack(fill="x", pady=(0, 2))
    lbl_progress = ctk.CTkLabel(
        progress_row, text="", font=("Consolas", 10), text_color="#5a5a6a",
    )
    lbl_progress.pack(side="right")

    # --- Log textbox ---
    txt_log = gt.create_log_textbox(frame)
    txt_log.pack(fill="both", expand=True, pady=(4, 0))

    _state = {"running": False}

    def log_msg(msg):
        def _append():
            txt_log.insert("end", msg + "\n")
            txt_log.see("end")
        txt_log.after(0, _append)

    def on_port_found(result):
        port = result["port"]
        proto = result["protocol"]
        service = result["service"].upper() if result["service"] else "UNKNOWN"
        banner = result["banner"]
        risky = result["risky"]

        icon = "🚨" if risky else "✅"
        line = f"{icon} {proto} {port:<6} OPEN  [{service}]"
        if risky:
            line += "  ← SECURITY RISK"
        log_msg(line)
        if banner:
            log_msg(f"   └ Banner: {banner}")

    def on_progress(pct, done, total):
        def _update():
            lbl_progress.configure(text=f"{pct}% scanned")
        frame.after(0, _update)

    def on_complete(results, error, target_ip=None, elapsed=0):
        _state["running"] = False

        def _finish():
            btn_scan.configure(state="normal", text="🔍 Scan")

            if error:
                log_msg(f"❌ {error}")
                _set_card("target", "Error", fg="#e05555")
                lbl_progress.configure(text="")
                return

            log_msg(f"\n{'─' * 50}")
            log_msg(f"Scan complete — {len(results)} open port(s) in {elapsed:.1f}s")
            lbl_progress.configure(text="Done")

            # Update cards
            _set_card("target", target_ip, fg="#d8d8e0")
            open_count = len(results)
            risky_count = sum(1 for r in results if r["risky"])

            if open_count == 0:
                _set_card("open", "0", fg="#4caf7a", bg="#1a3d2e", border="#4caf7a")
            else:
                _set_card("open", str(open_count), fg="#e6a23c", bg="#3d3018", border="#e6a23c")

            if risky_count == 0:
                _set_card("risky", "0", fg="#4caf7a", bg="#1a3d2e", border="#4caf7a")
            else:
                _set_card("risky", str(risky_count), fg="#e05555", bg="#3d1a1a", border="#e05555")

            _set_card("time", f"{elapsed:.1f}s", fg="#d8d8e0")

        frame.after(0, _finish)

    def start_scan():
        target = ent_target.get().strip()
        if not target or _state["running"]:
            return
        _state["running"] = True
        txt_log.delete("1.0", "end")
        _reset_cards()
        _set_card("target", target, fg="#6a6a7a")
        btn_scan.configure(state="disabled", text="⏳ Scanning...")
        lbl_progress.configure(text="0%")

        protocol = combo_protocol.get()
        port_range = combo_range.get()
        timeout = 0.5

        log_msg(f"🔍 Starting {protocol} scan on {target}")
        log_msg(f"   Range: {port_range}  |  Timeout: {timeout}s")
        log_msg(f"{'─' * 50}\n")

        threading.Thread(
            target=run_scan,
            args=(target, protocol, port_range, timeout,
                  on_port_found, on_progress, on_complete),
            daemon=True,
        ).start()

    ctk.CTkButton(
        ctrl, text="Export Report", width=120, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color="#333333", hover_color="#444444",
        command=lambda: utils.export_log(txt_log.get("1.0", "end"), "Port_Scan"),
    ).pack(side="right")

    btn_scan = ctk.CTkButton(
        ctrl, text="🔍 Scan", width=120, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color=gt.ACCENT_BLUE, hover_color=gt.ACCENT_BLUE_HOVER,
        command=start_scan,
    )
    btn_scan.pack(side="left", padx=(0, 8))

    return frame