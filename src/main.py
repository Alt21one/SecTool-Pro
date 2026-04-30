import customtkinter as ctk
import os
import threading
import requests
from PIL import Image
import sys

# Import your external modules
import portscanner
import emailchecker
import vulnscanner
import netmapper
import malscan
import HIDS
import utils


# ==========================================
# GUI CONFIGURATION
# ==========================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def load_icon(filename, size=(25, 25)):
    # 1. Figure out the base path (EXE temp folder OR project root)
    if hasattr(sys, '_MEIPASS'):
        base_dir = sys._MEIPASS
    else:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.join(current_dir, "..")
    
    # 2. Handle the specific location of the main logo vs other icons
    make_white = True
    if filename == "cyber-security.png":
        # The main logo is in the root folder, not the icons folder
        icon_path = os.path.join(base_dir, filename)
        make_white = False # FORCE it to keep its original blue color
    else:
        # All other icons are in the icons folder
        icon_path = os.path.join(base_dir, "icons", filename)
    
    # 3. Load and optionally colorize
    if os.path.exists(icon_path):
        img = Image.open(icon_path).convert("RGBA")
        
        # Only turn it white if it's NOT the main logo
        if make_white:
            r, g, b, a = img.split()
            gray = Image.new("L", img.size, 220)
            img = Image.merge("RGBA", (gray, gray, gray, a))
            
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    return None

# ==========================================
# LOGIC: VULN SCANNER (Still in main.py)
# ==========================================
def run_vuln_scan(url, txt):
    def log(msg): txt.after(0, lambda: txt.insert("end", msg + "\n"))
    if not url.startswith("http"): url = "https://" + url
    log(f"Scanning {url}...")
    try:
        r = requests.get(url, timeout=5)
        headers = ["Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy"]
        for h in headers:
            status = "✅ FOUND" if h in r.headers else "❌ MISSING"
            log(f"{h}: {status}")
    except Exception as e: log(f"Error: {e}")

# ==========================================
# DASHBOARD GENERATOR (Upgraded)
# ==========================================
def create_dashboard_frame(parent):
    import json
    import platform
    import socket
    import uuid
    import re
    
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    
    # 1. Header
    header = ctk.CTkFrame(frame, fg_color="transparent")
    header.pack(fill="x", pady=(0, 14))
    
    ctk.CTkLabel(header, text="System Overview",
                 font=("Segoe UI", 28, "bold"), text_color="#ececf0").pack(anchor="w")
    
    last_scan = "Never"
    if os.path.exists("last_scan.txt"):
        try:
            with open("last_scan.txt", "r") as f:
                last_scan = f.read().strip()
        except Exception:
            pass
    
    scan_color = "#4CAF50" if last_scan != "Never" else "#888"
    ctk.CTkLabel(header, text=f"Last Threat Scan: {last_scan}",
                 text_color=scan_color, font=("Segoe UI", 13)).pack(anchor="w", pady=(4, 0))

    # 2. Stat cards row
    stats_frame = ctk.CTkFrame(frame, fg_color="transparent")
    stats_frame.pack(fill="x", pady=(0, 10))
    stats_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

    # Load dynamic data
    db_size = 0
    if os.path.exists("malware_hashes.txt"):
        try:
            db_size = sum(1 for _ in open("malware_hashes.txt", "r"))
        except Exception:
            pass
    threats = 0
    if os.path.exists("sectool_stats.json"):
        try:
            with open("sectool_stats.json", "r") as f:
                threats = json.load(f).get("threats", 0)
        except Exception:
            pass

    score_val = max(0, 100 - (threats * 4))
    if score_val <= 60:
        score_color = "#e05555"
        score_bg = "#3d1a1a"
    elif score_val <= 95:
        score_color = "#e6a23c"
        score_bg = "#3d3018"
    else:
        score_color = "#4caf7a"
        score_bg = "#1a3d2e"

    hostname = socket.gethostname()
    ip_addr = socket.gethostbyname(hostname)

    # OS info
    os_name = platform.system()
    os_ver = platform.version()
    os_release = platform.release()

    card_defs = [
        ("🛡️ Signatures", f"{db_size:,}", "#3d7dd4", None),
        ("🔴 Threats", str(threats), "#e05555" if threats > 0 else "#4caf7a",
         "#3d1a1a" if threats > 0 else "#1a3d2e"),
        ("📊 Score", f"{score_val}%", score_color, score_bg),
        ("💻 System", f"{os_name} {os_release}", "#d8d8e0", None),
        ("🌐 IP", ip_addr, "#d8d8e0", None),
    ]

    for col, (label, value, fg, bg) in enumerate(card_defs):
        card = ctk.CTkFrame(
            stats_frame, fg_color=bg or "#22222a", corner_radius=14,
            border_width=1, border_color="#34343f", height=85,
        )
        card.grid(row=0, column=col, padx=4, sticky="nsew")
        card.grid_propagate(False)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(inner, text=label,
                     font=("Segoe UI", 12), text_color="#7a7a8a").pack()
        ctk.CTkLabel(inner, text=value,
                     font=("Segoe UI", 15, "bold"), text_color=fg).pack(pady=(2, 0))

    # 3. Shield + system info side by side
    mid_frame = ctk.CTkFrame(frame, fg_color="transparent")
    mid_frame.pack(fill="both", expand=True, pady=(6, 6))
    mid_frame.grid_columnconfigure(0, weight=1)
    mid_frame.grid_columnconfigure(1, weight=2)
    mid_frame.grid_rowconfigure(0, weight=1)

    # Shield image
    shield_card = ctk.CTkFrame(mid_frame, fg_color="#22222a", corner_radius=14,
                               border_width=1, border_color="#34343f")
    shield_card.grid(row=0, column=0, padx=(0, 6), sticky="nsew")

    shield_img = load_icon("cyber-security.png", size=(120, 120))
    if shield_img:
        ctk.CTkLabel(shield_card, text="", image=shield_img).place(
            relx=0.5, rely=0.4, anchor="center")

    status_text = "Protected" if threats == 0 else f"{threats} Threat{'s' if threats != 1 else ''} Found"
    status_clr = "#4caf7a" if threats == 0 else "#e05555"
    ctk.CTkLabel(shield_card, text=status_text,
                 font=("Segoe UI", 14, "bold"), text_color=status_clr).place(
        relx=0.5, rely=0.78, anchor="center")

    # System details card
    info_card = ctk.CTkFrame(mid_frame, fg_color="#22222a", corner_radius=14,
                             border_width=1, border_color="#34343f")
    info_card.grid(row=0, column=1, padx=(6, 0), sticky="nsew")

    info_inner = ctk.CTkFrame(info_card, fg_color="transparent")
    info_inner.pack(fill="both", expand=True, padx=20, pady=16)

    ctk.CTkLabel(info_inner, text="System Information",
                 font=("Segoe UI", 15, "bold"), text_color="#ececf0").pack(anchor="w", pady=(0, 10))

    mac_addr = ':'.join(re.findall('..', '%012x' % uuid.getnode())).upper()
    proc = platform.processor() or "Unknown"
    if len(proc) > 45:
        proc = proc[:45] + "..."

    info_rows = [
        ("Hostname", hostname),
        ("Internal IP", ip_addr),
        ("MAC Address", mac_addr),
        ("OS", f"{os_name} {os_release} (Build {os_ver})"),
        ("Architecture", platform.machine()),
        ("Processor", proc),
        ("Python", platform.python_version()),
    ]

    for label, value in info_rows:
        row = ctk.CTkFrame(info_inner, fg_color="transparent")
        row.pack(fill="x", pady=2)
        ctk.CTkLabel(row, text=f"{label}:", width=110, anchor="w",
                     font=("Segoe UI", 11), text_color="#7a7a8a").pack(side="left")
        ctk.CTkLabel(row, text=value, anchor="w",
                     font=("Consolas", 11), text_color="#d8d8e0").pack(side="left")

    # 4. Bottom bar
    bottom = ctk.CTkFrame(frame, fg_color="#1a1a22", corner_radius=12, height=36)
    bottom.pack(fill="x", pady=(6, 0))
    bottom.pack_propagate(False)
    ctk.CTkLabel(
        bottom, text=f"SecTool Pro  •  {hostname}  •  {ip_addr}  •  {mac_addr}",
        font=("Consolas", 10), text_color="#5a5a6a",
    ).place(relx=0.5, rely=0.5, anchor="center")

    return frame
# ==========================================
# MAIN APPLICATION
# ==========================================
def main():
    app = ctk.CTk()
    app.title("SecTool Pro")
    app.geometry("950x650")
    app.configure(fg_color="#1a1a1a")

    app.grid_rowconfigure(0, weight=1)
    app.grid_columnconfigure(1, weight=1)

    # --- SIDEBAR ---
    sidebar = ctk.CTkFrame(app, width=75, corner_radius=0, fg_color="#111111")
    sidebar.grid(row=0, column=0, sticky="nsew")
    sidebar.grid_propagate(False)

    logo_icon = load_icon("cyber-security.png", size=(40, 40))
    btn_nav_home = ctk.CTkButton(sidebar, text="", image=logo_icon, width=65, height=60, 
                                 fg_color="transparent", hover_color="#2b2b2b", 
                                 corner_radius=12, command=lambda: select_frame("home"))
    btn_nav_home.grid(row=0, column=0, pady=(25, 30), padx=5)

    btn_args = {"compound": "top", "width": 65, "height": 60, "fg_color": "transparent", 
                "hover_color": "#2b2b2b", "corner_radius": 12, "font": ("Segoe UI", 10, "bold")}

    # --- MAIN CONTAINER ---
    container = ctk.CTkFrame(app, corner_radius=25, fg_color="#242424", border_width=1, border_color="#333333")
    container.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
    
    view = ctk.CTkFrame(container, fg_color="transparent")
    view.pack(fill="both", expand=True, padx=25, pady=25)

    # --- INITIALIZE TABS ---
    frame_home = create_dashboard_frame(view)
    frame_malware = malscan.create_malscan_frame(view)
    frame_vuln = vulnscanner.create_vulnscanner_frame(view)
    frame_port = portscanner.create_port_scanner_frame(view)
   # frame_fim = FIM.create_fim_frame(view)
    frame_hids = HIDS.create_hids_frame(view)
    frame_map = netmapper.create_netmapper_frame(view)
    frame_email = emailchecker.create_email_checker_frame(view)


    # --- SIDEBAR BUTTONS ---
    btn_nav_malware = ctk.CTkButton(sidebar, text="Malware", image=load_icon("malware.png"), command=lambda: select_frame("malware"), **btn_args)
    btn_nav_malware.grid(row=1, column=0, pady=5)

    btn_nav_vuln = ctk.CTkButton(sidebar, text="Vuln", image=load_icon("vuln.png"), command=lambda: select_frame("vuln"), **btn_args)
    btn_nav_vuln.grid(row=2, column=0, pady=5)

    btn_nav_port = ctk.CTkButton(sidebar, text="Ports", image=load_icon("port.png"), command=lambda: select_frame("port"), **btn_args)
    btn_nav_port.grid(row=3, column=0, pady=5)

    #btn_nav_fim = ctk.CTkButton(sidebar, text="FIM", image=load_icon("folder.png"), command=lambda: select_frame("fim"), **btn_args)
    #btn_nav_fim.grid(row=4, column=0, pady=5)

    btn_nav_hids = ctk.CTkButton(sidebar, text="HIDS", image=load_icon("hids.png"), command=lambda: select_frame("hids"), **btn_args)
    btn_nav_hids.grid(row=4, column=0, pady=5)

    btn_nav_map = ctk.CTkButton(sidebar, text="Map", image=load_icon("map.png"), command=lambda: select_frame("map"), **btn_args)
    btn_nav_map.grid(row=5, column=0, pady=5)

    btn_nav_email = ctk.CTkButton(sidebar, text="Email", image=load_icon("email.png"), command=lambda: select_frame("email"), **btn_args)
    btn_nav_email.grid(row=6, column=0, pady=5)



    # --- ROUTING LOGIC ---
    def select_frame(name):
        for b in [btn_nav_home, btn_nav_malware, btn_nav_vuln, btn_nav_port, btn_nav_hids,btn_nav_map ,btn_nav_email]:
            b.configure(fg_color="transparent")
        for f in [frame_home, frame_malware, frame_vuln, frame_port, frame_hids, frame_map ,frame_email]:
            f.pack_forget()
        
        if name == "home":
            frame_home.pack(fill="both", expand=True)
            btn_nav_home.configure(fg_color="#2b2b2b")
        elif name == "malware":
            frame_malware.pack(fill="both", expand=True)
            btn_nav_malware.configure(fg_color="#2b2b2b")
        elif name == "vuln":
            frame_vuln.pack(fill="both", expand=True)
            btn_nav_vuln.configure(fg_color="#2b2b2b")
        elif name == "port":
            frame_port.pack(fill="both", expand=True)
            btn_nav_port.configure(fg_color="#2b2b2b")
       # elif name == "fim":
       #     frame_fim.pack(fill="both", expand=True)
       #     btn_nav_fim.configure(fg_color="#2b2b2b")
        elif name == "hids":
            frame_hids.pack(fill="both", expand=True)
            btn_nav_hids.configure(fg_color="#2b2b2b")
        elif name == "email":
            frame_email.pack(fill="both", expand=True)
            btn_nav_email.configure(fg_color="#2b2b2b")
        elif name == "map":
            frame_map.pack(fill="both", expand=True)
            btn_nav_map.configure(fg_color="#2b2b2b")    

    select_frame("home")
    app.mainloop()

if __name__ == "__main__":
    main()