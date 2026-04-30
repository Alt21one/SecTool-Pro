import customtkinter as ctk
from tkinter import filedialog
import os
import hashlib
import threading
import webbrowser
import requests
import time
from datetime import datetime
from PIL import Image
import sys
import gui_theme as gt
import base64

def obfuscate_key(api_key):
    """Simple encryption: reverses the key, adds salt, and encodes to Base64."""
    # Reverses the key and wraps it in fake text so it's not easily guessed
    salted = f"s3c_{api_key[::-1]}_t00l" 
    return base64.b64encode(salted.encode('utf-8')).decode('utf-8')

def deobfuscate_key(encoded_key):
    """Decrypts the Base64 string back to the original API key."""
    try:
        decoded = base64.b64decode(encoded_key.encode('utf-8')).decode('utf-8')
        # Remove 's3c_' (4 chars) from start and '_t00l' (5 chars) from end, then reverse back
        return decoded[4:-5][::-1]
    except Exception:
        return "" # If someone tampers with the file, it safely returns nothing

# ==========================================
# CONFIG & LOGIC
# ==========================================
TIMESTAMP_FILE = "last_scan.txt"
DATABASE_FILE = "malware_hashes.txt"

class LocalScanner:
    def __init__(self, log_callback, update_time_callback):
        self.log_callback = log_callback
        self.update_time_callback = update_time_callback

    def load_database(self):
        db = set()
        if os.path.exists(DATABASE_FILE):
            with open(DATABASE_FILE, "r") as f:
                for line in f:
                    h = line.strip().replace(";", "").lower()
                    if len(h) == 64: db.add(h)
        return db

    def get_file_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest().lower()
        except Exception:
            return None

    def generate_html_report(self, results, folder_path, threats_found, is_deep_scan=False):
        report_name = f"Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        total_files = len(results)
        clean_files = total_files - threats_found
        
        # Dynamic Risk Assessment
        if threats_found > 0:
            risk_badge = '<span class="badge bg-danger fs-6 px-3 py-2">⚠️ CRITICAL RISK</span>'
            header_color = "text-danger"
        else:
            risk_badge = '<span class="badge bg-success fs-6 px-3 py-2">✅ SYSTEM SECURE</span>'
            header_color = "text-info"

        scan_title = "VirusTotal Cloud Deep Scan" if is_deep_scan else "Offline Signature Scan"
        engine_type = "VirusTotal API v3" if is_deep_scan else "Local Hash Database"
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SecTool Pro - Incident Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --bg-dark: #0f172a;
                    --card-bg: #1e293b;
                    --border-color: #334155;
                    --text-main: #f8fafc;
                    --text-muted: #94a3b8;
                    --accent-cyan: #38bdf8;
                    --accent-red: #ef4444;
                    --accent-green: #10b981;
                }}
                body {{ 
                    background-color: var(--bg-dark); 
                    color: var(--text-main); 
                    font-family: 'Inter', sans-serif; 
                    padding: 40px 20px; 
                }}
                .dashboard-container {{ max-width: 1400px; margin: auto; }}
                .glass-card {{ 
                    background-color: var(--card-bg); 
                    border: 1px solid var(--border-color); 
                    border-radius: 12px; 
                    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
                }}
                .stat-card {{
                    background-color: #151e2e;
                    border: none;
                    border-radius: 10px;
                    transition: transform 0.2s;
                }}
                .stat-card:hover {{ transform: translateY(-3px); }}
                .stat-total {{ border-bottom: 4px solid var(--accent-cyan); }}
                .stat-threat {{ border-bottom: 4px solid var(--accent-red); background-image: linear-gradient(to top, rgba(239, 68, 68, 0.05), transparent); }}
                .stat-clean {{ border-bottom: 4px solid var(--accent-green); }}
                
                /* --- FIXED TABLE CSS --- */
                .table-custom {{ color: var(--text-main); vertical-align: middle; border-collapse: separate; border-spacing: 0 8px; }}
                .table-custom thead th {{ 
                    background-color: transparent !important; 
                    border-bottom: 2px solid var(--border-color); 
                    color: var(--text-muted) !important; 
                    font-weight: 600; 
                    text-transform: uppercase; 
                    font-size: 0.85rem; 
                    letter-spacing: 0.5px; 
                }}
                .table-custom tbody tr {{ box-shadow: 0 2px 4px rgba(0,0,0,0.2); }}
                
                /* Force Dark Backgrounds on Table Data Cells */
                .table-custom tbody td {{ 
                    background-color: var(--card-bg) !important; 
                    color: var(--text-main) !important;
                    border-top: 1px solid var(--border-color); 
                    border-bottom: 1px solid var(--border-color); 
                    padding: 16px; 
                }}
                .table-custom tbody td:first-child {{ border-left: 1px solid var(--border-color); border-top-left-radius: 8px; border-bottom-left-radius: 8px; }}
                .table-custom tbody td:last-child {{ border-right: 1px solid var(--border-color); border-top-right-radius: 8px; border-bottom-right-radius: 8px; }}
                
                /* Threat Row Customization */
                .threat-row td {{ 
                    background-color: rgba(239, 68, 68, 0.15) !important; 
                    border-color: rgba(239, 68, 68, 0.3) !important; 
                }}
                .threat-row .hash-font {{ color: #fca5a5 !important; }} /* Light red for readability */
                
                .hash-font {{ font-family: 'Fira Code', monospace; font-size: 0.85em; color: var(--text-muted); }}
                .vt-btn {{ font-weight: 600; border-radius: 6px; letter-spacing: 0.5px; transition: all 0.2s; }}
                code {{ background-color: #0f172a; padding: 4px 8px; border-radius: 4px; color: var(--accent-cyan); }}
            </style>
        </head>
        <body>
            <div class="container-fluid dashboard-container">
                <div class="glass-card p-5 mb-5">
                    <div class="d-flex justify-content-between align-items-start mb-4">
                        <div>
                            <h1 class="display-6 fw-bold {header_color} mb-2">🛡️ SecTool Pro Audit</h1>
                            <h4 class="text-secondary fw-normal">{scan_title}</h4>
                        </div>
                        <div>
                            {risk_badge}
                        </div>
                    </div>
                    
                    <div class="d-flex flex-wrap gap-3 text-secondary mb-5 fs-6">
                        <span><strong>📅 Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span> |
                        <span><strong>🎯 Target:</strong> <code>{folder_path}</code></span> |
                        <span><strong>⚙️ Engine:</strong> {engine_type}</span>
                    </div>
                    
                    <div class="row text-center g-4 mb-5">
                        <div class="col-md-4">
                            <div class="card stat-card stat-total p-4">
                                <h6 class="text-uppercase text-muted fw-bold mb-3">Total Files Scanned</h6>
                                <h2 class="display-5 text-info fw-bold mb-0">{total_files}</h2>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card stat-card stat-threat p-4">
                                <h6 class="text-uppercase text-muted fw-bold mb-3">Threats Detected</h6>
                                <h2 class="display-5 text-danger fw-bold mb-0">{threats_found}</h2>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card stat-card stat-clean p-4">
                                <h6 class="text-uppercase text-muted fw-bold mb-3">Clean / Unknown</h6>
                                <h2 class="display-5 text-success fw-bold mb-0">{clean_files}</h2>
                            </div>
                        </div>
                    </div>

                    <h5 class="fw-bold mb-3">File Analysis Breakdown</h5>
                    <div class="table-responsive">
                        <table class="table table-custom table-hover">
                            <thead>
                                <tr>
                                    <th>Status</th>
                                    <th>File Name</th>
        """
        
        if is_deep_scan:
            html_content += """<th>VT Score</th>"""
            
        html_content += """<th>SHA-256 Signature</th>"""
        
        if is_deep_scan:
             html_content += """<th class="text-end">Action</th>"""
             
        html_content += """
                                </tr>
                            </thead>
                            <tbody>
        """
        
        # Sort results so threats appear at the top
        results.sort(key=lambda x: x['status'] != 'Malware')

        for r in results:
            if r['status'] == "Malware":
                row_class = "threat-row"
                status_badge = '<span class="badge bg-danger px-2 py-1"><i class="bi bi-bug-fill"></i> MALWARE</span>'
            elif r['status'] == "Unknown":
                row_class = ""
                status_badge = '<span class="badge bg-secondary px-2 py-1">UNKNOWN</span>'
            elif r['status'] == "Rate Limited":
                row_class = ""
                status_badge = '<span class="badge bg-warning text-dark px-2 py-1">SKIPPED</span>'
            else:
                row_class = ""
                status_badge = '<span class="badge bg-success px-2 py-1">CLEAN</span>'

            html_content += f'<tr class="{row_class}">\n<td>{status_badge}</td>\n<td class="fw-bold text-light">{r["file"]}</td>\n'
            
            # Inject VT Score
            if is_deep_scan:
                score_color = "danger" if r['status'] == "Malware" else "success" if r['status'] == "Clean" else "secondary"
                vt_score = r.get("vt_score", "N/A")
                html_content += f'<td><span class="badge border border-{score_color} text-{score_color} bg-transparent">{vt_score}</span></td>\n'
            
            html_content += f'<td class="hash-font">{r["hash"]}</td>\n'
            
            # Inject VT Link Button
            if is_deep_scan:
                vt_link = r.get("vt_link", "#")
                if r['status'] == "Rate Limited":
                    html_content += '<td class="text-end"><button class="btn btn-sm btn-outline-secondary vt-btn" disabled>Unavailable</button></td>\n'
                else:
                    html_content += f'<td class="text-end"><a href="{vt_link}" target="_blank" class="btn btn-sm btn-outline-info vt-btn">View Details</a></td>\n'

            html_content += "</tr>\n"
        
        html_content += """
                            </tbody>
                        </table>
                    </div>
                    <div class="mt-5 text-center">
                        <p class="text-muted small">Generated securely by <strong>SecTool Pro</strong>. Always verify findings independently.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(report_name, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        webbrowser.open(f"file://{os.path.abspath(report_name)}")

    def update_global_stats(self, threats):
        import json
        stats_file = "sectool_stats.json"
        stats = {"threats": 0}
        if os.path.exists(stats_file):
            try:
                with open(stats_file, "r") as f: stats = json.load(f)
            except: pass
        stats["threats"] += threats
        with open(stats_file, "w") as f: json.dump(stats, f)

    def run_folder_audit(self, folder_path):
        """The original lightning-fast offline scan."""
        results = []
        threats = 0
        try:
            self.log_callback("Loading local database...")
            db = self.load_database()
            self.log_callback(f"Database loaded. ({len(db)} signatures)")

            all_files = []
            for root, dirs, files in os.walk(folder_path):
                for name in files:
                    all_files.append(os.path.join(root, name))

            total_files = len(all_files)
            if total_files == 0:
                self.log_callback("⚠️ Folder is empty. Nothing to scan.")
                return

            self.log_callback(f"Starting lightning scan on {total_files} files...")

            for i, file_path in enumerate(all_files):
                file_name = os.path.basename(file_path)
                
                if i % 10 == 0 or i == total_files - 1:
                    self.log_callback(f"Scanning ({i+1}/{total_files}): {file_name[:25]}...")
                
                file_hash = self.get_file_hash(file_path)
                if not file_hash: continue
                
                status = "Clean"
                if file_hash in db:
                    status = "Malware"
                    threats += 1

                results.append({'status': status, 'file': file_name, 'hash': file_hash})

            self.log_callback("Generating HTML Report...")
            self.generate_html_report(results, folder_path, threats, is_deep_scan=False)
            
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(TIMESTAMP_FILE, "w") as f: f.write(now_str)
            self.update_time_callback(now_str)
            self.update_global_stats(threats)
            
            self.log_callback(f"✅ Scan Complete. Threats found: {threats}")

        except Exception as e:
            self.log_callback(f"❌ Error: {str(e)}")

    def run_deep_audit(self, folder_path, api_key):
        """The new VirusTotal Cloud scan."""
        results = []
        threats = 0
        try:
            all_files = []
            for root, dirs, files in os.walk(folder_path):
                for name in files:
                    all_files.append(os.path.join(root, name))

            total_files = len(all_files)
            if total_files == 0:
                self.log_callback("⚠️ Folder is empty. Nothing to scan.")
                return

            self.log_callback(f"☁️ Starting Deep Cloud Scan on {total_files} files...")
            self.log_callback("⚠️ Note: VirusTotal allows 4 files per minute on free tier.")
            
            headers = {"x-apikey": api_key}

            for i, file_path in enumerate(all_files):
                file_name = os.path.basename(file_path)
                self.log_callback(f"Deep Scanning ({i+1}/{total_files}): {file_name[:25]}...")
                
                file_hash = self.get_file_hash(file_path)
                if not file_hash: continue
                
                status = "Clean"
                vt_score = "N/A"
                vt_link = f"https://www.virustotal.com/gui/file/{file_hash}"

                try:
                    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                    response = requests.get(url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        stats = data['data']['attributes']['last_analysis_stats']
                        
                        malicious = stats.get('malicious', 0)
                        undetected = stats.get('undetected', 0)
                        harmless = stats.get('harmless', 0)
                        suspicious = stats.get('suspicious', 0)
                        
                        total_scans = malicious + undetected + harmless + suspicious
                        vt_score = f"{malicious}/{total_scans}"
                        
                        if malicious > 0:
                            status = "Malware"
                            threats += 1
                            
                    # --- NEW: Catch Invalid API Keys ---
                    elif response.status_code == 401:
                        status = "Auth Error"
                        vt_score = "Invalid Key"
                        self.log_callback("❌ API Key is invalid or expired. Stopping scan.")
                        results.append({'status': status, 'file': file_name, 'hash': file_hash, 'vt_score': vt_score, 'vt_link': vt_link})
                        break # Immediately stops scanning the rest of the folder
                    # -----------------------------------
                    
                    elif response.status_code == 404:
                        self.log_callback(f"📤 Uploading new file: {file_name}...")
                        with open(file_path, "rb") as f:
                            files = {"file": (file_name, f)}    
                            upload_url = "https://www.virustotal.com/api/v3/files"
                            upload_res = requests.post(upload_url, headers=headers, files=files)
                            if upload_res.status_code == 200:
                                status = "Analysis Pending"
                                vt_score = "Queued"
                                self.log_callback(f"✅ {file_name} sent for analysis.")
                            else:
                                status = "Upload Failed"


                    elif response.status_code == 429:
                        status = "Rate Limited"
                        vt_score = "Limit Hit"
                        self.log_callback("⚠️ API Rate limit hit! Try scanning fewer files.")
                except Exception:
                    status = "Unknown"

                results.append({
                    'status': status, 
                    'file': file_name, 
                    'hash': file_hash,
                    'vt_score': vt_score,
                    'vt_link': vt_link
                })

                # time.sleep(15) # Uncomment to avoid rate limits

            self.log_callback("Generating HTML Report...")
            self.generate_html_report(results, folder_path, threats, is_deep_scan=True)
            
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(TIMESTAMP_FILE, "w") as f: f.write(now_str)
            self.update_time_callback(now_str)
            self.update_global_stats(threats)
            
            self.log_callback(f"✅ Deep Scan Complete. Threats found: {threats}")

        except Exception as e:
            self.log_callback(f"❌ Error: {str(e)}")


# ==========================================
# UI: ROCKET DASHBOARD
# ==========================================
def create_malscan_frame(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")

    # Last Scanned Text
    last_time = "Never"
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE, "r") as f: last_time = f.read()

    lbl_status = ctk.CTkLabel(frame, text=f"Last time scanned was : {last_time}", 
                              font=("Segoe UI", 16, "bold"), text_color="#ff4d4d")
    lbl_status.pack(pady=20)

    # Rocket Image
    # ==========================================
    # Rocket Image (Fixed for PyInstaller)
    # ==========================================
    if hasattr(sys, '_MEIPASS'):
        base_dir = sys._MEIPASS
    else:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.join(current_dir, "..")
        
    rocket_path = os.path.join(base_dir, "rocket.png")
    shield_path = os.path.join(base_dir, "cyber-security.png")
    
    img_path = rocket_path if os.path.exists(rocket_path) else shield_path
    
    if os.path.exists(img_path):
        img = ctk.CTkImage(Image.open(img_path), size=(180, 180))
        ctk.CTkLabel(frame, text="", image=img).pack(pady=20)
    # ==========================================

    # Status Info
    lbl_info = ctk.CTkLabel(frame, text="Select a folder to scan for malware", text_color="gray")
    lbl_info.pack()

    txt_mini_log = ctk.CTkLabel(frame, text="", text_color="cyan", font=("Consolas", 11))
    txt_mini_log.pack(pady=10)

    def update_ui_time(new_time):
        lbl_status.configure(text=f"Last time scanned was : {new_time}", text_color="#00ff88")

    def start_local_scan():
        path = filedialog.askdirectory(title="Select Folder to Scan")
        if not path: return
        scanner = LocalScanner(lambda m: txt_mini_log.configure(text=m), update_ui_time)
        threading.Thread(target=scanner.run_folder_audit, args=(path,), daemon=True).start()

    def start_deep_scan():
        dialog = ctk.CTkToplevel(frame)
        dialog.title("VirusTotal API Key")
        dialog.geometry("550x350")
        dialog.minsize(550, 350) # Enforce minimum size so it doesn't shrink
        
        lbl = ctk.CTkLabel(dialog, text="VirusTotal API Key Required", font=gt.FONT_HEAD)
        lbl.pack(pady=(20, 5))
        
        info_lbl = ctk.CTkLabel(dialog, text="Get a free key at virustotal.com to enable cloud scanning.", font=gt.FONT_SMALL, text_color=gt.MUTED)
        info_lbl.pack(pady=(0, 15))
        
        entry_key = gt.create_styled_entry(dialog, width=400, placeholder_text="Enter your API Key here...")
        entry_key.pack(pady=5)
        
        # --- UPDATED: Load and DECRYPT the saved key ---
        if os.path.exists("vt_apikey.txt"):
            try:
                with open("vt_apikey.txt", "r") as f:
                    saved_data = f.read().strip()
                    if saved_data:
                        decrypted_key = deobfuscate_key(saved_data)
                        if decrypted_key:
                            entry_key.insert(0, decrypted_key)
            except Exception:
                pass
        # -----------------------------------------------
        
        # New: Label to show errors directly in the window
        error_lbl = ctk.CTkLabel(dialog, text="", text_color="red")
        error_lbl.pack(pady=(5, 0))
        
        def on_submit(event=None):
            key = entry_key.get().strip()
            if not key:
                return
            
            # Show a loading state
            error_lbl.configure(text="Validating key... please wait.", text_color="#38bdf8")
            dialog.update() # Force UI to show the text
            
            try:
                # Test the key with a fake hash
                test_url = "https://www.virustotal.com/api/v3/files/0000000000000000000000000000000000000000000000000000000000000000"
                res = requests.get(test_url, headers={"x-apikey": key}, timeout=7)
                
                # 401 (Unauthorized) or 403 (Forbidden) means the key is completely wrong
                if res.status_code in [401, 403]:
                    error_lbl.configure(text="❌ Invalid API Key. Please check and try again.", text_color="red")
                    return # HARD STOP: Do not close window, do not scan
                
                # 404 (Not Found) is actually SUCCESS for us. It means the key worked, but the fake file isn't in their database.
                elif res.status_code != 404 and res.status_code != 200:
                    error_lbl.configure(text=f"❌ VirusTotal API Error ({res.status_code}). Try again later.", text_color="red")
                    return # HARD STOP
                    
            except requests.RequestException:
                # This triggers if the user has no internet connection or VT is completely down
                error_lbl.configure(text="❌ Network Error. Check your internet connection.", text_color="red")
                return # HARD STOP
                
            # --- IF THE CODE REACHES HERE, THE KEY IS 100% VALID ---
            
            # --- UPDATED: ENCRYPT the valid key before saving ---
            try:
                with open("vt_apikey.txt", "w") as f:
                    f.write(obfuscate_key(key))
            except Exception as e:
                print(f"Could not save key: {e}")
            # ----------------------------------------------------
            
            dialog.destroy()
            path = filedialog.askdirectory(title="Select Folder to Deep Scan")
            if not path: return
            
            scanner = LocalScanner(lambda m: txt_mini_log.configure(text=m), update_ui_time)
            threading.Thread(target=scanner.run_deep_audit, args=(path, key), daemon=True).start()
            
        entry_key.bind("<Return>", on_submit)
            
        try:
            # Wrapped in a try-except to catch missing 'gt' theme variables
            btn_submit = ctk.CTkButton(dialog, text="Start Deep Scan", command=on_submit, 
                                       font=gt.FONT_BTN, corner_radius=gt.CORNER_RADIUS, 
                                       fg_color=gt.ACCENT_BLUE, hover_color=gt.ACCENT_BLUE_HOVER, height=40)
            btn_submit.pack(pady=20)
        except AttributeError as e:
            # Fallback if a variable is missing in gui_theme.py
            print(f"Theme Error: {e}")
            btn_submit = ctk.CTkButton(dialog, text="Start Deep Scan", command=on_submit, height=40)
            btn_submit.pack(pady=20)

        # Move these to the END: Initialize window state only after all widgets are packed
        dialog.transient(frame.winfo_toplevel())
        dialog.grab_set()
        dialog.focus()

    btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
    btn_frame.pack(pady=20)

    btn_scan = ctk.CTkButton(btn_frame, text="Scan Now (Offline)", fg_color="#2ecc71", hover_color="#27ae60",
                             height=50, width=220, font=("Segoe UI", 16, "bold"), corner_radius=15,
                             command=start_local_scan)
    btn_scan.pack(pady=(0, 15))

    btn_deep = ctk.CTkButton(btn_frame, text="Deep Scan (VirusTotal)", fg_color="#F57C00", hover_color="#EF6C00",
                             height=50, width=220, font=("Segoe UI", 16, "bold"), corner_radius=15,
                             command=start_deep_scan)
    btn_deep.pack()

    return frame