import customtkinter as ctk
import platform
import subprocess
import threading
import winreg
import re
import os
import json
import sys
from datetime import datetime, timedelta
import gui_theme as gt
import utils

# ==========================================
# SCAN CACHE (persist last results)
# ==========================================

def _cache_path():
    """Return path to the scan cache file next to the script."""
    if hasattr(sys, '_MEIPASS'):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
        base = os.path.join(base, "..")
    return os.path.join(base, "vuln_scan_cache.json")


def save_scan_results(counts, log_texts):
    """Save scan results to disk."""
    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "counts": counts,
        "logs": log_texts,
    }
    try:
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def load_scan_results():
    """Load last scan results from disk. Returns None if no cache."""
    try:
        p = _cache_path()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return None

# ==========================================
# HELPERS
# ==========================================

def _run(cmd):
    """Run a command silently and return stdout."""
    try:
        return subprocess.check_output(
            cmd, text=True, encoding="utf-8", errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=30,
        )
    except Exception:
        return ""


def _ps(script):
    """Run a PowerShell one-liner and return stdout."""
    return _run(["powershell", "-NoProfile", "-Command", script])


def _reg_value(hive, path, name):
    """Read a single registry value. Returns None on failure."""
    try:
        key = winreg.OpenKey(hive, path)
        val, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return val
    except Exception:
        return None


# ==========================================
# SCAN CATEGORY 1 — PATCHES & OS VULNS
# ==========================================

def scan_patches(log):
    findings = 0
    log("🩹  CATEGORY 1: Missing Patches & OS-Level Vulnerabilities")
    log("=" * 55)

    # --- OS info ---
    os_ver = f"{platform.system()} {platform.release()} (Build {platform.version()})"
    log(f"💻 OS: {os_ver}")

    # --- Windows Update — last installed hotfix ---
    log("\n📦 Checking installed hotfixes (wmic qfe)...")
    raw = _run(["wmic", "qfe", "list", "brief", "/format:csv"])
    dates = []
    kb_count = 0
    for line in raw.splitlines():
        parts = line.strip().split(",")
        if len(parts) >= 6:
            kb_count += 1
            date_str = parts[-1].strip()
            for fmt in ("%m/%d/%Y", "%Y%m%d", "%d/%m/%Y"):
                try:
                    dates.append(datetime.strptime(date_str, fmt))
                    break
                except ValueError:
                    pass

    if dates:
        latest = max(dates)
        age = (datetime.now() - latest).days
        log(f"   Total KBs installed: {kb_count}")
        log(f"   Most recent patch: {latest.strftime('%Y-%m-%d')} ({age} days ago)")
        if age > 60:
            log("⚠️  FINDING: System has not been patched in over 60 days!")
            findings += 1
        elif age > 30:
            log("⚠️  FINDING: Last patch is over 30 days old.")
            findings += 1
        else:
            log("✅ Patches are relatively up to date.")
    else:
        log("⚠️  FINDING: Could not determine patch history.")
        findings += 1

    # --- PowerShell version ---
    log("\n🔧 Checking PowerShell version...")
    ps_ver = _ps("$PSVersionTable.PSVersion.Major").strip()
    if ps_ver:
        log(f"   PowerShell major version: {ps_ver}")
        try:
            if int(ps_ver) < 5:
                log("⚠️  FINDING: PowerShell version < 5 — upgrade recommended.")
                findings += 1
            else:
                log("✅ PowerShell version is current.")
        except ValueError:
            pass
    else:
        log("❌ Could not determine PowerShell version.")

    # --- .NET Framework ---
    log("\n🔧 Checking .NET Framework version...")
    net_ver = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full",
        "Release"
    )
    if net_ver:
        if net_ver >= 528040:
            log(f"✅ .NET Framework 4.8+ detected (release key: {net_ver}).")
        elif net_ver >= 461808:
            log(f"✅ .NET Framework 4.7.2+ detected (release key: {net_ver}).")
        else:
            log(f"⚠️  FINDING: Older .NET Framework (release key: {net_ver}). Consider updating.")
            findings += 1
    else:
        log("⚠️  .NET Framework 4.x not detected.")

    # --- Risky / outdated software ---
    log("\n📦 Scanning for outdated/risky software...")
    risky_keywords = ["java 8", "java 7", "java 6", "python 2", "flash player",
                      "silverlight", "internet explorer", "adobe reader 9",
                      "adobe reader x", "winrar 4"]
    found_risky = []
    for reg_path in [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]:
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            for i in range(4096):
                try:
                    sub_name = winreg.EnumKey(reg_key, i)
                    sub_key = winreg.OpenKey(reg_key, sub_name)
                    app_name = winreg.QueryValueEx(sub_key, "DisplayName")[0]
                    for risk in risky_keywords:
                        if risk in str(app_name).lower():
                            found_risky.append(app_name)
                except (OSError, FileNotFoundError):
                    continue
        except Exception:
            pass

    if found_risky:
        for app in found_risky:
            log(f"⚠️  FINDING: Outdated/risky software — {app}")
            findings += 1
    else:
        log("✅ No known outdated/risky software detected.")

    log(f"\n{'─' * 55}")
    log(f"🩹 Patches scan complete — {findings} finding(s).\n")
    return findings


# ==========================================
# SCAN CATEGORY 2 — CONFIGURATION & HARDENING
# ==========================================

def scan_config(log):
    findings = 0
    log("🔧  CATEGORY 2: Local Configuration & Hardening Issues")
    log("=" * 55)

    # --- Windows Host Firewall ---
    log("\n🛡️ Checking Windows Host Firewall...")
    fw_out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    profiles_off = []
    current_profile = ""
    for line in fw_out.splitlines():
        line = line.strip()
        if "Profile Settings" in line or "profile" in line.lower() and "settings" in line.lower():
            current_profile = line.split()[0] if line.split() else ""
        if "State" in line and "OFF" in line.upper():
            profiles_off.append(current_profile or "Unknown")

    if profiles_off:
        for p in profiles_off:
            log(f"⚠️  FINDING: Firewall profile disabled — {p}")
            findings += 1
    else:
        log("✅ Windows Host Firewall is ON for all profiles.")

    # --- UAC ---
    log("\n🛡️ Checking UAC (User Account Control)...")
    uac_enabled = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA"
    )
    consent = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin"
    )
    if uac_enabled == 0:
        log("⚠️  FINDING: UAC is DISABLED — highly dangerous!")
        findings += 1
    elif uac_enabled == 1:
        log("✅ UAC is enabled.")
        if consent == 0:
            log("⚠️  FINDING: UAC prompt silenced for admins (ConsentPrompt=0).")
            findings += 1
        elif consent is not None:
            log(f"   Admin consent prompt level: {consent}")
    else:
        log("❌ Could not read UAC status.")

    # --- Windows Defender ---
    log("\n🛡️ Checking Windows Defender...")
    defender = _ps(
        "try { $s = Get-MpComputerStatus; "
        "Write-Output \"RTP=$($s.RealTimeProtectionEnabled)|"
        "SIGS=$($s.AntivirusSignatureLastUpdated)\" } "
        "catch { Write-Output 'UNAVAILABLE' }"
    ).strip()
    if "UNAVAILABLE" in defender or not defender:
        log("⚠️  Windows Defender status unavailable (may be replaced by 3rd-party AV).")
    else:
        if "RTP=True" in defender:
            log("✅ Real-Time Protection is ON.")
        elif "RTP=False" in defender:
            log("⚠️  FINDING: Real-Time Protection is OFF!")
            findings += 1
        sig_match = re.search(r"SIGS=(.+)", defender)
        if sig_match:
            log(f"   Signature last updated: {sig_match.group(1)}")

    # --- Remote Desktop ---
    log("\n🖥️ Checking Remote Desktop (RDP)...")
    rdp = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections"
    )
    if rdp == 0:
        log("⚠️  FINDING: Remote Desktop is ENABLED — ensure it's necessary.")
        findings += 1
    elif rdp == 1:
        log("✅ Remote Desktop is disabled.")
    else:
        log("   Could not determine RDP status.")

    # --- SMBv1 ---
    log("\n📁 Checking SMBv1 protocol...")
    smb1 = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "SMB1"
    )
    if smb1 == 1:
        log("⚠️  FINDING: SMBv1 is ENABLED — vulnerable to EternalBlue/WannaCry!")
        findings += 1
    elif smb1 == 0:
        log("✅ SMBv1 is disabled.")
    else:
        # Check via PowerShell as fallback
        smb1_ps = _ps("(Get-SmbServerConfiguration).EnableSMB1Protocol").strip()
        if smb1_ps.lower() == "true":
            log("⚠️  FINDING: SMBv1 is ENABLED!")
            findings += 1
        elif smb1_ps.lower() == "false":
            log("✅ SMBv1 is disabled.")
        else:
            log("   SMBv1 status could not be determined.")

    # --- AutoRun / AutoPlay ---
    log("\n💿 Checking AutoRun/AutoPlay...")
    autorun = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun"
    )
    if autorun and autorun == 255:
        log("✅ AutoRun is disabled for all drives.")
    elif autorun is not None:
        log(f"⚠️  FINDING: AutoRun policy value: {autorun} — not fully disabled.")
        findings += 1
    else:
        log("⚠️  FINDING: AutoRun policy not set (may be enabled by default).")
        findings += 1

    log(f"\n{'─' * 55}")
    log(f"🔧 Configuration scan complete — {findings} finding(s).\n")
    return findings


# ==========================================
# SCAN CATEGORY 3 — SERVICES
# ==========================================

RISKY_SERVICES = {
    "telnet":           "Telnet — insecure remote access",
    "ftpsvc":           "FTP Server — cleartext protocol",
    "snmp":             "SNMP — often misconfigured",
    "remoteregistry":   "Remote Registry — allows remote registry editing",
    "winrm":            "WinRM — remote management",
    "sshd":             "OpenSSH Server — verify access controls",
    "w3svc":            "IIS Web Server — verify configuration",
    "msftpsvc":         "Microsoft FTP — cleartext protocol",
}


def scan_services(log):
    findings = 0
    log("⚙️  CATEGORY 3: Services Audit")
    log("=" * 55)

    # --- Running services ---
    log("\n🔍 Enumerating running services...")
    raw = _run(["sc", "query", "type=", "service", "state=", "running"])

    running = []
    current_name = ""
    for line in raw.splitlines():
        line = line.strip()
        m = re.match(r"SERVICE_NAME:\s+(.+)", line, re.IGNORECASE)
        if m:
            current_name = m.group(1).strip()
        if "RUNNING" in line and current_name:
            running.append(current_name)
            current_name = ""

    log(f"   Total running services: {len(running)}")

    # --- Flag risky services ---
    log("\n🚨 Checking for risky/unnecessary services...")
    flagged = []
    for svc in running:
        svc_lower = svc.lower()
        for key, desc in RISKY_SERVICES.items():
            if key in svc_lower:
                flagged.append((svc, desc))
                break

    if flagged:
        for svc, desc in flagged:
            log(f"⚠️  FINDING: {svc} — {desc}")
            findings += 1
    else:
        log("✅ No commonly risky services detected running.")

    # --- Network shares ---
    log("\n📂 Checking network shares...")
    shares_out = _run(["net", "share"])
    default_shares = {"c$", "d$", "e$", "admin$", "ipc$", "print$"}
    custom_shares = []
    for line in shares_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and ":" in parts[1]:
            share_name = parts[0].strip().lower()
            if share_name and share_name not in default_shares:
                custom_shares.append(parts[0].strip())

    if custom_shares:
        for s in custom_shares:
            log(f"⚠️  FINDING: Custom network share — {s}")
            findings += 1
    else:
        log("✅ No custom network shares detected (only defaults).")

    # --- Listening ports summary ---
    log("\n🌐 Checking listening ports...")
    netstat = _run(["netstat", "-an"])
    listening = []
    for line in netstat.splitlines():
        if "LISTENING" in line:
            parts = line.split()
            if parts:
                addr = parts[1] if len(parts) > 1 else ""
                listening.append(addr)

    log(f"   Total listening endpoints: {len(listening)}")
    risky_ports = {"21": "FTP", "23": "Telnet", "25": "SMTP", "135": "RPC",
                   "139": "NetBIOS", "445": "SMB", "3389": "RDP", "5985": "WinRM"}
    for addr in listening:
        port = addr.rsplit(":", 1)[-1] if ":" in addr else ""
        if port in risky_ports:
            log(f"⚠️  FINDING: Port {port} ({risky_ports[port]}) is listening.")
            findings += 1

    log(f"\n{'─' * 55}")
    log(f"⚙️ Services scan complete — {findings} finding(s).\n")
    return findings


# ==========================================
# SCAN CATEGORY 4 — ACCOUNTS & CREDENTIALS
# ==========================================

def scan_accounts(log):
    findings = 0
    log("👤  CATEGORY 4: Local Accounts, Privileges & Credentials")
    log("=" * 55)

    # --- Local accounts ---
    log("\n👥 Enumerating local accounts...")
    users_out = _run(["net", "user"])
    users = []
    in_list = False
    for line in users_out.splitlines():
        if "---" in line:
            in_list = True
            continue
        if in_list:
            if line.strip() == "" or "command completed" in line.lower():
                in_list = False
                continue
            users.extend(line.split())

    log(f"   Local accounts: {', '.join(users) if users else 'None found'}")

    # --- Check Guest account ---
    log("\n👤 Checking Guest account...")
    guest = _run(["net", "user", "Guest"])
    if "Account active" in guest:
        if "Yes" in guest.split("Account active")[1].split("\n")[0]:
            log("⚠️  FINDING: Guest account is ACTIVE!")
            findings += 1
        else:
            log("✅ Guest account is disabled.")
    else:
        log("   Could not determine Guest account status.")

    # --- Admin group members ---
    log("\n🔑 Checking Administrators group...")
    admins_out = _run(["net", "localgroup", "Administrators"])
    admins = []
    in_list = False
    for line in admins_out.splitlines():
        if "---" in line:
            in_list = True
            continue
        if in_list:
            if line.strip() == "" or "command completed" in line.lower():
                break
            admins.append(line.strip())

    if admins:
        log(f"   Admins: {', '.join(admins)}")
        if len(admins) > 3:
            log(f"⚠️  FINDING: {len(admins)} admin accounts — consider reducing.")
            findings += 1
        else:
            log("✅ Admin count is reasonable.")
    else:
        log("   Could not enumerate admin group.")

    # --- Password policy ---
    log("\n🔐 Checking password policy...")
    policy = _run(["net", "accounts"])
    for line in policy.splitlines():
        line = line.strip()
        if "Minimum password length" in line:
            log(f"   {line}")
            m = re.search(r"(\d+)", line)
            if m and int(m.group(1)) < 8:
                log("⚠️  FINDING: Minimum password length < 8 characters!")
                findings += 1
        elif "Maximum password age" in line:
            log(f"   {line}")
        elif "Lockout threshold" in line:
            log(f"   {line}")
            m = re.search(r"(\d+)", line)
            if m and int(m.group(1)) == 0:
                log("⚠️  FINDING: No account lockout threshold — brute force possible!")
                findings += 1
            elif "Never" in line:
                log("⚠️  FINDING: No account lockout threshold!")
                findings += 1

    # --- Auto-logon ---
    log("\n🔓 Checking auto-logon configuration...")
    auto_user = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "DefaultUserName"
    )
    auto_pass = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "DefaultPassword"
    )
    if auto_pass:
        log(f"⚠️  FINDING: Auto-logon with stored password for '{auto_user}'!")
        findings += 1
    elif auto_user:
        log(f"   Auto-logon user set: {auto_user} (no stored password).")
    else:
        log("✅ No auto-logon configured.")

    # --- Credential Guard ---
    log("\n🛡️ Checking Credential Guard...")
    cred_guard = _reg_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\LSA",
        "LsaCfgFlags"
    )
    if cred_guard and cred_guard > 0:
        log("✅ Credential Guard is enabled.")
    else:
        log("⚠️  FINDING: Credential Guard is not enabled.")
        findings += 1

    log(f"\n{'─' * 55}")
    log(f"👤 Accounts scan complete — {findings} finding(s).\n")
    return findings


# ==========================================
# UI: VULNSCANNER FRAME
# ==========================================

SEVERITY_COLORS = {
    "clean":    ("#1a3d2e", "#4caf7a", "✅"),
    "low":      ("#2e3a1a", "#b8cc44", "⚠️"),
    "medium":   ("#3d3018", "#e6a23c", "⚠️"),
    "high":     ("#3d1a1a", "#e05555", "🚨"),
}


def _severity_tier(count):
    if count == 0:
        return "clean"
    if count <= 2:
        return "low"
    if count <= 5:
        return "medium"
    return "high"


def create_vulnscanner_frame(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")

    gt.section_header(
        frame,
        "System Vulnerability Scanner",
        "Local security audit — patches, hardening, services & credentials.",
    ).pack(anchor="w", pady=(0, 14))

    # --- Summary Cards row ---
    cards_frame = ctk.CTkFrame(frame, fg_color="transparent")
    cards_frame.pack(fill="x", pady=(0, 10))
    cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

    card_data = [
        {"key": "patches",  "icon": "🩹", "label": "Patches"},
        {"key": "config",   "icon": "🔧", "label": "Config"},
        {"key": "services", "icon": "⚙️", "label": "Services"},
        {"key": "accounts", "icon": "👤", "label": "Accounts"},
    ]

    card_widgets = {}

    for col, cd in enumerate(card_data):
        card = ctk.CTkFrame(
            cards_frame, fg_color=gt.CARD_BG, corner_radius=14,
            border_width=1, border_color=gt.CARD_BORDER, height=80,
        )
        card.grid(row=0, column=col, padx=5, sticky="nsew")
        card.grid_propagate(False)

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        lbl_icon = ctk.CTkLabel(inner, text=f"{cd['icon']} {cd['label']}",
                                font=("Segoe UI", 12), text_color="#9898a8")
        lbl_icon.pack()

        lbl_count = ctk.CTkLabel(inner, text="—",
                                 font=("Segoe UI", 20, "bold"), text_color="#6a6a7a")
        lbl_count.pack(pady=(2, 0))

        card_widgets[cd["key"]] = {"card": card, "count_label": lbl_count}

    def _update_card(key, count):
        tier = _severity_tier(count)
        bg, fg, icon = SEVERITY_COLORS[tier]
        w = card_widgets[key]
        w["card"].configure(fg_color=bg, border_color=fg)
        w["count_label"].configure(
            text=f"{icon} {count} finding{'s' if count != 1 else ''}",
            text_color=fg,
        )

    # --- Controls card ---
    ctrl_card = gt.control_card(frame)
    ctrl_card.pack(fill="x", pady=(0, 10))
    ctrl_row = ctk.CTkFrame(ctrl_card, fg_color="transparent")
    ctrl_row.pack(fill="x", padx=14, pady=10)

    # --- Tabview ---
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

    tabs = {}
    logs = {}
    for cd in card_data:
        tab = tabview.add(f"  {cd['icon']} {cd['label']}  ")
        txt = gt.create_log_textbox(tab)
        txt.pack(fill="both", expand=True, padx=4, pady=4)
        tabs[cd["key"]] = tab
        logs[cd["key"]] = txt

    def _make_log(key):
        txt = logs[key]

        def log_fn(msg):
            def _append():
                txt.insert("end", msg + "\n")
                txt.see("end")
            txt.after(0, _append)

        return log_fn

    # --- Scan state ---
    _state = {"running": False}

    def _run_category(key, scan_fn):
        txt = logs[key]
        txt.after(0, lambda: txt.delete("1.0", "end"))
        log_fn = _make_log(key)
        count = scan_fn(log_fn)
        frame.after(0, lambda: _update_card(key, count))
        return count

    def run_full_scan():
        if _state["running"]:
            return
        _state["running"] = True
        btn_scan.configure(state="disabled", text="⏳ Scanning...")

        # Reset cards
        for key in card_widgets:
            w = card_widgets[key]
            w["card"].configure(fg_color=gt.CARD_BG, border_color=gt.CARD_BORDER)
            w["count_label"].configure(text="⏳", text_color="#6a6a7a")

        def _worker():
            total = 0
            counts = {}
            for key, fn in [
                ("patches", scan_patches),
                ("config", scan_config),
                ("services", scan_services),
                ("accounts", scan_accounts),
            ]:
                c = _run_category(key, fn)
                counts[key] = c
                total += c

            # Save results to cache
            import time
            time.sleep(0.3)  # let UI flush
            log_texts = {}
            for cd in card_data:
                log_texts[cd["key"]] = logs[cd["key"]].get("1.0", "end").strip()
            save_scan_results(counts, log_texts)

            _state["running"] = False
            frame.after(0, lambda: btn_scan.configure(
                state="normal",
                text=f"🔍 Full Scan ({total} findings)" if total else "🔍 Full Scan — All Clear ✅"
            ))

        threading.Thread(target=_worker, daemon=True).start()

    def run_single(key, fn):
        if _state["running"]:
            return
        _state["running"] = True

        def _worker():
            c = _run_category(key, fn)
            # Save partial update to cache
            import time
            time.sleep(0.3)
            cached = load_scan_results() or {"counts": {}, "logs": {}}
            cached["counts"][key] = c
            cached["logs"][key] = logs[key].get("1.0", "end").strip()
            cached["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                with open(_cache_path(), "w", encoding="utf-8") as f:
                    json.dump(cached, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            _state["running"] = False

        threading.Thread(target=_worker, daemon=True).start()

    # --- Buttons ---
    btn_scan = ctk.CTkButton(
        ctrl_row, text="🔍 Full Scan", width=140, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color=gt.ACCENT_BLUE, hover_color=gt.ACCENT_BLUE_HOVER,
        command=run_full_scan,
    )
    btn_scan.pack(side="left")

    # Individual category buttons
    cat_btns = [
        ("🩹 Patches", "patches", scan_patches, "#3878a8", "#2c6490"),
        ("🔧 Config", "config", scan_config, "#5c6bc0", "#4a5ab0"),
        ("⚙️ Services", "services", scan_services, "#26a69a", "#1e8e82"),
        ("👤 Accounts", "accounts", scan_accounts, "#4d8fac", "#3d7a96"),
    ]
    for text, key, fn, fg, hov in cat_btns:
        ctk.CTkButton(
            ctrl_row, text=text, width=100, height=34,
            corner_radius=10, font=("Segoe UI", 11, "bold"),
            fg_color=fg, hover_color=hov,
            command=lambda k=key, f=fn: run_single(k, f),
        ).pack(side="left", padx=(8, 0))

    # Export button
    def _export():
        combined = ""
        for cd in card_data:
            combined += logs[cd["key"]].get("1.0", "end") + "\n"
        utils.export_log(combined, "Vuln_Scan")

    ctk.CTkButton(
        ctrl_row, text="Export Report", width=120, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color="#333333", hover_color="#444444",
        command=_export,
    ).pack(side="right")

    tabview.pack(fill="both", expand=True, pady=(4, 0))

    # --- Restore last scan on startup ---
    def _restore_cache():
        cached = load_scan_results()
        if not cached:
            return
        ts = cached.get("timestamp", "Unknown")
        counts = cached.get("counts", {})
        log_texts = cached.get("logs", {})

        for key in counts:
            _update_card(key, counts[key])

        for key in log_texts:
            if key in logs and log_texts[key]:
                txt = logs[key]
                txt.insert("end", log_texts[key] + "\n")

        total = sum(counts.values())
        btn_scan.configure(
            text=f"🔍 Full Scan ({total} findings)" if total else "🔍 Full Scan — All Clear ✅"
        )

    frame.after(500, _restore_cache)

    return frame