import customtkinter as ctk
import threading
import requests
import re
import subprocess
import socket
import hashlib
import gui_theme as gt
import utils

# ==========================================
# HELPERS
# ==========================================

def _nslookup(qtype, domain):
    """Run nslookup and return raw output."""
    try:
        return subprocess.check_output(
            ["nslookup", f"-type={qtype}", domain],
            text=True, stderr=subprocess.STDOUT, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        return ""


# ==========================================
# ANALYSIS CHECKS
# ==========================================

def check_format(email):
    """Validate email format via regex."""
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def check_mx(domain, log):
    """Check DNS MX records for the domain."""
    log("\n📧 Checking MX (Mail Exchange) records...")
    raw = _nslookup("mx", domain)
    mx_records = []
    for line in raw.splitlines():
        if "mail exchanger" in line.lower() or "MX preference" in line:
            mx_records.append(line.strip())

    if mx_records:
        log(f"✅ {len(mx_records)} MX record(s) found — domain can receive email.")
        for rec in mx_records[:5]:
            log(f"   └ {rec}")
        return True
    else:
        log("❌ No MX records found — domain cannot receive email!")
        return False


def check_spf(domain, log):
    """Check SPF record in DNS TXT."""
    log("\n🛡️ Checking SPF (Sender Policy Framework)...")
    raw = _nslookup("txt", domain)
    spf_found = False
    for line in raw.splitlines():
        if "v=spf1" in line.lower():
            spf_found = True
            log(f"✅ SPF record found:")
            log(f"   └ {line.strip()}")
            if "-all" in line:
                log("   └ Policy: HARD FAIL (-all) — good, strict.")
            elif "~all" in line:
                log("   └ Policy: SOFT FAIL (~all) — acceptable.")
            elif "?all" in line:
                log("⚠️  Policy: NEUTRAL (?all) — weak, could be spoofed.")
                return "weak"
            elif "+all" in line:
                log("⚠️  Policy: PASS ALL (+all) — dangerous, anyone can spoof!")
                return "bad"
            break

    if not spf_found:
        log("⚠️  No SPF record found — domain vulnerable to email spoofing!")
        return "missing"
    return "ok"


def check_dmarc(domain, log):
    """Check DMARC record."""
    log("\n🛡️ Checking DMARC (Domain-based Message Authentication)...")
    raw = _nslookup("txt", f"_dmarc.{domain}")
    for line in raw.splitlines():
        if "v=dmarc1" in line.lower():
            log(f"✅ DMARC record found:")
            log(f"   └ {line.strip()}")
            if "p=reject" in line.lower():
                log("   └ Policy: REJECT — strong protection.")
            elif "p=quarantine" in line.lower():
                log("   └ Policy: QUARANTINE — moderate protection.")
            elif "p=none" in line.lower():
                log("⚠️  Policy: NONE — monitoring only, no protection.")
                return "weak"
            return "ok"

    log("⚠️  No DMARC record found — phishing via this domain is easier!")
    return "missing"


def check_disposable(email, log):
    """Check if email uses a disposable/burner provider."""
    log("\n🕵️ Checking disposable email databases...")
    try:
        res = requests.get(
            f"https://disposable.debounce.io/?email={email}", timeout=5
        )
        if res.status_code == 200:
            is_disp = res.json().get("disposable", "false") == "true"
            if is_disp:
                log("🚨 WARNING: Disposable / burner email address detected!")
                return True
            else:
                log("✅ Not a known disposable email provider.")
                return False
    except Exception:
        log("⚠️  Could not reach disposable email database.")
    return False


def check_breaches(email, log):
    """Check for data breaches via XposedOrNot API with full details."""
    log("\n🔓 Checking for known data breaches...")
    breaches_list = []

    # --- Step 1: quick check ---
    try:
        res = requests.get(
            f"https://api.xposedornot.com/v1/check-email/{email}", timeout=10
        )
        if res.status_code == 200:
            data = res.json()
            breaches = data.get("breaches", [[]])[0]
            if breaches:
                breaches_list = breaches
        elif res.status_code == 404:
            log("✅ No known data breaches found.")
            return []
        else:
            log("⚠️  Breach database returned an unexpected response.")
            return []
    except Exception:
        log("⚠️  Could not reach breach database.")
        return []

    if not breaches_list:
        log("✅ No known data breaches found — email appears clean.")
        return []

    log(f"🚨 ALERT: Found in {len(breaches_list)} data breach(es)!\n")

    # --- Step 2: get detailed breach analytics ---
    try:
        detail_res = requests.get(
            f"https://api.xposedornot.com/v1/breach-analytics?email={email}",
            timeout=12,
        )
        if detail_res.status_code == 200:
            detail_data = detail_res.json()
            exposed = detail_data.get("ExposedBreaches", {})
            breaches_details = exposed.get("breaches_details", [])

            if breaches_details:
                for bd in breaches_details:
                    name = bd.get("breach", "Unknown")
                    domain = bd.get("domain", "—")
                    date = bd.get("added_date", bd.get("breach_date", "Unknown"))
                    # Trim date to just the date part
                    if "T" in str(date):
                        date = str(date).split("T")[0]
                    records = bd.get("records", "?")
                    data_types = bd.get("xposed_data", bd.get("data", "Unknown"))
                    industry = bd.get("industry", "")
                    password_risk = bd.get("password_risk", "")

                    log(f"   ┌─ 🔴 {name}")
                    log(f"   │  Source:    {domain}")
                    log(f"   │  Date:      {date}")
                    if records and records != "?":
                        log(f"   │  Records:   {records:,}" if isinstance(records, int) else f"   │  Records:   {records}")
                    if industry:
                        log(f"   │  Industry:  {industry}")
                    if data_types and data_types != "Unknown":
                        log(f"   │  Exposed:   {data_types}")
                    if password_risk:
                        log(f"   │  Password:  {password_risk}")
                    log(f"   └{'─' * 40}")
            else:
                # Fallback: just show names
                for b in breaches_list:
                    log(f"   └ {b}")
        else:
            # Fallback: just names
            for b in breaches_list:
                log(f"   └ {b}")
    except Exception:
        # Fallback: just names
        for b in breaches_list:
            log(f"   └ {b}")

    return breaches_list


def check_hibp_password(email, log):
    """Check if the email's domain-prefix hash appears in HaveIBeenPwned Passwords
    (we hash the local part as a basic check — this is a demo/heuristic)."""
    log("\n🔑 Checking password breach exposure (k-anonymity)...")
    local_part = email.split("@")[0]
    sha1 = hashlib.sha1(local_part.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        res = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5
        )
        if res.status_code == 200:
            for line in res.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    count = parts[1]
                    log(f"⚠️  The username '{local_part}' has been seen as a password {count} times in breaches!")
                    return True
            log("✅ Username not found in password breach lists.")
        else:
            log("⚠️  Could not query password breach database.")
    except Exception:
        log("⚠️  Network error checking password breaches.")
    return False


def check_social_presence(email, log):
    """Basic check — does a Gravatar exist for this email?"""
    log("\n👤 Checking public profile / social footprint...")
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    try:
        res = requests.get(
            f"https://www.gravatar.com/avatar/{email_hash}?d=404", timeout=5
        )
        if res.status_code == 200:
            log("✅ Public Gravatar profile found — email is actively used.")
            return True
        else:
            log("   No Gravatar profile found (email may still be valid).")
    except Exception:
        log("⚠️  Could not check Gravatar.")
    return False


# ==========================================
# FULL ANALYSIS RUNNER
# ==========================================

def run_full_analysis(email, log, on_complete):
    """Run all checks and call on_complete with a results dict."""
    email = email.strip().lower()
    results = {
        "email": email,
        "format_ok": False,
        "mx_ok": False,
        "spf": "unknown",
        "dmarc": "unknown",
        "disposable": False,
        "breaches": [],
        "password_exposed": False,
        "gravatar": False,
        "risk_score": 0,
        "risk_level": "Unknown",
    }

    log(f"🔍 Full OSINT Analysis for: {email}")
    log("=" * 55)

    # Format
    if not check_format(email):
        log("❌ Invalid email format!")
        results["risk_level"] = "Invalid"
        results["risk_score"] = -1
        on_complete(results)
        return

    results["format_ok"] = True
    log("✅ Email format is valid.")
    domain = email.split("@")[1]

    # DNS / MX
    results["mx_ok"] = check_mx(domain, log)

    # SPF
    results["spf"] = check_spf(domain, log)

    # DMARC
    results["dmarc"] = check_dmarc(domain, log)

    # Disposable
    results["disposable"] = check_disposable(email, log)

    # Breaches
    results["breaches"] = check_breaches(email, log)

    # Password breach
    results["password_exposed"] = check_hibp_password(email, log)

    # Gravatar
    results["gravatar"] = check_social_presence(email, log)

    # --- Risk score calculation ---
    score = 0
    if not results["mx_ok"]:
        score += 30
    if results["spf"] in ("missing", "bad"):
        score += 15
    elif results["spf"] == "weak":
        score += 8
    if results["dmarc"] in ("missing",):
        score += 15
    elif results["dmarc"] == "weak":
        score += 8
    if results["disposable"]:
        score += 25
    if results["breaches"]:
        score += min(30, len(results["breaches"]) * 5)
    if results["password_exposed"]:
        score += 10

    results["risk_score"] = min(100, score)

    if score == 0:
        results["risk_level"] = "Clean"
    elif score <= 20:
        results["risk_level"] = "Low Risk"
    elif score <= 50:
        results["risk_level"] = "Medium Risk"
    elif score <= 75:
        results["risk_level"] = "High Risk"
    else:
        results["risk_level"] = "Critical"

    log(f"\n{'=' * 55}")
    log(f"📊 Risk Score: {results['risk_score']}/100 — {results['risk_level']}")
    log(f"{'=' * 55}")
    log("✅ Analysis Complete.\n")

    on_complete(results)


# ==========================================
# UI: EMAIL CHECKER FRAME
# ==========================================

RISK_COLORS = {
    "Clean":       ("#4caf7a", "#1a3d2e"),
    "Low Risk":    ("#b8cc44", "#2e3a1a"),
    "Medium Risk": ("#e6a23c", "#3d3018"),
    "High Risk":   ("#e05555", "#3d1a1a"),
    "Critical":    ("#ff3333", "#4d1111"),
    "Invalid":     ("#888888", "#2a2a2a"),
    "Unknown":     ("#6a6a7a", "#22222a"),
}


def create_email_checker_frame(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")

    gt.section_header(
        frame,
        "OSINT Email Analyzer",
        "Domain validation, breach detection, spoofing risk & social footprint.",
    ).pack(anchor="w", pady=(0, 14))

    # --- Controls card ---
    card = gt.control_card(frame)
    card.pack(fill="x", pady=(0, 10))
    ctrl = ctk.CTkFrame(card, fg_color="transparent")
    ctrl.pack(fill="x", padx=14, pady=12)

    ent_email = gt.create_styled_entry(ctrl, width=300, placeholder_text="target@example.com")
    ent_email.pack(side="left", padx=(0, 10))

    # --- Result summary cards ---
    summary_frame = ctk.CTkFrame(frame, fg_color="transparent")
    summary_frame.pack(fill="x", pady=(0, 8))
    summary_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

    card_defs = [
        {"key": "risk",     "icon": "📊", "label": "Risk Score"},
        {"key": "mx",       "icon": "📧", "label": "Mail Server"},
        {"key": "spoof",    "icon": "🛡️", "label": "Spoof Protection"},
        {"key": "breaches", "icon": "🔓", "label": "Breaches"},
        {"key": "identity", "icon": "👤", "label": "Identity"},
    ]

    summary_widgets = {}
    for col, cd in enumerate(card_defs):
        c = ctk.CTkFrame(
            summary_frame, fg_color=gt.CARD_BG, corner_radius=14,
            border_width=1, border_color=gt.CARD_BORDER, height=75,
        )
        c.grid(row=0, column=col, padx=4, sticky="nsew")
        c.grid_propagate(False)

        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        lbl_title = ctk.CTkLabel(inner, text=f"{cd['icon']} {cd['label']}",
                                 font=("Segoe UI", 10), text_color="#7a7a8a")
        lbl_title.pack()

        lbl_val = ctk.CTkLabel(inner, text="—",
                               font=("Segoe UI", 14, "bold"), text_color="#6a6a7a")
        lbl_val.pack(pady=(2, 0))

        summary_widgets[cd["key"]] = {"card": c, "value": lbl_val}

    def _reset_cards():
        for k, w in summary_widgets.items():
            w["card"].configure(fg_color=gt.CARD_BG, border_color=gt.CARD_BORDER)
            w["value"].configure(text="⏳", text_color="#6a6a7a")

    def _set_card(key, text, fg="#d8d8e0", card_bg=None, border=None):
        w = summary_widgets[key]
        w["value"].configure(text=text, text_color=fg)
        if card_bg:
            w["card"].configure(fg_color=card_bg)
        if border:
            w["card"].configure(border_color=border)

    def _update_cards(r):
        """Update summary cards from results dict."""
        # Risk score
        level = r["risk_level"]
        fg, bg = RISK_COLORS.get(level, ("#6a6a7a", "#22222a"))
        score = r["risk_score"]
        if score < 0:
            _set_card("risk", "Invalid", fg="#888888")
        else:
            _set_card("risk", f"{score}/100", fg=fg, card_bg=bg, border=fg)

        # MX
        if r["mx_ok"]:
            _set_card("mx", "✅ Valid", fg="#4caf7a", card_bg="#1a3d2e", border="#4caf7a")
        else:
            _set_card("mx", "❌ None", fg="#e05555", card_bg="#3d1a1a", border="#e05555")

        # Spoof protection (SPF + DMARC)
        spf = r["spf"]
        dmarc = r["dmarc"]
        if spf == "ok" and dmarc == "ok":
            _set_card("spoof", "✅ Protected", fg="#4caf7a", card_bg="#1a3d2e", border="#4caf7a")
        elif spf in ("missing", "bad") or dmarc == "missing":
            _set_card("spoof", "⚠️ Vulnerable", fg="#e6a23c", card_bg="#3d3018", border="#e6a23c")
        else:
            _set_card("spoof", "⚡ Partial", fg="#b8cc44")

        # Breaches
        bc = len(r["breaches"])
        if bc == 0:
            _set_card("breaches", "✅ Clean", fg="#4caf7a", card_bg="#1a3d2e", border="#4caf7a")
        else:
            _set_card("breaches", f"🚨 {bc} found", fg="#e05555", card_bg="#3d1a1a", border="#e05555")

        # Identity
        if r["disposable"]:
            _set_card("identity", "🗑️ Burner", fg="#e05555", card_bg="#3d1a1a", border="#e05555")
        elif r["gravatar"]:
            _set_card("identity", "👤 Active", fg="#4caf7a", card_bg="#1a3d2e", border="#4caf7a")
        else:
            _set_card("identity", "🔍 Unknown", fg="#6a6a7a")

    # --- Log textbox ---
    txt_log = gt.create_log_textbox(frame)
    txt_log.pack(fill="both", expand=True, pady=(4, 0))

    _scan_state = {"running": False}

    def log_msg(msg):
        def _append():
            txt_log.insert("end", msg + "\n")
            txt_log.see("end")
        txt_log.after(0, _append)

    def on_complete(results):
        _scan_state["running"] = False
        frame.after(0, lambda: _update_cards(results))
        frame.after(0, lambda: btn_scan.configure(state="normal", text="🔍 Analyze"))

    def start_analysis():
        email = ent_email.get().strip()
        if not email or _scan_state["running"]:
            return
        _scan_state["running"] = True
        txt_log.delete("1.0", "end")
        _reset_cards()
        btn_scan.configure(state="disabled", text="⏳ Analyzing...")
        threading.Thread(
            target=run_full_analysis,
            args=(email, log_msg, on_complete),
            daemon=True,
        ).start()

    btn_scan = ctk.CTkButton(
        ctrl, text="🔍 Analyze", width=140, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color=gt.ACCENT_BLUE, hover_color=gt.ACCENT_BLUE_HOVER,
        command=start_analysis,
    )
    btn_scan.pack(side="left", padx=(0, 10))

    ctk.CTkButton(
        ctrl, text="Export Report", width=120, height=38,
        corner_radius=12, font=gt.FONT_BTN,
        fg_color="#333333", hover_color="#444444",
        command=lambda: utils.export_log(txt_log.get("1.0", "end"), "Email_OSINT"),
    ).pack(side="right")

    return frame