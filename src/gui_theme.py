"""
Shared CustomTkinter styling for SecTool Pro — one place for colors, fonts, and widgets.
"""
import customtkinter as ctk

# --- Typography ---
FONT_TITLE = ("Segoe UI", 26, "bold")
FONT_HEAD = ("Segoe UI", 15)
FONT_BODY = ("Segoe UI", 13)
FONT_SMALL = ("Segoe UI", 11)
FONT_NAV = ("Segoe UI", 10, "bold")
FONT_BTN = ("Segoe UI", 13, "bold")
FONT_LOG = ("Consolas", 12)
FONT_STATUS = ("Segoe UI", 14, "bold")

# --- Shell ---
TEXT_PRIMARY = "#ececf0"
MUTED = "#9898a8"
APP_BG = "#0f0f12"
SIDEBAR_BG = "#0a0a0c"
SIDEBAR_WIDTH = 88
CONTENT_BG = "#1c1c21"
CONTENT_BORDER = "#2e2e36"
CONTENT_RADIUS = 20
CORNER_RADIUS = 12
ACTIVE_NAV = "#243a5c"
HOVER_NAV = "#2a2d38"
SEP_COLOR = "#34343f"

# --- Surfaces ---
CARD_BG = "#22222a"
CARD_BORDER = "#34343f"
INPUT_BG = "#1a1a22"
TEXTBOX_BG = "#14141a"
TEXTBOX_BORDER = "#303040"

# --- Accents (buttons / highlights) ---
ACCENT_BLUE = "#3d7dd4"
ACCENT_BLUE_HOVER = "#2f6bc0"
ACCENT_ORANGE = "#e07c2e"
ACCENT_ORANGE_HOVER = "#c96a22"
ACCENT_RED = "#d94a4a"
ACCENT_RED_HOVER = "#c03d3d"
ACCENT_GREEN = "#3d9e6c"
ACCENT_GREEN_HOVER = "#328a5c"
ACCENT_INFO = "#5c9fd4"
ACCENT_OK = "#4caf7a"
ACCENT_WARN = "#e6a23c"
ACCENT_BAD = "#e05555"


def section_header(parent, title: str, subtitle: str | None = None):
    """Title + optional muted subtitle; pack() or grid() the returned frame."""
    f = ctk.CTkFrame(parent, fg_color="transparent")
    ctk.CTkLabel(f, text=title, font=FONT_TITLE, text_color=TEXT_PRIMARY).pack(anchor="w")
    if subtitle:
        ctk.CTkLabel(f, text=subtitle, font=FONT_BODY, text_color=MUTED).pack(anchor="w", pady=(6, 0))
    return f


def control_card(parent, **pack_kw):
    """Rounded surface for control rows (toolbar)."""
    card = ctk.CTkFrame(
        parent,
        fg_color=CARD_BG,
        corner_radius=14,
        border_width=1,
        border_color=CARD_BORDER,
    )
    if pack_kw:
        card.pack(**pack_kw)
    return card


def create_log_textbox(parent, **kwargs):
    d = {
        "font": FONT_LOG,
        "fg_color": TEXTBOX_BG,
        "text_color": "#d8d8e0",
        "corner_radius": 14,
        "border_width": 1,
        "border_color": TEXTBOX_BORDER,
    }
    d.update(kwargs)
    return ctk.CTkTextbox(parent, **d)


def create_styled_entry(parent, **kwargs):
    d = {
        "height": 40,
        "corner_radius": 12,
        "border_width": 1,
        "border_color": TEXTBOX_BORDER,
        "fg_color": INPUT_BG,
        "text_color": TEXT_PRIMARY,
        "font": FONT_BODY,
    }
    d.update(kwargs)
    return ctk.CTkEntry(parent, **d)


def create_styled_combo(parent, **kwargs):
    d = {
        "corner_radius": 12,
        "border_width": 1,
        "border_color": TEXTBOX_BORDER,
        "fg_color": INPUT_BG,
        "button_color": ACCENT_BLUE,
        "button_hover_color": ACCENT_BLUE_HOVER,
        "dropdown_fg_color": CARD_BG,
        "font": FONT_BODY,
        "text_color": TEXT_PRIMARY,
    }
    d.update(kwargs)
    return ctk.CTkComboBox(parent, **d)
