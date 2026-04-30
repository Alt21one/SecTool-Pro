import customtkinter as ctk
import platform
import socket
import psutil
import uuid
import re

def get_system_info():
    info = {}
    try:
        info['Hostname'] = socket.gethostname()
        info['IP Address'] = socket.gethostbyname(info['Hostname'])
        info['OS'] = f"{platform.system()} {platform.release()}"
        # Get MAC Address
        info['MAC Address'] = ':'.join(re.findall('..', '%012x' % uuid.getnode())).upper()
        info['Processor'] = platform.processor()
        info['RAM'] = f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB"
    except:
        info = {"Error": "Could not retrieve all stats."}
    return info

def create_home_frame(parent):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    
    # ASCII Art Logo (Professional Style)
    ascii_logo = """
    ███████╗███████╗ ██████╗████████╗ ██████╗  ██████╗ ██╗     
    ██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     
    ███████╗█████╗  ██║        ██║   ██║   ██║██║   ██║██║     
    ╚════██║██╔══╝  ██║        ██║   ██║   ██║██║   ██║██║     
    ███████║███████╗╚██████╗   ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚══════╝╚══════╝ ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                                    PRO EDITION [v2.0]
    """
    
    ctk.CTkLabel(frame, text=ascii_logo, font=("Courier", 10, "bold"), text_color="#1976D2", justify="left").pack(pady=20)
    
    # Stats Box
    stats_frame = ctk.CTkFrame(frame, corner_radius=15, border_width=1, border_color="#333333")
    stats_frame.pack(fill="x", padx=50, pady=10)
    
    ctk.CTkLabel(stats_frame, text="SYTEM OPERATIONAL STATUS", font=("Segoe UI", 16, "bold"), text_color="gray").pack(pady=10)
    
    sys_info = get_system_info()
    for key, value in sys_info.items():
        row = ctk.CTkFrame(stats_frame, fg_color="transparent")
        row.pack(fill="x", padx=40, pady=5)
        ctk.CTkLabel(row, text=f"{key}:", font=("Segoe UI", 13, "bold"), text_color="#1976D2", width=120, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=value, font=("Segoe UI", 13)).pack(side="left")

    ctk.CTkLabel(frame, text="Select a module from the sidebar to begin security operations.", text_color="gray").pack(pady=30)
    
    return frame