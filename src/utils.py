import customtkinter as ctk
from tkinter import filedialog

def export_log(text_content, module_name):
    """Opens a Save Dialog and writes the log content to a .txt file"""
    if not text_content.strip():
        return 

   
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        initialfile=f"SecTool_Report_{module_name}.txt",
        title=f"Export {module_name} Report",
        filetypes=[("Text Files", "*.txt"), ("Log Files", "*.log"), ("All Files", "*.*")]
    )
    
    
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                
                f.write(f"=========================================\n")
                f.write(f"  SecTool Pro - {module_name} Report\n")
                f.write(f"=========================================\n\n")
                f.write(text_content)
            print(f"Report saved to {file_path}")
        except Exception as e:
            print(f"Error saving report: {e}")
