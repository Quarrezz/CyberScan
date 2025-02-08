import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import threading
import subprocess

class CyberSecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Security Scanner")
        self.root.geometry("900x650")
        self.root.configure(bg="#2E2E2E")
        
        self.frame = tk.Frame(self.root, bg="#2E2E2E")
        self.frame.pack(pady=10)
        
        self.label = tk.Label(self.frame, text="Enter target domain:", fg="white", bg="#2E2E2E")
        self.label.pack(side=tk.LEFT, padx=5)
        
        self.entry = tk.Entry(self.frame, width=40, bg="#3E3E3E", fg="white", insertbackground="white")
        self.entry.pack(side=tk.LEFT, padx=5)
        
        self.start_button = tk.Button(self.frame, text="Start Scan", command=self.start_scan, bg="#1E90FF", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(self.frame, text="Stop", command=self.stop_scan, state=tk.DISABLED, bg="#FF4500", fg="white")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.options_frame = tk.Frame(self.root, bg="#2E2E2E")
        self.options_frame.pack(pady=5)
        
        self.port_scan_var = tk.BooleanVar(value=True)
        self.port_scan_check = tk.Checkbutton(self.options_frame, text="Port Scanning", variable=self.port_scan_var, bg="#2E2E2E", fg="white", selectcolor="#2E2E2E")
        self.port_scan_check.pack(side=tk.LEFT, padx=5)
        
        self.exploit_scan_var = tk.BooleanVar(value=True)
        self.exploit_scan_check = tk.Checkbutton(self.options_frame, text="Exploit Scanning", variable=self.exploit_scan_var, bg="#2E2E2E", fg="white", selectcolor="#2E2E2E")
        self.exploit_scan_check.pack(side=tk.LEFT, padx=5)
        
        self.anon_var = tk.BooleanVar()
        self.anon_check = tk.Checkbutton(self.options_frame, text="Use Tor Network", variable=self.anon_var, bg="#2E2E2E", fg="white", selectcolor="#2E2E2E")
        self.anon_check.pack(side=tk.LEFT, padx=5)
        
        self.save_output_var = tk.BooleanVar()
        self.save_output_check = tk.Checkbutton(self.options_frame, text="Save Output", variable=self.save_output_var, bg="#2E2E2E", fg="white", selectcolor="#2E2E2E")
        self.save_output_check.pack(side=tk.LEFT, padx=5)
        
        self.output_text = scrolledtext.ScrolledText(self.root, width=100, height=25, bg="#1E1E1E", fg="white", insertbackground="white")
        self.output_text.pack(pady=10)
        
        self.save_button = tk.Button(self.root, text="Save Output", command=self.save_output, bg="#32CD32", fg="white")
        self.save_button.pack(pady=5)
        
        self.process = None
    
    def start_scan(self):
        target = self.entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target domain.")
            return
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "[🔄] Scanning started...\n")
        
        self.process = threading.Thread(target=self.run_scan, args=(target,))
        self.process.start()
    
    def run_scan(self, target):
        try:
            cmd = ["python3", "core/port_scanner.py", target]
            if self.anon_var.get():
                cmd.append("--tor")
            if not self.port_scan_var.get():
                cmd.append("--no-port-scan")
            if not self.exploit_scan_var.get():
                cmd.append("--no-exploit-scan")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in iter(process.stdout.readline, ''):
                self.output_text.insert(tk.END, line)
                self.output_text.yview(tk.END)
            process.wait()
        except Exception as e:
            self.output_text.insert(tk.END, f"[❌] Error: {e}\n")
        finally:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def stop_scan(self):
        if self.process:
            messagebox.showinfo("Info", "Stopping scan...")
            self.process.terminate()
            self.process = None
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def save_output(self):
        if not self.save_output_var.get():
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.output_text.get(1.0, tk.END))
            messagebox.showinfo("Success", "Output saved successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSecurityScannerGUI(root)
    root.mainloop()
