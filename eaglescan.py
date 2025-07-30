mport os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

class eaglescan:


    def __init__(self, master):
        """
        Initializes the MalwareScanner GUI.
        """
        self.master = master
        master.title("Malware Scanner")
        master.geometry("600x400")

        # --- Malware Hashes Database ---
        # In a real-world scenario, this would be a much larger, external database.
        self.malware_hashes = {
            "eicar.com.txt": "44d88612fea8a8f36de82e1278abb02f", # EICAR test file
            "trojan_test.txt": "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", # Example Trojan
            "worm_test.exe": "b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4"  # Example Worm
        }

        # --- GUI Elements ---
        self.label = tk.Label(master, text="Select a directory to scan for malware:")
        self.label.pack(pady=10)

        self.select_button = tk.Button(master, text="Select Directory", command=self.select_directory)
        self.select_button.pack()

        self.scan_button = tk.Button(master, text="Scan Now", command=self.scan_directory, state=tk.DISABLED)
        self.scan_button.pack(pady=5)

        self.results_area = scrolledtext.ScrolledText(master, width=70, height=15)
        self.results_area.pack(pady=10)

        self.directory_to_scan = ""

    def select_directory(self):
        
        self.directory_to_scan = filedialog.askdirectory()
        if self.directory_to_scan:
            self.label.config(text=f"Selected: {self.directory_to_scan}")
            self.scan_button.config(state=tk.NORMAL)
            self.results_area.delete(1.0, tk.END)

    def get_file_hash(self, file_path):
        
        hasher = hashlib.md5()
        try:
            with open(file_path, 'rb') as f:
                buf = f.read()
                hasher.update(buf)
            return hasher.hexdigest()
        except Exception as e:
            return f"Error: {e}"

    def scan_directory(self):
        """
        Scans the selected directory for malicious files.
        """
        if not self.directory_to_scan:
            messagebox.showerror("Error", "Please select a directory first.")
            return

        self.results_area.insert(tk.INSERT, f"Scanning {self.directory_to_scan}...\n\n")
        found_malware = False

        for dirpath, _, filenames in os.walk(self.directory_to_scan):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                file_hash = self.get_file_hash(file_path)

                if file_hash in self.malware_hashes.values():
                    self.results_area.insert(tk.INSERT, f"[!] Malware DETECTED: {file_path}\n", 'malware')
                    found_malware = True
                else:
                    self.results_area.insert(tk.INSERT, f"[*] Clean: {file_path}\n")

        self.results_area.tag_config('malware', foreground='red')

        if not found_malware:
            self.results_area.insert(tk.INSERT, "\nScan complete. No malware found.\n")
        else:
            self.results_area.insert(tk.INSERT, "\nScan complete. Malware detected.\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareScanner(root)
    root.mainloop()
