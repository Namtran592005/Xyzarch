import os
import sys
import re
import random
import zipfile
import hashlib
import zlib
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import pytz
import time
import winsound
import json
import threading
from pathlib import Path

class EncryptionMethods:
    """Encryption methods configuration"""
    METHODS = {
        "AES-256 (Standard)": {
            "key_size": 32,
            "block_mode": AES.MODE_CBC,
            "cipher_class": AES
        },
        "3DES (US Military)": {
            "key_size": 24,
            "block_mode": DES3.MODE_CBC,
            "cipher_class": DES3
        },
        "Blowfish (Alternative)": {
            "key_size": 56,
            "block_mode": Blowfish.MODE_CBC,
            "cipher_class": Blowfish
        },
        "Chaos (Custom)": {  # Add Chaos method
            "key_size": 32,  # Key size just for compatibility, not used in Chaos
            "block_mode": None,
            "cipher_class": None
        }
    }


def chaos_encrypt(data, key):
    """Improved chaotic encryption for binary data"""
    random.seed(hashlib.sha256(key.encode()).digest())  # Use a strong, deterministic seed
    encrypted_data = bytearray()
    for byte in data:
        random_byte = random.randint(0, 255)
        encrypted_data.append(byte ^ random_byte)  # XOR operation for encryption
    return bytes(encrypted_data)


def chaos_decrypt(data, key):
    """Improved chaotic decryption for binary data"""
    random.seed(hashlib.sha256(key.encode()).digest())  # Use the same seed as encryption
    decrypted_data = bytearray()
    for byte in data:
        random_byte = random.randint(0, 255)
        decrypted_data.append(byte ^ random_byte)  # Reverse XOR operation
    return bytes(decrypted_data)


class Encryption:
    def __init__(self, method, password):
        self.method = method
        self.password = password
        self.key = hashlib.sha256(password.encode()).digest()  # Create a secure key from the password

        # Get encryption method details
        self.method_info = EncryptionMethods.METHODS.get(method)
        if not self.method_info:
            raise ValueError(f"Unsupported encryption method: {method}")

        # Initialize cipher for supported methods
        if self.method_info["cipher_class"] == AES:
            self.cipher = AES.new(self.key, self.method_info["block_mode"], iv=os.urandom(16))
        elif self.method_info["cipher_class"] == DES3:
            self.cipher = DES3.new(self.key, self.method_info["block_mode"], iv=os.urandom(8))
        elif self.method_info["cipher_class"] == Blowfish:
            self.cipher = Blowfish.new(self.key, self.method_info["block_mode"], iv=os.urandom(8))
        elif self.method_info["cipher_class"] is None:  # Chaos method
            self.cipher = None  # Special case for Chaos

    def encrypt(self, data):
        if self.method == "Chaos (Custom)":
            return chaos_encrypt(data, self.password)  # Chaos encrypt works directly on binary data
        else:
            padded_data = pad(data, 16)
            encrypted_data = self.cipher.encrypt(padded_data)
            return encrypted_data

    def decrypt(self, data):
        if self.method == "Chaos (Custom)":
            return chaos_decrypt(data, self.password)  # Chaos decrypt works directly on binary data
        else:
            decrypted_data = unpad(self.cipher.decrypt(data), 16)
            return decrypted_data


# Example file-based encryption and decryption
def encrypt_file(input_path, output_path, method, password):
    with open(input_path, "rb") as f:
        data = f.read()
    
    encryption = Encryption(method, password)
    encrypted_data = encryption.encrypt(data)
    
    with open(output_path, "wb") as f:
        f.write(encrypted_data)


def decrypt_file(input_path, output_path, method, password):
    with open(input_path, "rb") as f:
        data = f.read()
    
    encryption = Encryption(method, password)
    decrypted_data = encryption.decrypt(data)
    
    with open(output_path, "wb") as f:
        f.write(decrypted_data)

class PasswordDialog:
    """Custom password dialog with strength meter"""
    def __init__(self, parent):
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Password Entry")
        self.dialog.geometry("400x530")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.result = None
        self.password = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.setup_ui()
        
    def setup_ui(self):
        frame = ctk.CTkFrame(self.dialog)
        frame.pack(padx=20, pady=20, fill='both', expand=True)
        
        # Title
        title_frame = ctk.CTkFrame(frame, fg_color="transparent")
        title_frame.pack(fill='x', pady=(0, 20))
        
        title_label = ctk.CTkLabel(
            title_frame, 
            text="Enter Password", 
            font=("Helvetica", 18, "bold")
        )
        title_label.pack()
        
        # Password entry
        self.entry_frame = ctk.CTkFrame(frame, fg_color="transparent")
        self.entry_frame.pack(fill='x', pady=(0, 10))
        
        self.password_entry = ctk.CTkEntry(
            self.entry_frame,
            textvariable=self.password,
            show='*',
            placeholder_text="Enter your password"
        )
        self.password_entry.pack(fill='x', side='left', expand=True)
        
        self.toggle_btn = ctk.CTkButton(
            self.entry_frame,
            text="Show",
            width=60,
            command=self.toggle_password_visibility
        )
        self.toggle_btn.pack(side='right', padx=(10, 0))
        
        # Strength meter
        self.setup_strength_meter(frame)
        
        # Generate password button
        generate_btn = ctk.CTkButton(
            frame,
            text="Generate Strong Password",
            command=self.generate_password
        )
        generate_btn.pack(fill='x', pady=10)
        
        # Password tips
        self.setup_password_tips(frame)
        
        # Action buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill='x', pady=(20, 0))
        
        ctk.CTkButton(
            btn_frame,
            text="OK",
            command=self.on_ok
        ).pack(side='left', expand=True, padx=(0, 5))
        
        ctk.CTkButton(
            btn_frame,
            text="Cancel",
            command=self.on_cancel,
            fg_color="gray"
        ).pack(side='right', expand=True, padx=(5, 0))
        
        self.password.trace_add('write', self.update_strength)
        
    def setup_strength_meter(self, parent):
        strength_frame = ctk.CTkFrame(parent)
        strength_frame.pack(fill='x', pady=10)
        
        self.strength_label = ctk.CTkLabel(strength_frame, text="Password Strength:")
        self.strength_label.pack(anchor='w')
        
        self.bars_frame = ctk.CTkFrame(strength_frame, fg_color="transparent")
        self.bars_frame.pack(fill='x', pady=(5, 0))
        
        self.strength_bars = []
        for _ in range(4):
            bar = ctk.CTkProgressBar(self.bars_frame)
            bar.pack(side='left', padx=2, expand=True)
            bar.set(1)
            self.strength_bars.append(bar)
            
        self.strength_text = ctk.CTkLabel(strength_frame, text="")
        self.strength_text.pack()
        
    def setup_password_tips(self, parent):
        tips_frame = ctk.CTkFrame(parent)
        tips_frame.pack(fill='x', pady=10)
        
        tips_label = ctk.CTkLabel(
            tips_frame,
            text="Password Tips:",
            font=("Helvetica", 14, "bold")
        )
        tips_label.pack(anchor='w', pady=(0, 5))
        
        tips = [
            "• Use at least 8 characters",
            "• Mix uppercase & lowercase letters",
            "• Include numbers (0-9)",
            "• Add special characters (!@#$%^&*)",
            "• Avoid common words or phrases",
            "• Don't use personal information"
        ]
        
        for tip in tips:
            tip_label = ctk.CTkLabel(tips_frame, text=tip)
            tip_label.pack(anchor='w')
            
    def toggle_password_visibility(self):
        current = self.password_entry.cget("show")
        self.password_entry.configure(show="" if current == "*" else "*")
        self.toggle_btn.configure(text="Hide" if current == "*" else "Show")
        
    def generate_password(self):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
        password = ''.join(random.choice(chars) for _ in range(16))
        self.password.set(password)
        
    def calculate_strength(self, password):
        score = 0
        if len(password) >= 8: score += 1
        if re.search(r'[A-Z]', password): score += 1
        if re.search(r'[0-9]', password): score += 1
        if re.search(r'[^A-Za-z0-9]', password): score += 1
        return score
        
    def update_strength(self, *args):
        password = self.password.get()
        strength = self.calculate_strength(password)
        
        colors = ['#ff4444', '#ffa700', '#ffff00', '#00ff00']
        labels = ['Weak', 'Fair', 'Good', 'Strong']
        
        self.strength_text.configure(
            text=labels[strength-1] if strength > 0 else ''
        )
        
        for i in range(4):
            self.strength_bars[i].configure(
                progress_color=colors[strength-1] if i < strength else 'gray'
            )
            
    def on_ok(self):
        if self.password.get():
            self.result = self.password.get()
            self.dialog.destroy()
            
    def on_cancel(self):
        self.dialog.destroy()
        
    def show(self):
        self.dialog.wait_window()
        return self.result

class XyzArch:
    """Main application class"""
    VERSION = "1.0.0"
    DEVELOPER = "Namtran5905"
    
    def __init__(self):
        self.setup_appearance()
        self.setup_window()
        self.initialize_variables()
        self.setup_ui()
        self.setup_clock()
        
    def setup_appearance(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
    def setup_window(self):
        self.root = ctk.CTk()
        self.root.title(f"XyzArch Compressor {self.VERSION}")
        self.root.geometry("500x500")
        self.root.minsize(450, 450)
        
    def initialize_variables(self):
        self.files = []
        self.hash_types = {
            'SHA1': tk.BooleanVar(value=False),
            'MD5': tk.BooleanVar(value=False),
            'CRC32': tk.BooleanVar(value=False)
        }
        
    def setup_ui(self):
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.setup_file_section()
        self.setup_file_list()
        self.setup_encryption_section()
        self.setup_hash_section()
        self.setup_options_section()
        self.setup_action_section()
        
    def setup_file_section(self):
        file_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        file_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkButton(
            file_frame,
            text="Add Files",
            command=self.add_files,
            fg_color="#4CAF50",
            hover_color="#45a049"
        ).pack(side="left", expand=True, padx=(0, 5))
        
        ctk.CTkButton(
            file_frame,
            text="Clear Files",
            command=self.clear_files,
            fg_color="#F44336",
            hover_color="#D32F2F"
        ).pack(side="right", expand=True, padx=(5, 0))
        
    def setup_file_list(self):
        self.file_listbox = ctk.CTkTextbox(self.main_frame, height=250)
        self.file_listbox.pack(fill="x", pady=(0, 10))
        
    def setup_encryption_section(self):
        encrypt_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        encrypt_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(
            encrypt_frame,
            text="Encryption Method:"
        ).pack(side="left", padx=(0, 10))
        
        self.encrypt_method_var = ctk.StringVar(value="AES-256 (Standard)")
        ctk.CTkOptionMenu(
            encrypt_frame,
            values=list(EncryptionMethods.METHODS.keys()),
            variable=self.encrypt_method_var
        ).pack(side="left", expand=True)
        
    def setup_hash_section(self):
        hash_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        hash_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(
            hash_frame,
            text="Generate Hash:"
        ).pack(side="left", padx=(0, 10))
        
        for hash_type, var in self.hash_types.items():
            ctk.CTkCheckBox(
                hash_frame,
                text=hash_type,
                variable=var
            ).pack(side="left", padx=5)
            
    def setup_options_section(self):
        options_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        options_frame.pack(fill="x", pady=(0, 10))
        
        self.encrypt_var = ctk.BooleanVar(value=False)
        self.delete_source_var = ctk.BooleanVar(value=False)
        
        ctk.CTkCheckBox(
            options_frame,
            text="Encrypt Archive",
            variable=self.encrypt_var
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkCheckBox(
            options_frame,
            text="Delete Source Files",
            variable=self.delete_source_var
        ).pack(side="left")
        
    def setup_action_section(self):
        action_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        action_frame.pack(fill="x")
        
        ctk.CTkButton(
            action_frame,
            text="Compress",
            command=self.compress_files,
            fg_color="#2196F3",
            hover_color="#1E88E5"
        ).pack(side="left", expand=True, padx=(0, 5))
        
        ctk.CTkButton(
            action_frame,
            text="Extract",
            command=self.extract_archive,
            fg_color="#FF9800",
            hover_color="#F57C00"
        ).pack(side="right", expand=True, padx=(5, 0))
        
    def setup_clock(self):
        self.clock_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.clock_frame.pack(side="bottom", fill="x", padx=10, pady=5)
        
        self.time_label = ctk.CTkLabel(
            self.clock_frame,
            text="",
            font=("", 12)
        )
        self.time_label.pack(side="right")
        
        self.update_clock()
        
    def update_clock(self):
        tz = pytz.timezone('Asia/Ho_Chi_Minh')
        current_time = datetime.now(tz)
        time_str = current_time.strftime("%d/%m/%Y %H:%M:%S (UTC+7)")
        self.time_label.configure(text=time_str)
        self.root.after(1000, self.update_clock)
        
    def add_files(self):
        files = filedialog.askopenfilenames()
        for file in files:
            if file not in self.files:
                self.files.append(file)
        self.update_file_listbox()
        
    def clear_files(self):
        self.files.clear()
        self.update_file_listbox()
        
    def update_file_listbox(self):
        self.file_listbox.delete("1.0", tk.END)
        for file in self.files:
            self.file_listbox.insert(tk.END, f"{os.path.basename(file)}\n")
            
    def get_password(self):
        dialog = PasswordDialog(self.root)
        return dialog.show()
        
    def encrypt_archive(self, archive_path, password):
        method = EncryptionMethods.METHODS[self.encrypt_method_var.get()]
        
        if self.encrypt_method_var.get() == "Chaos (Custom)":  # Handle Chaos method
            with open(archive_path, 'rb') as f:
                data = f.read()
            encrypted_data = chaos_encrypt(data, password)
            with open(archive_path, 'wb') as f:
                f.write(encrypted_data)
        else:
            # Handle other encryption methods (existing code)
            method = EncryptionMethods.METHODS[self.encrypt_method_var.get()]
            key = hashlib.sha256(password.encode()).digest()[:method['key_size']]
            iv = os.urandom(16)
            
            with open(archive_path, 'rb') as f:
                data = f.read()
            
            cipher = method['cipher_class'].new(key, method['block_mode'], iv)
            encrypted_data = iv + cipher.encrypt(pad(data, cipher.block_size))
            
            with open(archive_path, 'wb') as f:
                f.write(encrypted_data)

    def decrypt_archive(self, archive_path, password):
        method = EncryptionMethods.METHODS[self.encrypt_method_var.get()]
        
        if self.encrypt_method_var.get() == "Chaos (Custom)":  # Handle Chaos decryption
            with open(archive_path, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = chaos_decrypt(encrypted_data, password)
            with open(archive_path, 'wb') as f:
                f.write(decrypted_data)
        else:
            # Handle other decryption methods (existing code)
            key = hashlib.sha256(password.encode()).digest()[:method['key_size']]
            
            with open(archive_path, 'rb') as f:
                encrypted_data = f.read()
                iv = encrypted_data[:16]
                data = encrypted_data[16:]
            
            cipher = method['cipher_class'].new(key, method['block_mode'], iv)
            decrypted_data = unpad(cipher.decrypt(data), cipher.block_size)
            
            with open(archive_path, 'wb') as f:
                f.write(decrypted_data)
            
    def generate_hashes(self, file_path):
        hashes = {}
        with open(file_path, 'rb') as f:
            data = f.read()
            if self.hash_types['SHA1'].get():
                hashes['SHA1'] = hashlib.sha1(data).hexdigest()
            if self.hash_types['MD5'].get():
                hashes['MD5'] = hashlib.md5(data).hexdigest()
            if self.hash_types['CRC32'].get():
                hashes['CRC32'] = hex(zlib.crc32(data) & 0xFFFFFFFF)[2:].zfill(8)
        return hashes
        
    def compress_files(self):
        if not self.files:
            messagebox.showwarning("Warning", "Please select files to compress")
            return
            
        output_dir = filedialog.askdirectory(title="Select Destination Folder")
        if not output_dir:
            return
            
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"XyzArch_{timestamp}.xyzarch"
            archive_path = os.path.join(output_dir, archive_name)
            
            # Show progress dialog
            progress = self.show_progress_dialog("Compressing Files")
            
            def compression_task():
                try:
                    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        total_files = len(self.files)
                        for i, file_path in enumerate(self.files, 1):
                            progress.update_progress(
                                i / total_files,
                                f"Compressing: {os.path.basename(file_path)}"
                            )
                            zipf.write(file_path, os.path.basename(file_path))
                            
                    # Optional encryption
                    if self.encrypt_var.get():
                        progress.update_status("Encrypting archive...")
                        password = self.get_password()
                        if password:
                            self.encrypt_archive(archive_path, password)
                            
                    # Hash generation
                    if any(var.get() for var in self.hash_types.values()):
                        progress.update_status("Generating hashes...")
                        hashes = self.generate_hashes(archive_path)
                        if hashes:
                            hash_file_path = os.path.join(output_dir, f"{archive_name}.txt")
                            with open(hash_file_path, 'w') as hash_file:
                                for hash_type, hash_value in hashes.items():
                                    hash_file.write(f"{hash_type}: {hash_value}\n")
                                    
                    # Optional file deletion
                    if self.delete_source_var.get():
                        progress.update_status("Cleaning up source files...")
                        for file_path in self.files:
                            os.remove(file_path)
                            
                    progress.complete()
                    winsound.Beep(1000, 200)  # Success sound
                    messagebox.showinfo(
                        "Success",
                        f"Compressed {len(self.files)} files to {archive_name}"
                    )
                    self.clear_files()
                    
                except Exception as e:
                    progress.error(str(e))
                    winsound.Beep(500, 500)  # Error sound
                    messagebox.showerror("Error", str(e))
                    
            threading.Thread(target=compression_task).start()
            
        except Exception as e:
            winsound.Beep(500, 500)  # Error sound
            messagebox.showerror("Error", str(e))
            
    def extract_archive(self):
        archive_path = filedialog.askopenfilename(
            title="Select Archive to Extract",
            filetypes=[("XyzArch Archives", "*.xyzarch")]
        )
        if not archive_path:
            return
            
        try:
            # Show progress dialog
            progress = self.show_progress_dialog("Extracting Archive")
            
            def extraction_task():
                try:
                    # Optional decryption
                    if messagebox.askyesno("Encryption", "Is this archive encrypted?"):
                        progress.update_status("Decrypting archive...")
                        password = self.get_password()
                        if password:
                            self.decrypt_archive(archive_path, password)
                            
                    output_dir = filedialog.askdirectory(title="Select Extraction Folder")
                    if not output_dir:
                        progress.complete()
                        return
                        
                    with zipfile.ZipFile(archive_path, 'r') as zipf:
                        total_files = len(zipf.namelist())
                        for i, file_name in enumerate(zipf.namelist(), 1):
                            progress.update_progress(
                                i / total_files,
                                f"Extracting: {file_name}"
                            )
                            zipf.extract(file_name, output_dir)
                            
                    progress.complete()
                    winsound.Beep(1200, 200)  # Success sound
                    messagebox.showinfo(
                        "Success",
                        f"Extracted archive to {output_dir}"
                    )
                    
                except Exception as e:
                    progress.error(str(e))
                    winsound.Beep(500, 500)  # Error sound
                    messagebox.showerror("Error", str(e))
                    
            threading.Thread(target=extraction_task).start()
            
        except Exception as e:
            winsound.Beep(500, 500)  # Error sound
            messagebox.showerror("Error", str(e))
            
    def show_progress_dialog(self, title):
        progress_dialog = ctk.CTkToplevel(self.root)
        progress_dialog.title(title)
        progress_dialog.geometry("400x150")
        progress_dialog.transient(self.root)
        progress_dialog.grab_set()
        
        progress_var = tk.DoubleVar()
        status_var = tk.StringVar(value="Starting...")
        
        progress_bar = ctk.CTkProgressBar(progress_dialog)
        progress_bar.pack(padx=20, pady=(20, 10), fill='x')
        progress_bar.set(0)
        
        status_label = ctk.CTkLabel(
            progress_dialog,
            textvariable=status_var
        )
        status_label.pack(padx=20, pady=(0, 20))
        
        class ProgressHandler:
            def update_progress(self, value, status=None):
                progress_bar.set(value)
                if status:
                    status_var.set(status)
                    
            def update_status(self, status):
                status_var.set(status)
                
            def complete(self):
                progress_dialog.destroy()
                
            def error(self, message):
                progress_dialog.destroy()
                
        return ProgressHandler()
        
    def run(self):
        self.root.mainloop()

def main():
    try:
        app = XyzArch()
        app.run()
    except Exception as e:
        messagebox.showerror(
            "Fatal Error",
            f"An unexpected error occurred:\n{str(e)}\n\nPlease contact support."
        )

if __name__ == "__main__":
    main()
