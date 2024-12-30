import os
import socket
import threading
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet

class FileTransferClient:
    def __init__(self, port=5000):
        # Network configuration
        self.port = port
        self.buffer_size = 4096
        self.server_ip = None
        
        # Generate secure encryption key (must match server)
        self.key = base64.urlsafe_b64encode(b'SecureFileTransfer2024_LongKey32Bytes!'[:32])
        self.cipher = Fernet(self.key)
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("File Transfer Client")
        self.root.geometry("600x500")
        
        # Setup GUI and discover server
        self.setup_gui()
        self.discover_server()

    def setup_gui(self):
        # Server Host Label and Entry
        tk.Label(self.root, text="Server Host:").pack(pady=(10, 0))
        self.host_entry = tk.Entry(self.root, width=30)
        self.host_entry.pack()
        self.host_entry.insert(0, "Discovering...")

        # File Send Button
        tk.Button(self.root, text="Select File to Send", command=self.select_file).pack(pady=10)

        # Status Area
        tk.Label(self.root, text="Transfer Status:").pack()
        self.status_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=70, height=20)
        self.status_area.pack(padx=10, pady=10)

    def get_local_ip(self):
        try:
            # Create a socket to connect to an external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return '127.0.0.1'

    def discover_server(self):
        def scan_network():
            local_ip = self.get_local_ip()
            subnet = '.'.join(local_ip.split('.')[:-1]) + '.'
            
            for i in range(1, 255):
                test_ip = f"{subnet}{i}"
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.1)
                        result = sock.connect_ex((test_ip, self.port))
                        if result == 0:
                            self.server_ip = test_ip
                            self.root.after(0, self.update_server_ip)
                            return
                except Exception:
                    pass
            
            self.update_status("No server found. Enter IP manually.")

        threading.Thread(target=scan_network, daemon=True).start()

    def update_server_ip(self):
        if self.server_ip:
            self.host_entry.delete(0, tk.END)
            self.host_entry.insert(0, self.server_ip)
            self.update_status(f"Server discovered at {self.server_ip}")

    def update_status(self, message):
        self.status_area.insert(tk.END, message + "\n")
        self.status_area.see(tk.END)

    def encrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                data = file.read()
            return self.cipher.encrypt(data)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return None

    def send_file(self, file_path):
        try:
            # Validate file
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")

            # Encrypt file
            encrypted_data = self.encrypt_file(file_path)
            if not encrypted_data:
                return False

            # Create socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                # Get server host from entry
                server_host = self.host_entry.get().strip()
                if not server_host or server_host == "Discovering...":
                    messagebox.showerror("Error", "Please specify a server host")
                    return False

                # Connect to server
                client_socket.connect((server_host, self.port))

                # Prepare filename
                filename = os.path.basename(file_path)
                filename_bytes = filename.encode()

                # Send filename length
                client_socket.send(len(filename_bytes).to_bytes(4, byteorder='big'))
                
                # Send filename
                client_socket.send(filename_bytes)

                # Send file size
                client_socket.send(len(encrypted_data).to_bytes(8, byteorder='big'))

                # Send encrypted file data
                client_socket.sendall(encrypted_data)

                # Receive server response
                response = client_socket.recv(7)
                if response == b"SUCCESS":
                    self.update_status(f"File {filename} sent successfully")
                    messagebox.showinfo("Success", f"File {filename} sent successfully")
                    return True
                else:
                    self.update_status("File transfer failed")
                    messagebox.showerror("Error", "File transfer failed")
                    return False

        except Exception as e:
            self.update_status(f"Send file error: {e}")
            messagebox.showerror("Error", str(e))
            return False

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.send_file(file_path)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    client = FileTransferClient()
    client.run()