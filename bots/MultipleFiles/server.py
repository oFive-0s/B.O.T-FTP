import os
import socket
import threading
import base64
import tkinter as tk
from tkinter import scrolledtext
from cryptography.fernet import Fernet

class FileTransferServer:
    def __init__(self, port=5000, save_path='received_files'):
        # Network configuration
        self.port = port
        self.host = '0.0.0.0'  # Listen on all available interfaces
        self.buffer_size = 4096
        
        # File save path
        self.save_path = save_path
        os.makedirs(save_path, exist_ok=True)
        
        # Generate secure encryption key
        self.key = base64.urlsafe_b64encode(b'SecureFileTransfer2024_LongKey32Bytes!'[:32])
        self.cipher = Fernet(self.key)
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("File Transfer Server")
        self.root.geometry("600x500")
        
        # Setup GUI and start server
        self.setup_gui()
        self.start_server()

    def setup_gui(self):
        # Server status label
        tk.Label(self.root, text="Server Status:").pack(pady=(10, 0))
        
        # Scrolled text area for logs
        self.status_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=70, height=20)
        self.status_area.pack(padx=10, pady=10)

    def update_status(self, message):
        self.status_area.insert(tk.END, message + "\n")
        self.status_area.see(tk.END)

    def handle_client(self, client_socket, client_address):
        try:
            # Receive filename length
            filename_length_bytes = client_socket.recv(4)
            filename_length = int.from_bytes(filename_length_bytes, byteorder='big')
            
            # Receive filename
            filename = client_socket.recv(filename_length).decode()
            
            # Receive file size
            file_size_bytes = client_socket.recv(8)
            file_size = int.from_bytes(file_size_bytes, byteorder='big')
            
            # Receive encrypted file data
            encrypted_data = b''
            while len(encrypted_data) < file_size:
                chunk = client_socket.recv(self.buffer_size)
                if not chunk:
                    break
                encrypted_data += chunk
            
            # Decrypt file
            try:
                decrypted_data = self.cipher.decrypt(encrypted_data)
            except Exception as decrypt_error:
                self.update_status(f"Decryption error from {client_address}: {decrypt_error}")
                client_socket.send(b"FAILED")
                return

            # Save decrypted file
            save_path = os.path.join(self.save_path, filename)
            with open(save_path, 'wb') as file:
                file.write(decrypted_data)
            
            # Send success response
            client_socket.send(b"SUCCESS")
            
            # Update status
            self.update_status(f"Received file from {client_address}: {filename}")

        except Exception as e:
            self.update_status(f"Error receiving file from {client_address}: {e}")
            client_socket.send(b"FAILED")
        finally:
            client_socket.close()

    def start_server(self):
        def run_server():
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                # Bind and listen
                server_socket.bind((self.host, self.port))
                server_socket.listen(5)
                
                self.update_status(f"Server listening on {self.host}:{self.port}")
                
                while True:
                    # Accept client connections
                    client_socket, client_address = server_socket.accept()
                    self.update_status(f"Connection from {client_address}")
                    
                    # Handle each client in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, client_address)
                    )
                    client_thread.start()
            
            except Exception as e:
                self.update_status(f"Server error: {e}")
            finally:
                server_socket.close()

        # Start server in a separate thread
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    server = FileTransferServer()
    server.run()
