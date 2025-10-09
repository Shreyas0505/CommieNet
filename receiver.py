class TrustedReceiver:
    """
    Receives and executes code from trusted sources
    ⚠️ MUST BE MANUALLY INSTALLED ON EACH MACHINE FIRST
    """
    
    def __init__(self, port=DEPLOY_PORT):
        self.port = port
        self.secret_hash = hash_secret(SHARED_SECRET)
        self.received_files_dir = Path("received_files")
        self.received_files_dir.mkdir(exist_ok=True)
    
    def authenticate(self, provided_hash):
        """Verify the sender is trusted"""
        return provided_hash == self.secret_hash
    
    def execute_file(self, filepath, auto_run=True):
        """Execute received file"""
        try:
            if not auto_run:
                print(f"[*] File saved: {filepath}")
                print(f"[*] To run: python {filepath}")
                return
            
            print(f"[!] AUTO-EXECUTING: {filepath}")
            print("[!] This is dangerous - only do this with trusted sources!\n")
            
            # Execute the file
            if filepath.endswith('.py'):
                result = subprocess.Popen(
                    [sys.executable, str(filepath)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print(f"[+] Executed with PID: {result.pid}")
                return result.pid
            else:
                print(f"[-] Cannot auto-execute non-Python file")
                
        except Exception as e:
            print(f"[-] Execution error: {e}")
    
    def handle_deployment(self, client_socket, address):
        """Handle incoming deployment"""
        try:
            # Receive metadata
            metadata_size = int.from_bytes(client_socket.recv(4), 'big')
            metadata_json = client_socket.recv(metadata_size).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            # Authenticate
            if not self.authenticate(metadata['auth_hash']):
                print(f"[-] Authentication failed from {address[0]}")
                client_socket.send(b'AUTH_FAILED')
                return
            
            print(f"[+] Authenticated deployment from {address[0]}")
            client_socket.send(b'AUTH_OK')
            
            # Receive file
            filename = metadata['filename']
            filesize = metadata['filesize']
            auto_run = metadata.get('auto_run', False)
            
            print(f"[*] Receiving: {filename} ({filesize} bytes)")
            
            filepath = self.received_files_dir / filename
            received = 0
            
            with open(filepath, 'wb') as f:
                while received < filesize:
                    chunk = client_socket.recv(min(4096, filesize - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
            
            print(f"[+] File received: {filepath}")
            
            # Send confirmation
            client_socket.send(b'FILE_RECEIVED')
            
            # Auto-execute if requested
            if auto_run:
                time.sleep(1)  # Brief delay
                self.execute_file(filepath, auto_run=True)
            
        except Exception as e:
            print(f"[-] Error handling deployment: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        """Start receiver service"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(5)
        
        local_ip = socket.gethostbyname(socket.gethostname())
        print("="*60)
        print("⚠️  TRUSTED RECEIVER ACTIVE - WILL AUTO-EXECUTE CODE  ⚠️")
        print("="*60)
        print(f"[*] Listening on: {local_ip}:{self.port}")
        print(f"[*] Authenticated deployments will AUTO-EXECUTE")
        print(f"[*] Press Ctrl+C to stop\n")
        
        try:
            while True:
                client, address = server.accept()
                thread = threading.Thread(
                    target=self.handle_deployment,
                    args=(client, address)
                )
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down receiver...")
        finally:
            server.close()
