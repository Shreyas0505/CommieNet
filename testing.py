class TrustedDeployer:
    """
    Deploys files to trusted receivers on network
    ⚠️ All targets must be running receiver.py first
    """
    
    def __init__(self, port=DEPLOY_PORT):
        self.port = port
        self.secret_hash = hash_secret(SHARED_SECRET)
    
    def deploy_to_target(self, target_ip, filepath, auto_run=True):
        """Deploy file to a specific target"""
        try:
            print(f"\n[*] Deploying to {target_ip}...")
            
            # Check file exists
            if not os.path.exists(filepath):
                print(f"[-] File not found: {filepath}")
                return False
            
            # Connect to target
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, self.port))
            
            # Prepare metadata
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            metadata = {
                'auth_hash': self.secret_hash,
                'filename': filename,
                'filesize': filesize,
                'auto_run': auto_run
            }
            
            metadata_json = json.dumps(metadata).encode('utf-8')
            
            # Send metadata
            sock.send(len(metadata_json).to_bytes(4, 'big'))
            sock.send(metadata_json)
            
            # Wait for auth response
            response = sock.recv(1024)
            if response != b'AUTH_OK':
                print(f"[-] Authentication failed on {target_ip}")
                return False
            
            print(f"[+] Authenticated with {target_ip}")
            
            # Send file
            with open(filepath, 'rb') as f:
                sent = 0
                while sent < filesize:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    sock.send(chunk)
                    sent += len(chunk)
                    
                    # Progress
                    progress = (sent / filesize) * 100
                    print(f"\r[*] Progress: {progress:.1f}%", end='')
            
            print()  # New line
            
            # Wait for confirmation
            response = sock.recv(1024)
            if response == b'FILE_RECEIVED':
                status = "DEPLOYED & EXECUTING" if auto_run else "DEPLOYED"
                print(f"[+] {status} on {target_ip}")
                return True
            
        except socket.timeout:
            print(f"[-] Timeout connecting to {target_ip}")
            print(f"    Is receiver.py running on that machine?")
        except ConnectionRefusedError:
            print(f"[-] Connection refused by {target_ip}")
            print(f"    Make sure receiver.py is running there first!")
        except Exception as e:
            print(f"[-] Error deploying to {target_ip}: {e}")
        finally:
            sock.close()
        
        return False
    
    def discover_and_deploy(self, filepath, auto_run=True):
        """Discover receivers and deploy to all"""
        print("\n" + "="*60)
        print("⚠️  DISCOVERING RECEIVERS FOR AUTO-DEPLOYMENT  ⚠️")
        print("="*60)
        
        # Simple broadcast to find receivers
        # In real scenario, receivers would broadcast their presence
        
        print("\n[*] Enter target IPs (one per line, empty line to finish):")
        targets = []
        while True:
            ip = input("Target IP: ").strip()
            if not ip:
                break
            targets.append(ip)
        
        if not targets:
            print("[-] No targets specified")
            return
        
        print(f"\n[*] Will deploy: {filepath}")
        print(f"[*] Auto-run: {auto_run}")
        print(f"[*] Targets: {len(targets)}")
        
        confirm = input("\n⚠️  Proceed with deployment? (yes/no): ")
        if confirm.lower() != 'yes':
            print("[*] Deployment cancelled")
            return
        
        # Deploy to all targets
        success = 0
        for target_ip in targets:
            if self.deploy_to_target(target_ip, filepath, auto_run):
                success += 1
        
        print("\n" + "="*60)
        print(f"[*] Deployment complete: {success}/{len(targets)} successful")
        print("="*60)


# ==================== MAIN ====================

def main():
    print("\n" + "="*60)
    print("⚠️  TRUSTED AUTO-DEPLOY SYSTEM - EDUCATIONAL ONLY  ⚠️")
    print("="*60)
    print("\nWARNING: This system auto-executes code over network")
    print("Only use in private networks you own and control!")
    print("\nMode:")
    print("1. RECEIVER - Run this FIRST on machines that will receive")
    print("2. DEPLOYER - Run this to deploy to receivers")
    print("="*60)
    
    choice = input("\nChoose mode (1/2): ").strip()
    
    if choice == '1':
        print("\n⚠️  Starting RECEIVER mode...")
        print("This machine will AUTO-EXECUTE files from trusted sources")
        confirm = input("Continue? (yes/no): ")
        if confirm.lower() == 'yes':
            receiver = TrustedReceiver()
            receiver.start()
        else:
            print("Cancelled")
    
    elif choice == '2':
        print("\n⚠️  Starting DEPLOYER mode...")
        deployer = TrustedDeployer()
        
        filepath = input("\nFile to deploy: ").strip()
        auto_run = input("Auto-run on targets? (yes/no): ").strip().lower() == 'yes'
        
        deployer.discover_and_deploy(filepath, auto_run)
    
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
