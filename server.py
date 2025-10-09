"""
Distributed Computing System - Resource Sharing over LAN
Run server.py on the machine providing resources
Run client.py on the machine that wants to use remote resources
"""

# ==================== SERVER.PY ====================
# Run this on Laptop 2 (Resource Provider)

import socket
import subprocess
import json
import psutil
import threading
import os
from datetime import datetime

class ResourceServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.reserved_memory = 0  # MB
        self.reserved_cpu = 0  # percentage
        
    def get_available_resources(self):
        """Get current system resources"""
        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=1)
        return {
            'total_memory_mb': mem.total / (1024**2),
            'available_memory_mb': mem.available / (1024**2),
            'used_memory_mb': mem.used / (1024**2),
            'cpu_percent': cpu,
            'cpu_count': psutil.cpu_count()
        }
    
    def reserve_resources(self, memory_mb, cpu_percent):
        """Reserve resources for client"""
        resources = self.get_available_resources()
        
        if memory_mb > resources['available_memory_mb']:
            return False, f"Insufficient memory. Available: {resources['available_memory_mb']:.2f} MB"
        
        self.reserved_memory = memory_mb
        self.reserved_cpu = cpu_percent
        return True, f"Reserved {memory_mb} MB RAM and {cpu_percent}% CPU"
    
    def execute_process(self, command, working_dir=None):
        """Execute a process and return output"""
        try:
            start_time = datetime.now()
            
            # Execute the command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=working_dir
            )
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            return {
                'success': True,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'execution_time': execution_time
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Process execution timeout (5 minutes)'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def handle_client(self, client_socket, address):
        """Handle client connection"""
        print(f"[+] Connection from {address}")
        
        try:
            while True:
                # Receive data
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                request = json.loads(data)
                action = request.get('action')
                
                if action == 'get_resources':
                    resources = self.get_available_resources()
                    response = {'status': 'success', 'data': resources}
                
                elif action == 'reserve':
                    memory = request.get('memory_mb', 0)
                    cpu = request.get('cpu_percent', 0)
                    success, message = self.reserve_resources(memory, cpu)
                    response = {'status': 'success' if success else 'error', 'message': message}
                
                elif action == 'execute':
                    command = request.get('command')
                    working_dir = request.get('working_dir')
                    print(f"[*] Executing: {command}")
                    result = self.execute_process(command, working_dir)
                    response = {'status': 'success', 'data': result}
                
                elif action == 'release':
                    self.reserved_memory = 0
                    self.reserved_cpu = 0
                    response = {'status': 'success', 'message': 'Resources released'}
                
                else:
                    response = {'status': 'error', 'message': 'Unknown action'}
                
                # Send response
                client_socket.send(json.dumps(response).encode('utf-8'))
        
        except Exception as e:
            print(f"[-] Error handling client: {e}")
        finally:
            client_socket.close()
            print(f"[-] Connection closed: {address}")
    
    def start(self):
        """Start the server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        print(f"[*] Server listening on {self.host}:{self.port}")
        print(f"[*] Server IP: {socket.gethostbyname(socket.gethostname())}")
        
        try:
            while True:
                client, address = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client, address)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            server.close()

if __name__ == "__main__":
    server = ResourceServer()
    server.start()