import socket
import json
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    # returns 32-byte key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_bytes(aesgcm_key: bytes, plaintext: bytes) -> (bytes, bytes):
    aesgcm = AESGCM(aesgcm_key)
    nonce = os.urandom(12)  # 96-bit nonce for AESGCM
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct

def decrypt_bytes(aesgcm_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(aesgcm_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

# ---------- ResourceClient ----------
class ResourceClient:
    def __init__(self, server_ip, server_port=5555, passphrase: str = None, salt: bytes = None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None

        # encryption config: if passphrase provided, derive key
        self.aes_key = None
        self.salt = salt or b"fixed_salt_16b"  # change to secure salt management
        if passphrase:
            self.aes_key = derive_key_from_passphrase(passphrase, self.salt)

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            print(f"[+] Connected to {self.server_ip}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    # --- send_request now supports optional full-message encryption ---
    def send_request(self, request_dict):
        """
        If self.aes_key is set, encrypts the JSON bytes and sends:
            { "enc": true, "nonce": "<b64>", "payload": "<b64>" }
        Otherwise sends plain JSON.
        """
        try:
            raw = json.dumps(request_dict).encode('utf-8')

            if self.aes_key:
                nonce, ct = encrypt_bytes(self.aes_key, raw)
                envelope = {
                    "enc": True,
                    "nonce_b64": base64.b64encode(nonce).decode('utf-8'),
                    "payload_b64": base64.b64encode(ct).decode('utf-8')
                }
                to_send = json.dumps(envelope).encode('utf-8')
            else:
                to_send = raw

            # send length-prefix first (4 bytes big-endian) to support large messages reliably
            length = len(to_send).to_bytes(4, 'big')
            self.socket.sendall(length + to_send)

            # receive length-prefixed response
            header = self._recv_exact(4)
            if not header:
                return None
            resp_len = int.from_bytes(header, 'big')
            resp_bytes = self._recv_exact(resp_len)
            if not resp_bytes:
                return None

            # parse response
            resp_json = json.loads(resp_bytes.decode('utf-8'))
            if self.aes_key and resp_json.get("enc"):
                nonce = base64.b64decode(resp_json["nonce_b64"])
                payload = base64.b64decode(resp_json["payload_b64"])
                decrypted = decrypt_bytes(self.aes_key, nonce, payload)
                return json.loads(decrypted.decode('utf-8'))
            else:
                return resp_json

        except Exception as e:
            print(f"[-] Request failed: {e}")
            return None

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.socket.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # --- upload_file uses payload encryption for the file content as well (already covered by send_request if aes_key set) ---
    def upload_file(self, local_path, remote_path):
        try:
            with open(local_path, "rb") as f:
                data = f.read()
            # If using aes_key, send raw bytes — send_request will encrypt entire JSON envelope
            # But to be explicit we base64 the content to keep JSON safe
            content_b64 = base64.b64encode(data).decode('utf-8')
            req = {
                "action": "upload",
                "remote_path": remote_path,
                "content_b64": content_b64
            }
            response = self.send_request(req)
            if response and response.get("status") == "ok":
                print(f"[+] Uploaded {local_path} → {remote_path}")
                return True
            else:
                print("[-] Upload failed:", response)
                return False
        except Exception as e:
            print(f"[-] Upload error: {e}")
            return False

    def execute_remote(self, command, working_dir=None):
        request = {
            "action": "execute",
            "command": command,
            "working_dir": working_dir
        }
        response = self.send_request(request)
        return response.get("data") if response else None

    def disconnect(self):
        if self.socket:
            self.socket.close()
            print("[*] Disconnected from server")
