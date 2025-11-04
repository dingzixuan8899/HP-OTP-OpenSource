import socket
import ssl
import time
import random
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# --------------------------
# Constants (Match Server)
# --------------------------
SERVER_HOST = '127.0.0.1'  # Replace with server IP in LAN/WAN
SERVER_PORT = 4433
TIME_STEP_X = 30  # 30 seconds (TOTP standard)
HASH_ALG = hashes.SHA256()
HMAC_ALG = hashes.SHA1()
ECC_CURVE = ec.SECP256R1()
OTP_LENGTH = 6
RECOMMENDED_HONEYWORDS = 20  # k=20 (paper's recommendation)
DEVICE_STORAGE = "htotp_device_storage.txt"  # Stores (username, rc, T1)

class HTOTPDevice:
    def __init__(self):
        self.username = None
        self.rc = None  # Device-stored salt (paper §IV.B.2)
        self.T1 = None  # Registration timestamp (paper §IV.B.2)
        self.hc_pub_key = None  # Honeychecker's public key (from server)
        # Load stored data (if registered before)
        self._load_device_storage()

    def _load_device_storage(self):
        """Load salt (rc) and T1 from device storage (simulate secure storage)."""
        try:
            with open(DEVICE_STORAGE, "r") as f:
                lines = f.readlines()
                if lines:
                    self.username, rc_b64, T1_str = lines[0].split('|')
                    self.rc = base64.b64decode(rc_b64)
                    self.T1 = int(T1_str)
                    print(f"[Device] Loaded stored data for user {self.username}")
        except FileNotFoundError:
            print("[Device] No existing storage (first run)")

    def _save_device_storage(self):
        """Save salt (rc) and T1 to device storage (simulate secure storage)."""
        if not (self.username and self.rc and self.T1):
            raise ValueError("Device data not fully initialized")
        rc_b64 = base64.b64encode(self.rc).decode('utf-8')
        with open(DEVICE_STORAGE, "w") as f:
            f.write(f"{self.username}|{rc_b64}|{self.T1}")
        print(f"[Device] Saved data to {DEVICE_STORAGE}")

    def _hash(self, data: bytes) -> bytes:
        """SHA-256 hash (for salted password hashes, paper §IV.B.2)."""
        digest = hashes.Hash(HASH_ALG, default_backend())
        digest.update(data)
        return digest.finalize()

    def _generate_honeywords(self, real_pw: str) -> list:
        """
        Generate honeywords (decoy passwords) per paper §IV.B.1:
        - Mix real password with popular passwords and variations
        - Ensures flatness (1/k probability of guessing real password)
        """
        # Sample popular passwords (replace with larger dataset in production)
        popular_pw = [
            "Password123", "12345678", "qwerty123", "admin123", "user@123",
            "123456789", "letmein123", "welcome123", "football123", "iloveyou123",
            "abc123456", "123abc456", "password1", "1q2w3e4r", "5t6y7u8i"
        ]
        # Generate variations of real password (e.g., add numbers, uppercase)
        pw_variations = [
            real_pw.upper(), real_pw.lower(), f"{real_pw}123", f"{real_pw}!",
            f"_{real_pw}_", f"{real_pw[::-1]}"  # Reverse real password
        ]
        # Combine and shuffle: 1 real pw + 19 honeywords (total 20)
        honeywords = [real_pw] + popular_pw[:10] + pw_variations[:9]
        random.shuffle(honeywords)
        return honeywords

    def _encrypt_index(self, Ic: int) -> tuple:
        """
        Encrypt real index Ic using ElGamal variant (paper §IV.B.2):
        - E = g^e (ephemeral public key)
        - M = PK_HC^e XOR Ic (encrypted index)
        - Returns (E_bytes, M_bytes)
        """
        if not self.hc_pub_key:
            raise ValueError("Honeychecker public key not loaded")
        
        # Generate ephemeral key e
        e = ec.generate_private_key(ECC_CURVE, default_backend())
        E = e.public_key()  # E = g^e
        E_bytes = E.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Compute PK_HC^e (shared secret)
        shared_secret = e.exchange(ec.ECDH(), self.hc_pub_key)
        # XOR with Ic (convert Ic to bytes matching shared secret length)
        shared_secret_int = int.from_bytes(shared_secret, byteorder='big')
        Ic_bytes = Ic.to_bytes(len(shared_secret), byteorder='big')
        Ic_int = int.from_bytes(Ic_bytes, byteorder='big')
        M_int = shared_secret_int ^ Ic_int
        M_bytes = M_int.to_bytes(len(shared_secret), byteorder='big')

        return (E_bytes, M_bytes)

    def _get_hc_pub_key(self) -> ec.EllipticCurvePublicKey:
        """Fetch honeychecker's public key from server (setup phase)."""
        # Connect to server (unencrypted first to get pub key; simulate setup)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Disable cert verification for setup (only for testing!)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            with ssl_context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
                secure_sock.connect((SERVER_HOST, SERVER_PORT))
                # Send dummy command to trigger server's pub key display (simplified)
                secure_sock.sendall(b"GET_HC_PUB_KEY")
                # Read pub key (server prints it; in production, use a dedicated API)
                # Note: For testing, copy the pub key from server logs and paste here!
                print("\n[Device] Copy Honeychecker Public Key from Server Logs:")
                print("Example: -----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----")
                hc_pub_key_pem = input("Paste here: ").strip()
                # Deserialize pub key
                hc_pub_key = serialization.load_pem_public_key(
                    hc_pub_key_pem.encode('utf-8'),
                    backend=default_backend()
                )
                return hc_pub_key

    def register(self):
        """
        User registration (paper §IV.B.2):
        1. Input username/password
        2. Generate salt (rc) and honeywords
        3. Compute salted hashes Q = [H(pw||rc)] + [H(wi||rc)]
        4. Encrypt real index Ic; send to server
        """
        if self.username:
            print(f"[Device] Already registered as {self.username}")
            return

        # Step 1: Input user credentials
        self.username = input("Enter username: ").strip()
        real_pw = input("Enter password: ").strip()

        # Step 2: Load honeychecker pub key
        self.hc_pub_key = self._get_hc_pub_key()

        # Step 3: Generate salt (rc) (random 32 bytes, paper §IV.B.2)
        self.rc = os.urandom(32)  # Use os.urandom for cryptographically secure random
        print(f"[Device] Generated salt (rc): {base64.b64encode(self.rc).decode('utf-8')}")

        # Step 4: Generate honeywords and salted hashes Q
        honeywords = self._generate_honeywords(real_pw)
        Q = []
        real_pw_index = None  # Track index of real password in Q
        for idx, pw in enumerate(honeywords):
            # Compute salted hash: H(pw || rc)
            salted_pw = pw.encode('utf-8') + self.rc
            hash_val = self._hash(salted_pw)
            Q.append(hash_val)
            # Record index of real password
            if pw == real_pw:
                real_pw_index = idx
        print(f"[Device] Generated Q (size: {len(Q)}), real index: {real_pw_index}")

        # Step 5: Encrypt real index Ic = real_pw_index
        E_bytes, M_bytes = self._encrypt_index(real_pw_index)

        # Step 6: Prepare registration data (base64 encode binary data)
        e_bytes_b64 = base64.b64encode(E_bytes).decode('utf-8')
        m_bytes_b64 = base64.b64encode(M_bytes).decode('utf-8')
        q_list_b64 = ','.join([base64.b64encode(h).decode('utf-8') for h in Q])
        self.T1 = int(time.time())  # Registration timestamp T1

        # Step 7: Send to server via TLS
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False  # Disable for testing
            ssl_context.verify_mode = ssl.CERT_NONE
            with ssl_context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
                secure_sock.connect((SERVER_HOST, SERVER_PORT))
                # Send command + data: "REGISTER|username|E|M|Q|T1"
                data = f"REGISTER|{self.username}|{e_bytes_b64}|{m_bytes_b64}|{q_list_b64}|{self.T1}"
                secure_sock.sendall(data.encode('utf-8'))
                # Receive response
                response = secure_sock.recv(1024).decode('utf-8')
                if response == "REG_SUCCESS: User registered":
                    self._save_device_storage()
                    print("[Device] Registration successful!")
                else:
                    print(f"[Device] Registration failed: {response}")

    def generate_otp(self) -> str:
        """
        Generate OTP offline (paper §IV.B.3):
        1. Input password (pw')
        2. Compute salted hash: qc' = H(pw' || rc)
        3. Compute Ts = (T2 - T1)/X
        4. Generate OTP = Truncate(HMAC-SHA1(qc', Ts))
        """
        if not (self.username and self.rc and self.T1):
            print("[Device] Not registered! Run 'register()' first.")
            return ""

        # Step 1: Input password (pw')
        pw_prime = input("Enter password to generate OTP: ").strip()

        # Step 2: Compute salted hash qc' = H(pw' || rc)
        salted_pw_prime = pw_prime.encode('utf-8') + self.rc
        qc_prime = self._hash(salted_pw_prime)

        # Step 3: Compute Ts = (T2 - T1)/X (T2 = current time)
        T2 = int(time.time())
        Ts = (T2 - self.T1) // TIME_STEP_X
        print(f"[Device] Current Ts: {Ts} (T2: {T2}, T1: {self.T1})")

        # Step 4: Generate OTP (HMAC-SHA1 + truncation)
        timestamp_bytes = Ts.to_bytes(8, byteorder='big')
        hmac = hashes.Hash(hashes.HMAC(qc_prime, HMAC_ALG, backend=default_backend()))
        hmac.update(timestamp_bytes)
        hmac_result = hmac.finalize()

        # Dynamic truncation (RFC 4226 §5.3)
        offset = hmac_result[-1] & 0x0F
        truncated = hmac_result[offset:offset+4]
        truncated_int = int.from_bytes(truncated, byteorder='big') & 0x7FFFFFFF
        otp = str(truncated_int % (10 ** OTP_LENGTH)).zfill(OTP_LENGTH)

        print(f"[Device] Generated OTP: {otp} (valid for {TIME_STEP_X}s)")
        return otp

    def verify_otp(self, otp: str):
        """Send OTP to server for verification (paper §IV.B.3)."""
        if not self.username:
            print("[Device] Not registered!")
            return

        # Send OTP to server via TLS
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False  # Disable for testing
            ssl_context.verify_mode = ssl.CERT_NONE
            with ssl_context.wrap_socket(sock, server_hostname=SERVER_HOST) as secure_sock:
                secure_sock.connect((SERVER_HOST, SERVER_PORT))
                # Send command + data: "VERIFY|username|OTP"
                data = f"VERIFY|{self.username}|{otp}"
                secure_sock.sendall(data.encode('utf-8'))
                # Receive verification result
                response = secure_sock.recv(1024).decode('utf-8')
                print(f"[Device] Verification Response: {response}")

if __name__ == "__main__":
    import os  # Required for os.urandom (salt generation)
    device = HTOTPDevice()

    # Interactive menu
    while True:
        print("\n===== HTOTP Device Menu =====")
        print("1. Register (first-time use)")
        print("2. Generate OTP")
        print("3. Verify OTP (send to server)")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":
            device.register()
        elif choice == "2":
            device.generate_otp()
        elif choice == "3":
            otp = input("Enter OTP to verify: ").strip()
            if len(otp) == OTP_LENGTH and otp.isdigit():
                device.verify_otp(otp)
            else:
                print("Invalid OTP (must be 6 digits)")
        elif choice == "4":
            print("[Device] Exiting...")
            break
        else:
            print("Invalid choice. Try again.")
