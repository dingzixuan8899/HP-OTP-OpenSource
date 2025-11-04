import asyncio
import websockets
import json
from gmpy2 import mpz, powm, randrange, invert
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from typing import Tuple, Optional


class HPOTPDevice:
    def __init__(self, did: str, password: str):
        """
        Initialize HP-OTP device
        :param did: Unique Device ID (e.g., "device_dzx")
        :param password: User password for OTP generation
        """
        self.did = did
        self.password = password.encode("utf-8")  # Convert password to bytes
        self.q: Optional[mpz] = None  # Prime order of cyclic group (from server setup)
        self.g: Optional[mpz] = None  # Generator of cyclic group (from server setup)
        self.a_c: Optional[mpz] = None  # Device's public credential (A_c)
        self.k_c: mpz = randrange(mpz(2)**256)  # Device's long-term private key (256-bit)

    # -------------------------- Protocol Core Functions --------------------------
    def _hash_func(self, data: bytes) -> mpz:
        """Hash function H: {0,1}* → Z_q (same as server)"""
        sha256 = SHA256.new()
        sha256.update(data)
        return mpz(sha256.hexdigest(), 16) % self.q

    def generate_a_c(self) -> mpz:
        """
        Generate A_c = g^(H(pw || r_c) * k_c) mod q 
        (Registration phase credential, Section 4.2)
        """
        # Generate random r_c (256-bit)
        r_c = randrange(mpz(2)**256)
        # Compute H(pw || r_c)
        hash_input = self.password + r_c.to_bytes(32, byteorder="big")  # 32-byte r_c
        h_pw_rc = self._hash_func(hash_input)
        # Compute A_c = g^(H(pw||r_c) * k_c) mod q
        exponent = (h_pw_rc * self.k_c) % self.q
        self.a_c = powm(self.g, exponent, self.q)
        return self.a_c

    async def register(self, server_uri: str) -> bool:
        """
        Register device with server
        :param server_uri: WebSocket URI of HP-OTP server (e.g., "ws://localhost:8765")
        :return: Registration success status
        """
        try:
            async with websockets.connect(server_uri) as websocket:
                # 1. Get group parameters (Q, G) from server (simplified: reuse server's setup)
                # In practice, server may send Q/G during first connection; here we use same generation logic
                self.q, self.g = self._setup_group()  # Match server's group generation
                
                # 2. Generate A_c and send registration request
                self.generate_a_c()
                register_msg = {
                    "type": "register",
                    "did": self.did,
                    "a_c": f"{self.a_c:x}"  # Send as hex string
                }
                await websocket.send(json.dumps(register_msg))
                
                # 3. Receive registration result
                response = await websocket.recv()
                result = json.loads(response)
                if result["status"] == "success":
                    print(f"Device {self.did} registered successfully")
                    return True
                else:
                    print(f"Registration failed: {result['msg']}")
                    return False
        except Exception as e:
            print(f"Registration error: {str(e)}")
            return False

    async def verify(self, server_uri: str) -> bool:
        """
        Perform OTP verification with server
        :param server_uri: WebSocket URI of HP-OTP server
        :return: Verification success status
        """
        if not self.a_c:
            print("Device not registered. Please register first.")
            return False

        try:
            async with websockets.connect(server_uri) as websocket:
                # Step 1: Send DID to server and get B_s
                verify_step1 = {
                    "type": "verify_step1",
                    "did": self.did
                }
                await websocket.send(json.dumps(verify_step1))
                response = await websocket.recv()
                step1_result = json.loads(response)
                
                if step1_result["status"] != "success":
                    print(f"Verification Step 1 failed: {step1_result['msg']}")
                    return False

                # Parse B_s from server response (hex string → mpz)
                b_s = mpz(step1_result["b_s"], 16)
                print(f"Received B_s from server: {hex(b_s)[:10]}...")

                # Step 2: Device generates e_c, computes t_c, C_s, and OTP
                e_c = randrange(self.q)  # Random number e_c ∈ Z_q
                # Compute t_c = H(A_c || e_c)
                t_c_input = f"{self.a_c:x}_{e_c:x}".encode("utf-8")  # A_c (hex) + e_c (hex)
                t_c = self._hash_func(t_c_input)
                # Compute C_s = B_s^t_c mod q
                c_s = powm(b_s, t_c, self.q)
                # Generate OTP: e_c (32 hex chars) + u (6 digits)
                u = self._generate_otp(e_c, c_s)
                otp = f"{e_c:x}".zfill(32) + u  # e_c padded to 32 hex chars + 6-digit u
                print(f"Generated OTP: {otp[:32]}...{u} (e_c + u)")

                # Step 3: Send OTP to server for verification
                verify_step3 = {
                    "type": "verify_step3",
                    "otp": otp
                }
                await websocket.send(json.dumps(verify_step3))
                final_response = await websocket.recv()
                final_result = json.loads(final_response)

                if final_result["status"] == "success":
                    print("OTP verified successfully. Login granted.")
                    return True
                else:
                    print(f"Verification failed: {final_result['msg']}")
                    return False

        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False

    async def change_password(self, server_uri: str, new_password: str) -> bool:
        """
        Change password
        :param server_uri: WebSocket URI of HP-OTP server
        :param new_password: New user password
        :return: Password change success status
        """
        if not self.a_c:
            print("Device not registered. Please register first.")
            return False

        try:
            async with websockets.connect(server_uri) as websocket:
                # 1. Generate old A_c (current credential) and new A_c (with new password)
                old_a_c = self.a_c
                self.password = new_password.encode("utf-8")  # Update password
                new_a_c = self.generate_a_c()  # Generate new A_c with new password

                # 2. Send password change request
                change_msg = {
                    "type": "change_password",
                    "did": self.did,
                    "a_c_old": f"{old_a_c:x}",  # Old credential
                    "a_c_new": f"{new_a_c:x}"   # New credential
                }
                await websocket.send(json.dumps(change_msg))

                # 3. Receive result
                response = await websocket.recv()
                result = json.loads(response)
                if result["status"] == "success":
                    print("Password changed successfully")
                    return True
                else:
                    print(f"Password change failed: {result['msg']}")
                    # Revert password if change failed
                    self.password = new_password.encode("utf-8")
                    self.generate_a_c()
                    return False

        except Exception as e:
            print(f"Password change error: {str(e)}")
            return False

    # -------------------------- Helper Functions --------------------------
    @staticmethod
    def _setup_group() -> Tuple[mpz, mpz]:
        """Generate cyclic group (same as server to ensure compatibility)"""
        q = next_prime(mpz(2)**1023)  # 1024-bit prime
        g = mpz(2)  # Generator
        return q, g

    def _generate_otp(self, e_c: mpz, c_s: mpz) -> str:
        """Generate 6-digit OTP using F_OTP (same as server)"""
        input_data = f"{e_c:x}_{c_s:x}".encode("utf-8")
        hash_int = self._hash_func(input_data)
        return str(hash_int % 1000000).zfill(6)  # 6-digit OTP


# -------------------------- Test the Device --------------------------
async def test_device():
    # Initialize device with DID and initial password
    device = HPOTPDevice(did="my_device_001", password="my_secure_password_123")
    
    # 1. Register with server (ensure server is running first)
    server_uri = "ws://localhost:8765"
    register_success = await device.register(server_uri)
    if not register_success:
        return
    
    # 2. Perform verification (simulate login)
    await device.verify(server_uri)
    
    # 3. Change password (simulate password update)
    await device.change_password(server_uri, new_password="new_secure_password_456")
    
    # 4. Verify with new password
    await device.verify(server_uri)


if __name__ == "__main__":
    try:
        asyncio.run(test_device())
    except KeyboardInterrupt:
        print("\nDevice operation cancelled")
    except Exception as e:
        print(f"Device error: {str(e)}")