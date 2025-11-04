import asyncio
import websockets
import json
from gmpy2 import mpz, powm, next_prime, randrange
from Crypto.Hash import SHA256
from typing import Dict, Tuple

# -------------------------- 1. Setup Phase: Initialize Protocol Parameters --------------------------
# Generate cyclic group G: prime order q (1024 bits for security) and generator g (select 2, verified as primitive root)
def setup_group() -> Tuple[mpz, mpz]:
    # Generate 1024-bit prime q (gmpy2.next_prime ensures primality)
    q = next_prime(mpz(2)** 1023)  # 1024-bit prime
    # Generator g=2 (simplified verification: 2 has high probability of being a primitive root of q)
    g = mpz(2)
    return q, g

# Global protocol parameters (initialized on server startup)
Q, G = setup_group()

# Hash function H: {0,1}* → Z_q (SHA256 hash converted to large integer, modulo Q)
def hash_func(data: bytes) -> mpz:
    sha256 = SHA256.new()
    sha256.update(data)
    # Convert hash result to hex string → large integer → modulo Q
    return mpz(sha256.hexdigest(), 16) % Q

# OTP generation function F_OTP: reference HOTP's hash+truncation (6-8 digits for usability per Section 4.2)
def generate_otp(e_c: mpz, c_s: mpz) -> str:
    # Input: e_c (device random number) and c_s (negotiated parameter) → concatenated as byte stream
    input_data = f"{e_c:x}_{c_s:x}".encode("utf-8")  # Hex conversion to avoid large integer overflow
    # Take first 12 hex digits (6 bytes) from hash, convert to integer, then mod 10^6 for 6-digit OTP
    hash_int = hash_func(input_data)
    otp = str(hash_int % 1000000).zfill(6)  # Pad to 6 digits with leading zeros
    return otp

# -------------------------- 2. Global Storage (simplified; replace with MySQL/Redis in production) --------------------------
# Storage structure: key=Device ID (DID), value=Password verification credential A_c
did_to_ac: Dict[str, mpz] = {}

# -------------------------- 3. WebSocket Connection Handling (Core Protocol Logic) --------------------------
async def handle_hpotp(websocket: websockets.WebSocketServerProtocol):
    """Process HP-OTP interactions for a single device (registration/verification/password change)"""
    print(f"New device connection: {websocket.remote_address}")
    current_did = None  # Currently interacting device ID
    verify_state = 0    # Verification state: 0=not started, 1=B_s sent, 2=verification complete

    try:
        async for message in websocket:
            # Parse JSON data sent by the device
            data = json.loads(message)
            msg_type = data.get("type")

            # -------------------------- 3.1 Registration Phase --------------------------
            if msg_type == "register":
                # Extract DID and A_c from device (A_c needs conversion to large integer)
                did = data.get("did")
                a_c_hex = data.get("a_c")
                
                # Basic format validation
                if not (did and a_c_hex and len(did) >= 8):
                    await websocket.send(json.dumps({"status": "fail", "msg": "Invalid DID or A_c format"}))
                    continue
                if did in did_to_ac:
                    await websocket.send(json.dumps({"status": "fail", "msg": "DID already registered"}))
                    continue

                # Convert A_c from hex string to large integer
                a_c = mpz(a_c_hex, 16)
                # Store DID-A_c mapping
                did_to_ac[did] = a_c
                await websocket.send(json.dumps({"status": "success", "msg": "Registration successful"}))
                print(f"Device registered: DID={did}, A_c={a_c_hex[:10]}...")

            # -------------------------- 3.2 Verification Phase --------------------------
            elif msg_type == "verify_step1":
                # Step 1: Server receives DID, generates m_s, computes B_s and sends it
                did = data.get("did")
                if did not in did_to_ac:
                    await websocket.send(json.dumps({"status": "fail", "msg": "DID not registered"}))
                    continue

                # 1.1 Generate random number m_s (within Z_q, using gmpy2 for secure randomness)
                m_s = randrange(Q)
                # 1.2 Retrieve stored A_c, compute B_s = A_c^m_s mod Q (using powm for efficient modular exponentiation)
                a_c = did_to_ac[did]
                b_s = powm(a_c, m_s, Q)
                # 1.3 Send B_s as hex string, record current DID and m_s (for subsequent verification)
                current_did = did
                current_m_s = m_s  # Temporarily store m_s for verification phase
                verify_state = 1   # Mark B_s as sent

                await websocket.send(json.dumps({
                    "status": "success",
                    "b_s": f"{b_s:x}",  # Transmit as hex string
                    "msg": "B_s sent, waiting for OTP"
                }))
                print(f"Verification Step 1 completed: DID={did}, m_s={hex(m_s)[:10]}..., B_s={hex(b_s)[:10]}...")

            elif msg_type == "verify_step3" and verify_state == 1:
                # Steps 2+3: Receive OTP, compute verification parameters and compare
                otp = data.get("otp")
                if not otp or len(otp) != 6 + 32:  # OTP format: 6-digit u + 32-char e_c (16-byte → 32 hex chars)
                    await websocket.send(json.dumps({"status": "fail", "msg": "Invalid OTP format (requires 6-digit u + 32-char e_c)"}))
                    continue

                # 2.1 Extract e_c (first 32 hex chars) and u (last 6 digits) from OTP
                e_c_hex = otp[:32]
                u_received = otp[32:]
                e_c = mpz(e_c_hex, 16)  # Convert e_c to large integer

                # 2.2 Retrieve stored A_c, compute t_c' = H(A_c || e_c)
                a_c = did_to_ac[current_did]
                # Concatenate A_c (hex) and e_c (hex), hash the byte stream
                t_c_input = f"{a_c:x}_{e_c_hex}".encode("utf-8")
                t_c_prime = hash_func(t_c_input)  # t_c' ∈ Z_q

                # 2.3 Compute C_s' = g^(t_c' * m_s) mod Q
                exponent = (t_c_prime * current_m_s) % Q  # Mod Q to avoid oversized exponents
                c_s_prime = powm(G, exponent, Q)

                # 2.4 Compute u' = F_OTP(e_c, C_s') and compare with received u
                u_calculated = generate_otp(e_c, c_s_prime)
                verify_result = (u_received == u_calculated)

                # 2.5 Return verification result
                if verify_result:
                    await websocket.send(json.dumps({"status": "success", "msg": "OTP verified, login successful"}))
                    print(f"Verification Step 3 completed: DID={current_did}, Result=Passed")
                else:
                    await websocket.send(json.dumps({"status": "fail", "msg": "OTP verification failed, invalid password or device"}))
                    print(f"Verification Step 3 completed: DID={current_did}, Result=Failed (received u={u_received}, computed u={u_calculated})")
                
                # Reset verification state
                verify_state = 0
                current_did = None
                current_m_s = None

            # -------------------------- 3.3 Password Change Phase --------------------------
            elif msg_type == "change_password":
                did = data.get("did")
                a_c_old_hex = data.get("a_c_old")  # A_c' corresponding to old password
                a_c_new_hex = data.get("a_c_new")  # A_c_new corresponding to new password

                # Basic validation
                if did not in did_to_ac:
                    await websocket.send(json.dumps({"status": "fail", "msg": "DID not registered"}))
                    continue
                if not (a_c_old_hex and a_c_new_hex):
                    await websocket.send(json.dumps({"status": "fail", "msg": "Invalid old/new A_c format"}))
                    continue

                # Convert to large integers
                a_c_old = mpz(a_c_old_hex, 16)
                a_c_new = mpz(a_c_new_hex, 16)
                a_c_stored = did_to_ac[did]

                # Verify old A_c matches (ensure legitimate user)
                if a_c_old != a_c_stored:
                    await websocket.send(json.dumps({"status": "fail", "msg": "Old password verification failed, cannot change"}))
                    continue

                # Update A_c to new value
                did_to_ac[did] = a_c_new
                await websocket.send(json.dumps({"status": "success", "msg": "Password changed successfully, A_c updated"}))
                print(f"Password updated: DID={did}, Old A_c={a_c_old_hex[:10]}..., New A_c={a_c_new_hex[:10]}...")

            # -------------------------- 3.4 Unknown Message Type --------------------------
            else:
                await websocket.send(json.dumps({"status": "fail", "msg": "Unknown message type"}))

    except websockets.exceptions.ConnectionClosedOK:
        print(f"Device disconnected normally: {websocket.remote_address}")
    except Exception as e:
        print(f"Interaction error: {str(e)}, Device={websocket.remote_address}")
    finally:
        # Clean up temporary state
        if current_did:
            print(f"Cleaning temporary state: DID={current_did}")

# -------------------------- 4. Start HP-OTP Server --------------------------
async def start_hpotp_server(host: str = "0.0.0.0", port: int = 8765):
    """Start WebSocket server and listen on specified port"""
    async with websockets.serve(handle_hpotp, host, port):
        print(f"HP-OTP server started: ws://{host}:{port}")
        print(f"Protocol parameters: Q (prime)={hex(Q)[:10]}..., G (generator)={G}")
        await asyncio.Future()  # Block to keep server running

if __name__ == "__main__":
    # Start server (ensure gmpy2 and other libraries are installed correctly)
    try:
        asyncio.run(start_hpotp_server())
    except KeyboardInterrupt:
        print("\nHP-OTP server shut down manually")
    except Exception as e:
        print(f"Server startup failed: {str(e)} (check if dependencies are installed correctly)")