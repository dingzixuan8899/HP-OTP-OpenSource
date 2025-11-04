import os
import time
import hashlib
import struct
import json
from typing import Optional, Tuple


# --------------------------
# Protocol Public Parameters 
# --------------------------
N_BITS = 130    # OTP length (130 bits)
S_BITS = 80     # Salt length (id)
C_BITS = 32     # Time encoding bits
I = 30          # Time slot duration (30 seconds)
K = 1000        # Hash chain length (TEST ONLY: match device k)



# Server State Class 

class TKeyServerState:
    def __init__(self, id_bytes: bytes, p_prev: bytes, t_prev: int, t_init: int, k: int):
        """
        Initialize server state (stores p_prev, t_prev, id, t_init, k).
        Args:
            id_bytes: 80-bit salt (id) from device
            p_prev: Last valid OTP/p_init (tail of the hash chain)
            t_prev: Last valid time slot (t_init initially)
            t_init: Setup time slot from device
            k: Hash chain length from device
        """
        self.id_bytes = id_bytes    # Public salt (not a secret)
        self.p_prev = p_prev        # Last valid hash chain value (not a secret)
        self.t_prev = t_prev        # Last valid time slot
        self.t_init = t_init        # Setup time slot
        self.k = k                  # Hash chain length
        self.t_max = t_init + k     # Expiration time slot of the chain


# --------------------------
# Helper Functions 
# --------------------------
def get_time_slot(timestamp: float = None) -> int:
    """Convert UNIX timestamp to time slot (same as device)."""
    if timestamp is None:
        timestamp = time.time()
    return int(timestamp // I)


def compute_h_i(i: int, id_bytes: bytes, x_bytes: bytes) -> bytes:
    """Compute h_i(x) (same as device-side implementation)."""
    i_32bytes = struct.pack('>I', i)
    input_data = i_32bytes + id_bytes + x_bytes
    sha256_hash = hashlib.sha256(input_data).digest()
    sha256_bits = bin(int.from_bytes(sha256_hash, 'big'))[2:].zfill(256)
    truncated_bits = sha256_bits[:N_BITS]
    return int(truncated_bits, 2).to_bytes((N_BITS + 7) // 8, 'big')


# --------------------------
# Server Core Logic
# --------------------------
def parse_registration_qr(qr_data_str: str) -> Tuple[bytes, bytes, int, int]:
    """
    Parse QR code data to extract registration parameters (p_init, id, t_init, k).
    Args:
        qr_data_str: JSON string from scanned QR code
    Returns:
        Tuple: (p_init_bytes, id_bytes, t_init, k)
    """
    data = json.loads(qr_data_str)
    p_init_bytes = bytes.fromhex(data["p_init_hex"])
    id_bytes = bytes.fromhex(data["id_hex"])
    t_init = data["t_init"]
    k = data["k"]
    
    # Validate parameter lengths (security check)
    assert len(p_init_bytes) == (N_BITS + 7) // 8, f"Invalid p_init length: {len(p_init_bytes)} bytes"
    assert len(id_bytes) == (S_BITS + 7) // 8, f"Invalid id length: {len(id_bytes)} bytes"
    assert k > 0, "k must be positive"
    return p_init_bytes, id_bytes, t_init, k


def init_server_state(qr_data_str: str) -> TKeyServerState:
    """
    Initialize server state from QR code registration data (per Section 3).
    Args:
        qr_data_str: JSON string from scanned QR code
    Returns:
        TKeyServerState: Initialized server state
    """
    p_init, device_id, t_init, k = parse_registration_qr(qr_data_str)
    return TKeyServerState(
        id_bytes=device_id,
        p_prev=p_init,       # Initial p_prev = p_init
        t_prev=t_init,       # Initial t_prev = t_init
        t_init=t_init,
        k=k
    )


def verify_otp(state: TKeyServerState, otp_bytes: bytes, current_t: Optional[int] = None, window: int = 1) -> bool:
    """
    Verify OTP (p) at time slot `current_t` (per Section 3).
    Args:
        state: Server state object
        otp_bytes: OTP (p_t) from device (bytes)
        current_t: Authentication time slot (None = use current time)
        window: Allowable time skew (±window slots, per TOTP practice)
    Returns:
        bool: True if OTP is valid; False otherwise
    """
    # Step 1: Get current time slot (if not provided)
    if current_t is None:
        current_t = get_time_slot()
    
    # Step 2: Basic validity checks
    if len(otp_bytes) != (N_BITS + 7) // 8:
        print(f"Invalid OTP length: {len(otp_bytes)} bytes (expected { (N_BITS + 7) // 8 })")
        return False
    if current_t > state.t_max:
        print(f"Hash chain expired (current_t={current_t} > t_max={state.t_max})")
        return False
    if current_t < state.t_prev - window:
        print(f"OTP too old (current_t={current_t} < t_prev - window={state.t_prev - window})")
        return False
    
    # Step 3: Compute p_prev' = h_{t_prev}(h_{t_prev-1}(...h_{current_t+1}(otp)...))
    # (matches's p_prev' definition)
    current_val = otp_bytes
    start_step = current_t + 1
    end_step = min(state.t_prev + window, state.t_max)  # Allow window for time skew
    
    if start_step > end_step:
        print(f"No steps to compute (start_step={start_step} > end_step={end_step})")
        return False
    
    print(f"Verifying OTP: Computing h_{start_step} to h_{end_step}...")
    for step in range(start_step, end_step + 1):
        h_i_index = state.t_max - step  # i = t_init + k - step (matches h_i definition)
        current_val = compute_h_i(h_i_index, state.id_bytes, current_val)
    
    # Step 4: Compare computed p_prev' with stored p_prev
    if current_val == state.p_prev:
        # Update state on success
        state.p_prev = otp_bytes
        state.t_prev = current_t
        print(f"OTP verified successfully! Updated t_prev to {current_t}")
        return True
    else:
        print(f"OTP invalid: Computed p_prev'={current_val.hex()} != Stored p_prev={state.p_prev.hex()}")
        return False


# --------------------------
# Server Test Workflow
# --------------------------
if __name__ == "__main__":
    # Step 1: Simulate scanning the device's registration QR code

    with open("tkey_registration.png", "rb") as f:
        # For TESTING: Manually copy the JSON string from the device's registration data
        # Replace this with actual QR scanning logic (e.g., using pyzbar)
        registration_json = '''
        {
            "p_init_hex": "REPLACE_WITH_DEVICE_P_INIT_HEX",
            "id_hex": "REPLACE_WITH_DEVICE_ID_HEX",
            "t_init": REPLACE_WITH_DEVICE_T_INIT,
            "k": 1000
        }
        '''.strip()
    
    # Step 2: Initialize server state
    print("Initializing server state from QR code...")
    server_state = init_server_state(registration_json)
    print(f"Server state initialized: id={server_state.id_bytes.hex()}, t_init={server_state.t_init}, k={server_state.k}")
    
    # Step 3: Simulate receiving OTP from device (paste the OTP hex from the device)
    user_otp_hex = input("Enter OTP hex from device: ")
    user_otp = bytes.fromhex(user_otp_hex)
    
    # Step 4: Verify OTP
    current_t = get_time_slot()  # Use current server time slot
    is_valid = verify_otp(server_state, user_otp, current_t, window=1)
    print(f"Final Verification Result: {'PASS' if is_valid else 'FAIL'}")