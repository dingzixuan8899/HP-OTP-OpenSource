import os
import time
import hashlib
import struct
import qrcode
from PIL import Image


# --------------------------
# Protocol Public Parameters 
# --------------------------
N_BITS = 130    # OTP length (130 bits for 128-bit security)
S_BITS = 80     # Salt length (id)
C_BITS = 32     # Time encoding bits
I = 30          # Time slot duration (30 seconds)
K = 1000        # Hash chain length (TEST ONLY: use 2e6 for 2-year validity in production)
M_BITS = 256    # SHA-256 output size (matches protocol's H)


def generate_crypto_random(bits: int) -> bytes:
    """
    Generate cryptographically secure random bytes (for sk and id).
    Args:
        bits: Number of random bits needed
    Returns:
        bytes: Random bytes (padded to full bytes)
    """
    num_bytes = (bits + 7) // 8   
    return os.urandom(num_bytes)


def get_time_slot(timestamp: float = None) -> int:
    """
    Convert UNIX timestamp to a time slot (30-second intervals since UNIX epoch).
    Args:
        timestamp: UNIX timestamp (None = use current time)
    Returns:
        int: Time slot index (t_init or authentication time t)
    """
    if timestamp is None:
        timestamp = time.time()
    return int(timestamp // I)


def compute_h_i(i: int, id_bytes: bytes, x_bytes: bytes) -> bytes:
    """
    Compute h_i(x) = SHA-256(<i>_32 || id || x) truncated to 130 bits (per Section 3).
    Args:
        i: 32-bit time slot index for domain separation
        id_bytes: 80-bit salt (id) as bytes
        x_bytes: Input to hash function (e.g., sk or intermediate hash chain value)
    Returns:
        bytes: 130-bit output of h_i(x) (padded to 17 bytes)
    """
    # Step 1: Encode i as 32-bit big-endian bytes (<i>_32)
    i_32bytes = struct.pack('>I', i)  # '>I' = big-endian unsigned 32-bit integer
    
    # Step 2: Concatenate <i>_32 || id || x
    input_data = i_32bytes + id_bytes + x_bytes
    
    # Step 3: Compute SHA-256 hash
    sha256_hash = hashlib.sha256(input_data).digest()  # 256 bits (32 bytes)
    
    # Step 4: Truncate to 130 bits (convert hash to bit string first)
    sha256_bits = bin(int.from_bytes(sha256_hash, 'big'))[2:]  # Remove '0b' prefix
    sha256_bits_padded = sha256_bits.zfill(M_BITS)  # Ensure 256 bits (pad leading zeros)
    truncated_bits = sha256_bits_padded[:N_BITS]    # Take first 130 bits
    
    # Step 5: Convert truncated bits back to bytes (17 bytes = 136 bits; leading zeros preserved)
    truncated_int = int(truncated_bits, 2)
    return truncated_int.to_bytes((N_BITS + 7) // 8, 'big')


def compute_p_init(sk_bytes: bytes, id_bytes: bytes, t_init: int, k: int) -> bytes:
    """
    Compute p_init = h_k(h_{k-1}(...h_1(sk)...)) (tail of the hash chain).
    Args:
        sk_bytes: 130-bit secret key (sk) as bytes
        id_bytes: 80-bit salt (id) as bytes
        t_init: Time slot at setup (t_init)
        k: Length of the hash chain (K)
    Returns:
        bytes: p_init (tail of the hash chain)
    """
    current_val = sk_bytes  # Start with sk (head of the chain)
    t_max = t_init + k      # Max time slot for the chain (t_init + K)
    
    # Iterate h_1 to h_k: h_i uses i = t_max - step (step 1→k)
    for step in range(1, k + 1):
        h_i_index = t_max - step  # i = t_init + k - step (matches h_i definition)
        current_val = compute_h_i(h_i_index, id_bytes, current_val)
        
        # Optional: Progress update for large k (comment out in production)
        if step % 100 == 0:
            print(f"Computing p_init: Step {step}/{k}")
    
    return current_val


def generate_registration_qr(p_init: bytes, id_bytes: bytes, t_init: int, k: int) -> Image.Image:
    """
    Generate a QR code for server registration (contains p_init, id, t_init, k).
    Args:
        p_init: Tail of the hash chain (bytes)
        id_bytes: 80-bit salt (bytes)
        t_init: Setup time slot (int)
        k: Hash chain length (int)
    Returns:
        PIL.Image.Image: QR code image
    """
    # Serialize data to JSON (encode bytes as hex for readability)
    registration_data = {
        "p_init_hex": p_init.hex(),
        "id_hex": id_bytes.hex(),
        "t_init": t_init,
        "k": k
    }
    data_str = json.dumps(registration_data)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data_str)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white")


def compute_otp(sk_bytes: bytes, id_bytes: bytes, t_init: int, k: int, current_t: int) -> bytes:
    """
    Compute OTP (p_t) for authentication at time slot `current_t`.
    Args:
        sk_bytes: 130-bit secret key (sk) as bytes
        id_bytes: 80-bit salt (id) as bytes
        t_init: Setup time slot (t_init)
        k: Hash chain length (K)
        current_t: Current authentication time slot (t)
    Returns:
        bytes: OTP (p_t)
    """
    t_max = t_init + k
    steps = t_max - current_t  # Number of hashes: h_1 to h_{t_max - t}
    
    if steps < 0:
        raise ValueError(f"Hash chain expired (current_t={current_t} > t_max={t_max})")
    
    current_val = sk_bytes
    for step in range(1, steps + 1):
        # i = t_max - (current_t + step - 1) (matches h_{t_max -t - step +1} definition)
        h_i_index = t_max - (current_t + step - 1)
        current_val = compute_h_i(h_i_index, id_bytes, current_val)
    
    return current_val


# --------------------------
# Device Test Workflow
# --------------------------
if __name__ == "__main__":
    # Step 1: Generate device secrets and setup parameters
    sk = generate_crypto_random(N_BITS)          # 130-bit secret key
    device_id = generate_crypto_random(S_BITS)   # 80-bit salt (id)
    t_init = get_time_slot()                     # Time slot at setup
    k = K                                        # Hash chain length (TEST: 1000)
    
    # Step 2: Compute p_init (tail of the hash chain)
    print(f"Starting p_init computation (k={k})...")
    p_init = compute_p_init(sk, device_id, t_init, k)
    print(f"p_init computed: {p_init.hex()}")
    
    # Step 3: Generate registration QR code (scan this with server)
    qr_image = generate_registration_qr(p_init, device_id, t_init, k)
    qr_image.save("tkey_registration.png")
    print("Registration QR code saved as 'tkey_registration.png'")
    
    # Step 4: Simulate authentication 
    time.sleep(5 * 60)   
    current_t = get_time_slot()
    otp = compute_otp(sk, device_id, t_init, k, current_t)
    print(f"Generated OTP for t={current_t}: {otp.hex()}")
    print(f"Share this OTP with server: {otp.hex()}")