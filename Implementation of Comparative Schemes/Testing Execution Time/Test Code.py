import time
import random
from gmpy2 import mpz, powm, next_prime, randrange, mul_mod, invert
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import List, Tuple


# -------------------------- 1. Initialize Protocol Parameters --------------------------
def setup_cyclic_group() -> Tuple[mpz, mpz]:
    """
    Generate cyclic group G (prime order q, generator g) as in HP-OTP Setup phase.
    q: 1024-bit prime (consistent with server/device group parameters)
    g: Generator of group G (set to 2, verified as a primitive root)
    """
    q = next_prime(mpz(2) ** 1023)  # 1024-bit prime order
    g = mpz(2)                      # Generator of group G
    return q, g

# Global group parameters (shared by server and device)
Q, G = setup_cyclic_group()
ITERATIONS = 1000  # Number of iterations (consistent with Section 6.1)


# -------------------------- 2. Helper Class for Merkle Tree --------------------------
class MerkleTree:
    """
    Simulate Merkle Tree generation (used in GTOTP).
    Calculates time for building a tree with random leaf nodes.
    """
    def __init__(self, leaf_count: int = 100):
        self.leaf_count = leaf_count  # Number of leaf nodes (simulate real-world scale)
        self.leaves: List[bytes] = []
        self._init_leaves()

    def _init_leaves(self) -> None:
        """Generate random leaf nodes (16 bytes each)"""
        for _ in range(self.leaf_count):
            self.leaves.append(get_random_bytes(16))

    def _hash_node(self, data: bytes) -> bytes:
        """Hash function for Merkle Tree nodes (SHA256, consistent with HP-OTP)"""
        sha256 = SHA256.new()
        sha256.update(data)
        return sha256.digest()

    def build_tree(self) -> bytes:
        """Build Merkle Tree and return root hash (measure this operation time)"""
        nodes = self.leaves.copy()

        # Iteratively hash node pairs until root is obtained
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left  # Handle odd count
                combined = left + right
                next_level.append(self._hash_node(combined))
            nodes = next_level

        return nodes[0]  # Return root hash


# -------------------------- 3. Basic Operation Functions --------------------------
def hash_zq(data: bytes) -> mpz:
    """
    Hash operation: {0,1}* → Z_q (Hash (Zq)).
    Uses SHA256, then maps result to Z_q via modulo Q.
    """
    sha256 = SHA256.new()
    sha256.update(data)
    return mpz(sha256.hexdigest(), 16) % Q


def mul_zq(a: mpz, b: mpz) -> mpz:
    """
    Multiplication in Z_q (MUL (Zq)).
    Uses gmpy2.mul_mod for efficient modular multiplication.
    """
    return mul_mod(a, b, Q)


def inv_g(a: mpz) -> mpz:
    """
    Inversion in group G (INV(G)).
    Computes the modular inverse of 'a' modulo Q (a ∈ G).
    """
    return invert(a, Q)


def exp_g(base: mpz, exponent: mpz) -> mpz:
    """
    Exponentiation in group G (EXP (G)).
    Uses gmpy2.powm for efficient modular exponentiation (base^exponent mod Q).
    """
    return powm(base, exponent, Q)


def forp(ec: mpz, cs: mpz) -> str:
    """
    OTP generation function (ForP()).
    Follows HP-OTP's F_OTP logic: hash(ec || cs) + truncation to 6-digit OTP.
    """
    # Concatenate ec and cs as hex strings (avoid large-integer overflow)
    input_data = f"{ec:x}_{cs:x}".encode("utf-8")
    # Hash and truncate to 6-digit OTP
    hash_int = hash_zq(input_data)
    return str(hash_int % 1000000).zfill(6)


def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Symmetric encryption (Enc()).
    Uses AES-128-CBC (consistent with pycrypto's common practice in Section 6.1).
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad plaintext to multiple of AES block size (16 bytes)
    pad_length = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_length]) * pad_length
    return cipher.encrypt(plaintext_padded)


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Symmetric decryption (Dec()).
    Uses AES-128-CBC (reverse of aes_encrypt).
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext)
    # Remove padding
    pad_length = plaintext_padded[-1]
    return plaintext_padded[:-pad_length]


# -------------------------- 4. Time Testing Logic --------------------------
def test_operation_time(operation, *args, iterations: int = ITERATIONS) -> float:
    """
    Test average execution time of a single operation.
    :param operation: Target function to test
    :param args: Fixed arguments for the operation (if any)
    :param iterations: Number of test iterations
    :return: Average time in microseconds (μs)
    """
    total_time = 0.0

    # Skip the first iteration to avoid initialization overhead (optional but more accurate)
    if iterations > 0:
        operation(*args)

    # Run main iterations and record time
    for _ in range(iterations):
        start_time = time.perf_counter()  # High-precision timer
        operation(*args)
        end_time = time.perf_counter()
        total_time += (end_time - start_time)

    # Calculate average time (convert seconds to microseconds: 1s = 1e6 μs)
    avg_time_us = (total_time / iterations) * 1e6
    return round(avg_time_us, 2)


def test_all_operations() -> Tuple[dict, dict]:

    # -------------------------- Prepare Test Data (Random & Representative) --------------------------
    # Random data for Hash (Zq)
    random_data = get_random_bytes(32)  # 32-byte random data
    # Random values for MUL (Zq), INV(G), EXP (G)
    a_zq = randrange(Q)
    b_zq = randrange(Q)
    g_element = randrange(G, Q)  # Element in group G
    exp = randrange(Q)           # Exponent for EXP (G)
    # Random data for ForP()
    ec = randrange(Q)
    cs = randrange(Q)
    # AES key (128-bit) and IV (16-byte) for Enc()/Dec()
    aes_key = get_random_bytes(16)
    aes_iv = get_random_bytes(16)
    aes_plaintext = get_random_bytes(128)  # 128-byte plaintext
    # Merkle Tree instance (100 leaves)
    merkle_tree = MerkleTree(leaf_count=100)

    # -------------------------- Testing --------------------------
    server_times = {}
    print("=== Starting Server-Side Operation Time Test ===")
    
    # Hash (Zq)
    server_times["Hash (Zq)"] = test_operation_time(hash_zq, random_data)
    # MUL (Zq)
    server_times["MUL (Zq)"] = test_operation_time(mul_zq, a_zq, b_zq)
    # INV(G)
    server_times["INV(G)"] = test_operation_time(inv_g, g_element)
    # EXP (G)
    server_times["EXP (G)"] = test_operation_time(exp_g, g_element, exp)
    # ForP()
    server_times["ForP()"] = test_operation_time(forp, ec, cs)
    # Enc() (precompute ciphertext to avoid reusing plaintext)
    ciphertext = aes_encrypt(aes_plaintext, aes_key, aes_iv)
    server_times["Enc()"] = test_operation_time(aes_encrypt, aes_plaintext, aes_key, aes_iv)
    # Dec()
    server_times["Dec()"] = test_operation_time(aes_decrypt, ciphertext, aes_key, aes_iv)
    # Mtree* (Merkle Tree generation)
    server_times["Mtree*"] = test_operation_time(merkle_tree.build_tree)



    return server_times


# -------------------------- 5. Run Test and Print Results --------------------------
def print_results(server_times: dict, device_times: dict) -> None:
    """Print test results in a format """
    print("\n==================== Execution Time of Basic Operations ====================")
    print(f"{'Operation':<12} {'Server Time (μs)':<18}")
    print("-" * 55)
    
    operations_order = ["Hash (Zq)", "MUL (Zq)", "INV(G)", "EXP (G)", "ForP()", "Enc()", "Dec()", "Mtree*"]
    for op in operations_order:
        server_t = server_times.get(op, "N/A")

        print(f"{op:<12} {server_t:<18}")
    



if __name__ == "__main__":
    # Run all tests and print results
    server_times = test_all_operations()
    print_results(server_times)