import gmpy2
import hashlib
import secrets
import socket

q = gmpy2.next_prime(2**256)
g = 2

def H(data: str) -> int:
    digest = hashlib.sha256(data.encode()).hexdigest()
    return int(digest, 16) % q

def FOTP(shared_secret: int, ec: int) -> str:
    data = str(shared_secret) + str(ec)
    digest = hashlib.sha256(data.encode()).hexdigest()
    otp_int = int(digest, 16) % (10**6)
    return str(otp_int).zfill(6)

def connect_to_server(host='127.0.0.1', port=9000):
    s = socket.socket()
    s.connect((host, port))
    return s

DID = "device001"
pw = "testpassword"
kc = secrets.randbelow(q)
rc = secrets.randbelow(q)

qc = H(pw + str(rc))
Ac = pow(g, qc * kc, q)

sock = connect_to_server()
sock.send(f"REGISTER|{DID}|{Ac}\n".encode())
print(sock.recv(1024).decode().strip())

sock.send(f"CHALLENGE|{DID}\n".encode())
response = sock.recv(4096).decode().strip()
cmd, Bs_str = response.split('|')
Bs = int(Bs_str)

pw_prime = input("Enter password: ")
qc_prime = H(pw_prime + str(rc))
inv = gmpy2.invert(qc_prime * kc, q)
Cs = pow(Bs, inv, q)

ec = secrets.randbelow(q)
shared_secret = Cs
otp = FOTP(shared_secret, ec)
print(f"Generated OTP: {otp}")

sock.send(f"OTP|{DID}|{otp}|{ec}\n".encode())
print(sock.recv(1024).decode().strip())
sock.close()
