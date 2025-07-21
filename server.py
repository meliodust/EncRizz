import socket
from crypto import generate_rsa_keys, full_decrypt

HOST = '0.0.0.0'
PORT = 65432

# RSA Key Generation
public_key, private_key = generate_rsa_keys(19, 43)
print(f"[SERVER] Public Key (Send to Client): {public_key}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("[SERVER] Listening for connections...")
    conn, addr = s.accept()
    with conn:
        print(f"[SERVER] Connected by {addr}")
        data = conn.recv(4096).decode()
        if data:
            cipher_b64, encrypted_key = data.split('||')
            decrypted_text = full_decrypt(cipher_b64, encrypted_key, private_key)
            print(f"[SERVER] Decrypted Message: {decrypted_text}")
