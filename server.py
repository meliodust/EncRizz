import socket, pickle
from crypto import generate_rsa_keys, decrypt_pipeline

HOST = '127.0.0.1'
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
        while True:
            data = conn.recv(4096)
            if not data:
                break
            cipher_b64, rsa_enc_key = pickle.loads(data)
            plaintext = decrypt_pipeline(cipher_b64, rsa_enc_key, private_key)
            print(f"[SERVER] Decrypted Message: {plaintext}")
