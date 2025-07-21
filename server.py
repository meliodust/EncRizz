import socket
from crypto import generate_rsa_keys, full_decrypt, md5_hash

HOST = '0.0.0.0'
PORT = 65432

public_key, private_key = generate_rsa_keys(19, 43)
print(f"[SERVER] Public Key (Send to Client): {public_key}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("[SERVER] Listening for connections...")
    conn, addr = s.accept()
    with conn:
        print(f"[SERVER] Connected by {addr}")
        data = conn.recv(8192).decode()
        if data:
            cipher_b64, encrypted_key, sender_hash = data.split('||')
            decrypted_text = full_decrypt(cipher_b64, encrypted_key, private_key)
            receiver_hash = md5_hash(decrypted_text)
            print(f"[SERVER] Decrypted Message: {decrypted_text}")
            print(f"[SERVER] Hash Value of Decrypted Text: {receiver_hash}")
            if sender_hash == receiver_hash:
                print("[SERVER] ✅ Integrity Check Passed")
            else:
                print("[SERVER] ❌ Integrity Check Failed")
