import socket
import threading
from crypto import generate_rsa_keys, full_decrypt, md5_hash

HOST = '0.0.0.0'
PORT = 65432

# Generate server's RSA key pair
public_key, private_key = generate_rsa_keys(19, 43)
print(f"[SERVER] Public Key (Send to Client): {public_key}")

def handle_client(conn, addr):
    print(f"[SERVER] Connected by {addr}")
    with conn:
        while True:
            try:
                data = conn.recv(8192).decode()
                if not data:
                    print(f"[SERVER] {addr} disconnected.")
                    break

                cipher_b64, encrypted_key, sender_hash = data.split('||')
                decrypted_text = full_decrypt(cipher_b64, encrypted_key, private_key)
                receiver_hash = md5_hash(decrypted_text)

                print(f"[SERVER] [{addr}] Decrypted Message: {decrypted_text}")
                print(f"[SERVER] [{addr}] Hash Value: {receiver_hash}")

                if sender_hash == receiver_hash:
                    print(f"[SERVER] [{addr}] ✅ Integrity Check Passed")
                else:
                    print(f"[SERVER] [{addr}] ❌ Integrity Check Failed")
            except Exception as e:
                print(f"[SERVER] Error with {addr}: {e}")
                break

# Main listening loop
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print("[SERVER] Listening for multiple client connections...")

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()
