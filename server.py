import socket
import threading
from crypto import (
    generate_rsa_keys, rsa_decrypt, full_decrypt, full_encrypt,
    md5_hash
)

HOST = '0.0.0.0'
PORT = 65432

public_key, private_key = generate_rsa_keys(19, 43)
print(f"[SERVER] Public Key (Send to Clients): {public_key}")

clients = []  # [(conn, addr, symmetric_key), ...]

def broadcast(message, sender_conn):
    """Encrypt and send message to all clients except the sender."""
    for client_conn, _, sym_key in clients:
        if client_conn != sender_conn:
            try:
                cipher_b64, encrypted_key, hash_value = full_encrypt(message, sym_key)
                packet = f"{cipher_b64}||{encrypted_key}||{hash_value}"
                client_conn.sendall(packet.encode())
            except:
                client_conn.close()
                clients[:] = [c for c in clients if c[0] != client_conn]

def handle_client(conn, addr):
    print(f"[SERVER] Connected by {addr}")

    # ===== 1. Receive symmetric key =====
    sym_key_encrypted = conn.recv(4096).decode()
    sym_key_ints = list(map(int, sym_key_encrypted.split(',')))
    sym_key = ''.join(chr(rsa_decrypt(i, private_key)) for i in sym_key_ints)
    print(f"[SERVER] Received symmetric key from {addr}")

    # Save this client
    clients.append((conn, addr, sym_key))

    with conn:
        while True:
            try:
                data = conn.recv(8192).decode()
                if not data:
                    print(f"[SERVER] {addr} disconnected.")
                    clients[:] = [c for c in clients if c[0] != conn]
                    break

                cipher_b64, encrypted_key, sender_hash = data.split('||')
                decrypted_text = full_decrypt(cipher_b64, encrypted_key, sym_key)
                receiver_hash = md5_hash(decrypted_text)

                print(f"[SERVER] [{addr}] Decrypted Message: {decrypted_text}")
                print(f"[SERVER] [{addr}] Hash Value: {receiver_hash}")

                if sender_hash == receiver_hash:
                    print(f"[SERVER] ✅ Integrity Check Passed")
                    broadcast(decrypted_text, conn)
                else:
                    print(f"[SERVER] ❌ Integrity Check Failed")
            except Exception as e:
                print(f"[SERVER] Error with {addr}: {e}")
                clients[:] = [c for c in clients if c[0] != conn]
                break

# ===== Main loop =====
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print("[SERVER] Listening for multiple clients...")

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()
