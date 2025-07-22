import socket
import threading
from crypto import generate_rsa_keys, full_decrypt, full_encrypt, md5_hash

HOST = '0.0.0.0'
PORT = 65432

# RSA keys for server
public_key, private_key = generate_rsa_keys(19, 43)
print(f"[SERVER] Public Key (Send to Clients): {public_key}")

clients = []  # List of (conn, address)

def broadcast(message, sender_conn):
    """Send message to all clients except the sender."""
    for client_conn, _ in clients:
        if client_conn != sender_conn:
            try:
                # Encrypt message again before sending
                cipher_b64, encrypted_key, hash_value = full_encrypt(message, public_key)
                packet = f"{cipher_b64}||{encrypted_key}||{hash_value}"
                client_conn.sendall(packet.encode())
            except:
                client_conn.close()
                clients.remove((client_conn, _))

def handle_client(conn, addr):
    print(f"[SERVER] Connected by {addr}")
    with conn:
        while True:
            try:
                data = conn.recv(8192).decode()
                if not data:
                    print(f"[SERVER] {addr} disconnected.")
                    clients.remove((conn, addr))
                    break

                cipher_b64, encrypted_key, sender_hash = data.split('||')
                decrypted_text = full_decrypt(cipher_b64, encrypted_key, private_key)
                receiver_hash = md5_hash(decrypted_text)

                print(f"[SERVER] [{addr}] {decrypted_text}")

                if sender_hash == receiver_hash:
                    print(f"[SERVER] ✅ Integrity Check Passed")
                    # Broadcast to other clients
                    broadcast(decrypted_text, conn)
                else:
                    print(f"[SERVER] ❌ Integrity Check Failed")
            except Exception as e:
                print(f"[SERVER] Error with {addr}: {e}")
                clients.remove((conn, addr))
                break

# Main server loop
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print("[SERVER] Listening for multiple clients...")

    while True:
        conn, addr = server_socket.accept()
        clients.append((conn, addr))
        threading.Thread(target=handle_client, args=(conn, addr)).start()
