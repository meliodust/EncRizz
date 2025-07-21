import socket
from crypto import full_encrypt

HOST = '100.xxx.xxx.xxx'  # Tailscale IP of server
PORT = 65432
server_public_key = (11, 817)  # Use the one printed by server.py

message = input("Enter message to send: ")
cipher_b64, encrypted_key = full_encrypt(message, server_public_key)
packet = f"{cipher_b64}||{encrypted_key}"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(packet.encode())
    print(f"[CLIENT] Sent Encrypted Ciphertext: {cipher_b64}")
