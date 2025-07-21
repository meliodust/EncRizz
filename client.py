import socket
from crypto import full_encrypt

HOST = '100.119.56.57'  # Tailscale IP of server
PORT = 65432
server_public_key = (11, 817)  # Match what the server prints

message = input("Enter message to send: ")
cipher_b64, encrypted_key, hash_value = full_encrypt(message, server_public_key)
packet = f"{cipher_b64}||{encrypted_key}||{hash_value}"

print(f"[CLIENT] Hash Value of Plain Text: {hash_value}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(packet.encode())
    print(f"[CLIENT] Sent Encrypted Ciphertext: {cipher_b64}")
