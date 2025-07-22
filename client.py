import socket
from crypto import full_encrypt

HOST = '100.96.251.91'  # Tailscale IP of server
PORT = 65432
server_public_key = (11, 817)  # Match what the server prints

# Ask for client name
client_name = input("Enter your name: ")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[CLIENT] Connected to server at {HOST}:{PORT}")

    while True:
        message = input("Enter message (type 'exit' to quit): ")
        if message.lower() == "exit":
            print("[CLIENT] Exiting chat...")
            break

        # Add name to message
        full_message = f"{client_name}: {message}"

        # Encrypt the message
        cipher_b64, encrypted_key, hash_value = full_encrypt(full_message, server_public_key)
        packet = f"{cipher_b64}||{encrypted_key}||{hash_value}"

        # Send encrypted data
        s.sendall(packet.encode())
        print(f"[CLIENT] Sent: {full_message}")
