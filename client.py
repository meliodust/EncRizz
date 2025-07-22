import socket
import threading
import random
from crypto import (
    rsa_encrypt, full_encrypt, full_decrypt,
    generate_vernam_key, md5_hash
)

HOST = '100.96.251.91'  # Server IP
PORT = 65432
server_public_key = (11, 817)  # Server public key

client_name = input("Enter your name: ")

# ===== 1. Generate and send symmetric key =====
symmetric_key = generate_vernam_key(16)  # 16-byte Vernam key (adjust as needed)
symmetric_key_encrypted = ','.join(str(rsa_encrypt(ord(c), server_public_key)) for c in symmetric_key)

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(8192).decode()
            if not data:
                break
            cipher_b64, encrypted_key, sender_hash = data.split('||')
            decrypted_text = full_decrypt(cipher_b64, encrypted_key, symmetric_key)
            print(f"\n{decrypted_text}")
            print(f"[CLIENT] Received Msg Hash: {md5_hash(decrypted_text)}")
        except:
            print("[CLIENT] Disconnected from server.")
            break

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[CLIENT] Connected to server.")

    # Send symmetric key once
    s.sendall(symmetric_key_encrypted.encode())

    # Start listening thread
    threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

    while True:
        message = input("Enter message: ")
        if message.lower() == "exit":
            break

        full_message = f"{client_name}: {message}"
        cipher_b64, encrypted_key, hash_value = full_encrypt(full_message, symmetric_key)
        packet = f"{cipher_b64}||{encrypted_key}||{hash_value}"

        print(f"[CLIENT] Plaintext Hash: {hash_value}")
        s.sendall(packet.encode())
