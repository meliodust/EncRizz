import socket
import threading
from crypto import full_encrypt, full_decrypt

HOST = '100.96.251.91'  # Replace with your server IP
PORT = 65432
server_public_key = (11, 817)  # Replace with server's printed public key

client_name = input("Enter your name: ")

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(8192).decode()
            if not data:
                break

            cipher_b64, encrypted_key, sender_hash = data.split('||')
            decrypted_text = full_decrypt(cipher_b64, encrypted_key, (43, 817))  # ❗ You need server's private key?
            print(f"\n{decrypted_text}")
        except:
            print("[CLIENT] Disconnected from server.")
            break

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[CLIENT] Connected to server.")

    # Start listening thread
    threading.Thread(target=receive_messages, args=(s,), daemon=True).start()

    while True:
        message = input()
        if message.lower() == "exit":
            break

        full_message = f"{client_name}: {message}"
        cipher_b64, encrypted_key, hash_value = full_encrypt(full_message, server_public_key)
        packet = f"{cipher_b64}||{encrypted_key}||{hash_value}"
        s.sendall(packet.encode())
