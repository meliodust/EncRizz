import socket, pickle
from crypto import encrypt_pipeline, generate_rsa_keys

HOST = '127.0.0.1'
PORT = 65432

# The server prints its public key; enter it here after you start the server.
server_public_key = (7, 817)  # Replace if server gives you different one

while True:
    msg = input("Enter message to send: ").upper()
    # Random Vernam key, but here we simplify by making it same length as msg:
    vernam_key = "XMCKLQWERTYUIOPASD"[:len(msg)]
    cipher_b64, rsa_enc_key = encrypt_pipeline(msg, vernam_key, server_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(pickle.dumps((cipher_b64, rsa_enc_key)))
    print(f"[CLIENT] Sent Encrypted Ciphertext: {cipher_b64}")
