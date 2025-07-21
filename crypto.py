import math
import base64
import random

# =========================
# ===== RSA FUNCTIONS =====
# =========================
def generate_rsa_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 11  # Chosen valid public exponent
    while math.gcd(e, phi) != 1:
        e += 2
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def rsa_encrypt(message_int, public_key):
    e, n = public_key
    return pow(message_int, e, n)

def rsa_decrypt(cipher_int, private_key):
    d, n = private_key
    return pow(cipher_int, d, n)

# =========================
# === CAESAR CIPHER (+5) ==
# =========================
def caesar_encrypt(text, shift=5):
    result = []
    for c in text:
        if c.isalpha():
            base = 'A' if c.isupper() else 'a'
            result.append(chr((ord(c) - ord(base) + shift) % 26 + ord(base)))
        else:
            result.append(c)
    return ''.join(result)

def caesar_decrypt(text, shift=5):
    return caesar_encrypt(text, -shift)

# =========================
# === TRANSPOSITION (KEY) =
# =========================
def transposition_encrypt(text, key="CIPHER"):
    n_cols = len(key)
    n_rows = (len(text) + n_cols - 1) // n_cols

    # Fill grid row-wise
    grid = [['' for _ in range(n_cols)] for _ in range(n_rows)]
    for i, char in enumerate(text):
        grid[i // n_cols][i % n_cols] = char

    # Sort columns based on alphabetical order of the key
    col_order = sorted(range(n_cols), key=lambda i: key[i])

    result = ''
    for col in col_order:
        for row in grid:
            if row[col]:
                result += row[col]
    return result


def transposition_decrypt(cipher, key="CIPHER"):
    n_cols = len(key)
    n_rows = (len(cipher) + n_cols - 1) // n_cols

    col_order = sorted(range(n_cols), key=lambda i: key[i])

    # Calculate column lengths (some columns may have fewer letters)
    total_cells = n_rows * n_cols
    full_cols = len(cipher) % n_cols
    col_lengths = [n_rows if i < full_cols else n_rows - 1 for i in range(n_cols)]

    # Fill columns in the correct order
    cols = {}
    index = 0
    for col in col_order:
        length = col_lengths[col]
        cols[col] = list(cipher[index:index + length])
        index += length

    # Reconstruct the text row-wise
    plaintext = ''
    for r in range(n_rows):
        for c in range(n_cols):
            if cols.get(c) and cols[c]:
                plaintext += cols[c].pop(0)
    return plaintext


# =========================
# ===== VIGENERE ==========
# =========================
def vigenere_encrypt(text, key="STORM"):
    result = []
    key = key.upper()
    k = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[k % len(key)]) - ord('A')
            base = 'A'
            result.append(chr((ord(c.upper()) - ord(base) + shift) % 26 + ord(base)))
            k += 1
        else:
            result.append(c)
    return ''.join(result)

def vigenere_decrypt(cipher, key="STORM"):
    result = []
    key = key.upper()
    k = 0
    for c in cipher:
        if c.isalpha():
            shift = ord(key[k % len(key)]) - ord('A')
            base = 'A'
            result.append(chr((ord(c.upper()) - ord(base) - shift) % 26 + ord(base)))
            k += 1
        else:
            result.append(c)
    return ''.join(result)

# =========================
# CUSTOM POLYALPHABETIC ===
# =========================
def custom_poly_encrypt(text, shifts=[3,1,4]):
    result = []
    for i, c in enumerate(text):
        if c.isalpha():
            shift = shifts[i % len(shifts)]
            result.append(chr((ord(c.upper()) - 65 + shift) % 26 + 65))
        else:
            result.append(c)
    return ''.join(result)

def custom_poly_decrypt(text, shifts=[3,1,4]):
    result = []
    for i, c in enumerate(text):
        if c.isalpha():
            shift = shifts[i % len(shifts)]
            result.append(chr((ord(c.upper()) - 65 - shift) % 26 + 65))
        else:
            result.append(c)
    return ''.join(result)

# =========================
# ==== VERNAM (OTP) =======
# =========================
def generate_vernam_key(length):
    return ''.join(chr(random.randint(0, 255)) for _ in range(length))

def vernam_encrypt(text, key):
    return ''.join(chr(ord(t) ^ ord(k)) for t, k in zip(text, key))

def vernam_decrypt(cipher, key):
    return vernam_encrypt(cipher, key)  # XOR is symmetric

# =========================
# ==== FULL ENCRYPTION ====
# =========================
def full_encrypt(plaintext, rsa_pub_key):
    # Step 1-5 (Layered Ciphers)
    stage1 = caesar_encrypt(plaintext)
    stage2 = transposition_encrypt(stage1)
    stage3 = vigenere_encrypt(stage2)
    stage4 = custom_poly_encrypt(stage3)

    # Step 6 (Vernam)
    vernam_key = generate_vernam_key(len(stage4))
    vernam_cipher = vernam_encrypt(stage4, vernam_key)

    # Encrypt Vernam key with RSA
    vernam_ints = [rsa_encrypt(ord(k), rsa_pub_key) for k in vernam_key]
    encrypted_key = ','.join(map(str, vernam_ints))

    # Base64 encode cipher text for safe transmission
    cipher_b64 = base64.b64encode(vernam_cipher.encode()).decode()
    return cipher_b64, encrypted_key

def full_decrypt(cipher_b64, encrypted_key, rsa_priv_key):
    # Decode Base64
    vernam_cipher = base64.b64decode(cipher_b64).decode()

    # Decrypt Vernam key
    vernam_ints = list(map(int, encrypted_key.split(',')))
    vernam_key = ''.join(chr(rsa_decrypt(i, rsa_priv_key)) for i in vernam_ints)

    # Step 6 (Vernam)
    stage4 = vernam_decrypt(vernam_cipher, vernam_key)

    # Reverse previous steps (5 to 1)
    stage3 = custom_poly_decrypt(stage4)
    stage2 = vigenere_decrypt(stage3)
    stage1 = transposition_decrypt(stage2)
    plaintext = caesar_decrypt(stage1)

    return plaintext
