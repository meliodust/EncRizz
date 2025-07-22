import math
import base64
import random
import hashlib

# =========================
# ===== RSA FUNCTIONS =====
# =========================
def generate_rsa_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 11
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
# ===== HASH FUNCTION =====
# =========================
def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

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
    grid = [['' for _ in range(n_cols)] for _ in range(n_rows)]

    for i, char in enumerate(text):
        grid[i // n_cols][i % n_cols] = char

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

    full_cols = len(cipher) % n_cols
    col_lengths = [n_rows if i < full_cols else n_rows - 1 for i in range(n_cols)]

    cols, index = {}, 0
    for col in col_order:
        length = col_lengths[col]
        cols[col] = list(cipher[index:index + length])
        index += length

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
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)  # Keep spaces/punctuation as-is
    return ''.join(result)

def vigenere_decrypt(text, key="STORM"):
    result = []
    key = key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)


# =========================
# CUSTOM POLYALPHABETIC ===
# =========================
def custom_poly_encrypt(text, shifts=[3, 1, 4]):
    result = []
    shift_index = 0
    for char in text:
        if char.isalpha():
            shift = shifts[shift_index % len(shifts)]
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            shift_index += 1
        else:
            result.append(char)
    return ''.join(result)

def custom_poly_decrypt(text, shifts=[3, 1, 4]):
    result = []
    shift_index = 0
    for char in text:
        if char.isalpha():
            shift = shifts[shift_index % len(shifts)]
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            shift_index += 1
        else:
            result.append(char)
    return ''.join(result)


# =========================
# ==== VERNAM (OTP) =======
# =========================
def generate_vernam_key(length):
    return ''.join(chr(random.randint(0, 255)) for _ in range(length))

def vernam_encrypt(text, key):
    return ''.join(chr(ord(t) ^ ord(k)) for t, k in zip(text, key))

def vernam_decrypt(cipher, key):
    return vernam_encrypt(cipher, key)

# =========================
# ==== FULL ENCRYPTION (RSA MODE) ====
# =========================
def full_encrypt_rsa(plaintext, rsa_pub_key):
    # Hash for integrity
    hash_value = md5_hash(plaintext)

    stage1 = caesar_encrypt(plaintext)
    stage2 = transposition_encrypt(stage1)
    stage3 = vigenere_encrypt(stage2)
    stage4 = custom_poly_encrypt(stage3)

    vernam_key = generate_vernam_key(len(stage4))
    vernam_cipher = vernam_encrypt(stage4, vernam_key)

    vernam_ints = [rsa_encrypt(ord(k), rsa_pub_key) for k in vernam_key]
    encrypted_key = ','.join(map(str, vernam_ints))

    cipher_b64 = base64.b64encode(vernam_cipher.encode()).decode()
    return cipher_b64, encrypted_key, hash_value


def full_decrypt_rsa(cipher_b64, encrypted_key, rsa_priv_key):
    vernam_cipher = base64.b64decode(cipher_b64).decode()

    vernam_ints = list(map(int, encrypted_key.split(',')))
    vernam_key = ''.join(chr(rsa_decrypt(i, rsa_priv_key)) for i in vernam_ints)

    stage4 = vernam_decrypt(vernam_cipher, vernam_key)
    stage3 = custom_poly_decrypt(stage4)
    stage2 = vigenere_decrypt(stage3)
    stage1 = transposition_decrypt(stage2)
    plaintext = caesar_decrypt(stage1)
    return plaintext


# =========================
# ==== FULL ENCRYPTION (SYMMETRIC CHAT MODE) ====
# =========================
def full_encrypt(plaintext, symmetric_key):
    hash_value = md5_hash(plaintext)

    stage1 = caesar_encrypt(plaintext)
    stage2 = transposition_encrypt(stage1)
    stage3 = vigenere_encrypt(stage2)
    stage4 = custom_poly_encrypt(stage3)

    repeated_key = (symmetric_key * ((len(stage4) // len(symmetric_key)) + 1))[:len(stage4)]
    vernam_cipher = vernam_encrypt(stage4, repeated_key)

    cipher_b64 = base64.b64encode(vernam_cipher.encode()).decode()
    return cipher_b64, "sym", hash_value


def full_decrypt(cipher_b64, _, symmetric_key):
    vernam_cipher = base64.b64decode(cipher_b64).decode()

    repeated_key = (symmetric_key * ((len(vernam_cipher) // len(symmetric_key)) + 1))[:len(vernam_cipher)]
    stage4 = vernam_decrypt(vernam_cipher, repeated_key)
    stage3 = custom_poly_decrypt(stage4)
    stage2 = vigenere_decrypt(stage3)
    stage1 = transposition_decrypt(stage2)
    plaintext = caesar_decrypt(stage1)
    return plaintext
