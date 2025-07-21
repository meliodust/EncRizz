import base64

# ========== RSA Functions ==========
def generate_rsa_keys(p, q, e=7):
    n = p * q
    phi = (p - 1) * (q - 1)
    # Compute modular inverse for d
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def rsa_encrypt_char(c, public_key):
    e, n = public_key
    return pow(ord(c), e, n)

def rsa_decrypt_char(val, private_key):
    d, n = private_key
    return chr(pow(val, d, n))

def rsa_encrypt_key(key, public_key):
    return [rsa_encrypt_char(c, public_key) for c in key]

def rsa_decrypt_key(enc_key, private_key):
    return ''.join(rsa_decrypt_char(c, private_key) for c in enc_key)

# ========== Caesar Cipher (Monoalphabetic) ==========
def caesar_encrypt(text, shift=5):
    res = ""
    for c in text.upper():
        if c.isalpha():
            res += chr(((ord(c)-65 + shift) % 26) + 65)
        else:
            res += c
    return res

def caesar_decrypt(text, shift=5):
    return caesar_encrypt(text, -shift)

# ========== Columnar Transposition ==========
def transposition_encrypt(text, key):
    key_order = sorted(list(key))
    col_order = [key_order.index(k)+1 for k in key]
    cols = len(key)
    rows = (len(text) + cols - 1) // cols
    text += "X" * (rows*cols - len(text))
    grid = [list(text[i*cols:(i+1)*cols]) for i in range(rows)]
    result = ""
    for i in sorted(range(cols), key=lambda x: key[x]):
        result += ''.join(row[i] for row in grid)
    return result

def transposition_decrypt(text, key):
    cols = len(key)
    rows = (len(text) + cols - 1) // cols
    key_order = sorted(list(key))
    sorted_idx = sorted(range(cols), key=lambda x: key[x])
    # reconstruct columns
    chunk = [len(text)//cols for _ in range(cols)]
    arr = [list(text[sum(chunk[:i]):sum(chunk[:i+1])]) for i in range(cols)]
    result = ""
    for r in range(rows):
        for c in sorted_idx:
            if arr[c]:
                result += arr[c].pop(0)
    return result.rstrip("X")

# ========== Vigenere ==========
def vigenere_encrypt(text, key):
    key = key.upper()
    result = ""
    for i, c in enumerate(text):
        if c.isalpha():
            shift = (ord(key[i % len(key)]) - 65)
            result += chr(((ord(c) - 65 + shift) % 26) + 65)
        else:
            result += c
    return result

def vigenere_decrypt(text, key):
    key = key.upper()
    result = ""
    for i, c in enumerate(text):
        if c.isalpha():
            shift = (ord(key[i % len(key)]) - 65)
            result += chr(((ord(c) - 65 - shift) % 26) + 65)
        else:
            result += c
    return result

# ========== Custom Polyalphabetic (+3, +1, +4 repeating) ==========
def custom_poly_encrypt(text, pattern=[3,1,4]):
    res = ""
    for i, c in enumerate(text):
        if c.isalpha():
            shift = pattern[i % len(pattern)]
            res += chr(((ord(c)-65 + shift) % 26) + 65)
        else:
            res += c
    return res

def custom_poly_decrypt(text, pattern=[3,1,4]):
    inv_pattern = [-x for x in pattern]
    return custom_poly_encrypt(text, inv_pattern)

# ========== Vernam (One-Time Pad) ==========
def vernam_encrypt(text, key):
    xor_bytes = bytes([ord(a) ^ ord(b) for a, b in zip(text, key)])
    return base64.b64encode(xor_bytes).decode()

def vernam_decrypt(cipher_b64, key):
    cipher_bytes = base64.b64decode(cipher_b64)
    return ''.join(chr(b ^ ord(k)) for b, k in zip(cipher_bytes, key))

# ========== Full Encryption Pipeline ==========
def encrypt_pipeline(plaintext, vernam_key, rsa_public):
    step1 = caesar_encrypt(plaintext)
    step2 = transposition_encrypt(step1, "CIPHER")
    step3 = vigenere_encrypt(step2, "STORM")
    step4 = custom_poly_encrypt(step3)
    step5 = vernam_encrypt(step4, vernam_key)
    rsa_enc_key = rsa_encrypt_key(vernam_key, rsa_public)
    return step5, rsa_enc_key

def decrypt_pipeline(cipher_b64, rsa_enc_key, rsa_private):
    vernam_key = rsa_decrypt_key(rsa_enc_key, rsa_private)
    step4 = vernam_decrypt(cipher_b64, vernam_key)
    step3 = custom_poly_decrypt(step4)
    step2 = vigenere_decrypt(step3, "STORM")
    step1 = transposition_decrypt(step2, "CIPHER")
    plain = caesar_decrypt(step1)
    return plain
