from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# AES Encryption and Decryption
def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return b64encode(nonce + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext)
    nonce = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext[16:]).decode('utf-8')
    return plaintext

# DES Encryption and Decryption
def des_encrypt(text, key):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return b64encode(nonce + ciphertext).decode('utf-8')

def des_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext)
    nonce = ciphertext[:8]
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext[8:])
    return plaintext.decode('latin-1')  # Handling binary data with latin-1

# RSA Encryption and Decryption
def rsa_encrypt(text, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(text.encode('utf-8'))
    return b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(ciphertext, private_key):
    ciphertext = b64decode(ciphertext)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

# Generate Keys
aes_key = get_random_bytes(16)  # AES key should be 16 bytes (128 bits)
des_key = get_random_bytes(8)   # DES key should be 8 bytes (64 bits)

# RSA key pair generation
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()
private_key = rsa_key

# Example Usage
text_to_encrypt = "Cybersecurity is important!"

# AES Encryption/Decryption
aes_encrypted = aes_encrypt(text_to_encrypt, aes_key)
aes_decrypted = aes_decrypt(aes_encrypted, aes_key)

# DES Encryption/Decryption
des_encrypted = des_encrypt(text_to_encrypt, des_key)
des_decrypted = des_decrypt(des_encrypted, des_key)

# RSA Encryption/Decryption
rsa_encrypted = rsa_encrypt(text_to_encrypt, public_key)
rsa_decrypted = rsa_decrypt(rsa_encrypted, private_key)

# Output the results
print(f"AES Encrypted: {aes_encrypted}")
print(f"AES Decrypted: {aes_decrypted}")
print(f"DES Encrypted: {des_encrypted}")
print(f"DES Decrypted: {des_decrypted}")
print(f"RSA Encrypted: {rsa_encrypted}")
print(f"RSA Decrypted: {rsa_decrypted}")
