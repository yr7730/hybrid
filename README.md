# hybrid
from tinyec import registry
from Crypto.Cipher import Blowfish
from phe import paillier
import hashlib

# Function to generate a random key for Blowfish encryption
def generate_blowfish_key():
    return b'Sixteen byte key'

# Function to generate a public-private key pair for lightweight ECC
def generate_ecc_keypair():
    curve = registry.get_curve('secp256r1')
    private_key = curve.field.random()
    public_key = private_key * curve.g
    return private_key, public_key

# Function to encrypt data using Blowfish encryption
def encrypt_blowfish(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.encrypt(data)

# Function to decrypt data using Blowfish encryption
def decrypt_blowfish(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.decrypt(data)

# Function to encrypt data using Paillier encryption
def encrypt_paillier(data, pubkey):
    return pubkey.encrypt(data)

# Function to decrypt data using Paillier encryption
def decrypt_paillier(data, keypair):
    return keypair.decrypt(data)

# User input
plaintext = input("Enter your message: ").encode()

# Generate keys
blowfish_key = generate_blowfish_key()
paillier_pubkey, paillier_privkey = paillier.generate_paillier_keypair()

# Encrypt data using Blowfish
encrypted_data_blowfish = encrypt_blowfish(plaintext, blowfish_key)

# Encrypt Blowfish key using Paillier
blowfish_key_str = hashlib.sha256(blowfish_key).digest()
encrypted_blowfish_key = encrypt_paillier(int.from_bytes(blowfish_key_str, 'big'), paillier_pubkey)

# Decrypt Blowfish key using Paillier
decrypted_blowfish_key = decrypt_paillier(encrypted_blowfish_key, paillier_privkey)

# Decrypt data using decrypted Blowfish key
decrypted_data_blowfish = decrypt_blowfish(encrypted_data_blowfish, decrypted_blowfish_key.to_bytes(16, 'big'))

# Output
print("Original Data:", plaintext.decode())
print("Encrypted Data (Blowfish):", encrypted_data_blowfish)
print("Decrypted Data (Blowfish):", decrypted_data_blowfish.decode())
