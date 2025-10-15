# tokenGen.py
import secrets, hashlib, binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_random_decimal(digits: int = 20) -> int:
    return secrets.randbelow(10**digits)

def generate_secure_token(random_number: int, token_size: int) -> str:
    random_bytes = secrets.token_bytes(token_size)
    byte_length = (random_number.bit_length() + 7) // 8 or 1
    number_bytes = random_number.to_bytes(byte_length, byteorder='big')
    token_material = number_bytes + random_bytes
    hash_digest = hashlib.sha256(token_material).digest()
    hash_hex = binascii.hexlify(hash_digest).decode('utf-8')
    token_plaintext = hash_hex[:token_size]

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        token_plaintext.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return binascii.hexlify(ciphertext).decode('utf-8')

if __name__ == "__main__":
    x = generate_random_decimal(16)
    print("Random number:", x)
    print("Encrypted token:", generate_secure_token(x, token_size=16))
