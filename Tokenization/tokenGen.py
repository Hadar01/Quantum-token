import secrets, hashlib, binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generate_random_decimal(digits: int = 20) -> int:
    # 10^digits is upper bound, secrets.randbelow gives secure random below that
    return secrets.randbelow(10**digits)


def generate_secure_token(random_number: int, token_size: int) -> str:
    # Step 1: Generate secure random bytes
    random_bytes = secrets.token_bytes(token_size)
    
    # Step 2: Convert random_number to bytes dynamically
    # Calculate minimum number of bytes needed to store the number
    byte_length = (random_number.bit_length() + 7) // 8 or 1
    number_bytes = random_number.to_bytes(byte_length, byteorder='big')
    
    # Step 3: Combine bytes
    token_material = number_bytes + random_bytes
    
    # Step 4: Hash with SHA-256
    hash_digest = hashlib.sha256(token_material).digest()
    hash_hex = binascii.hexlify(hash_digest).decode('utf-8')
    
    # Step 5: Take the first token_size characters as the token
    token_plaintext = hash_hex[:token_size]
    
    # Step 6: RSA encryption
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        token_plaintext.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    
    encrypted_token_hex = binascii.hexlify(ciphertext).decode('utf-8')
    return encrypted_token_hex

# Example usage:
x=generate_random_decimal(16)
print(generate_random_decimal(16))
secure_token = generate_secure_token(x, token_size=1)
print("Encrypted token:", secure_token)
