# Import necessary cryptographic libraries
from Crypto import Random          # For generating cryptographically secure random numbers
from Crypto.PublicKey import RSA   # For RSA key generation and management
from Crypto.Cipher import PKCS1_OAEP  # For RSA encryption/decryption with OAEP padding
import base64                      # For encoding binary data to text format


# OAEP, or Optimal Asymmetric Encryption Padding, is a padding scheme used with RSA to enhance its security.
# It works by adding randomness to the plaintext before encryption, making it more resistant to certain attacks.
# This is achieved by using two hash functions (G and H) and a random "seed" to mask and transform the message in a way that adds complexity and unpredictability.

def generate_keys():
    """
    Generate RSA key pair (private and public keys)
    
    RSA is an asymmetric cryptography algorithm where:
    - Private key: Used for decryption and digital signatures (kept secret)
    - Public key: Used for encryption and signature verification (can be shared)
    
    Returns:
        tuple: (private_key, public_key) - RSA key pair
    """
    # Key length must be a multiple of 256 and >= 1024 bits for security
    # 1024 bits = 256 * 4 (commonly used, though 2048+ bits recommended for production)
    key_size = 256*4
    
    # Generate private key using cryptographically secure random number generator
    private_key = RSA.generate(key_size, Random.new().read)
    
    # Extract corresponding public key from the private key
    public_key = private_key.publickey()
    
    return private_key, public_key

def encrypt_message(plaintext_msg, public_key):
    """
    Encrypt a message using RSA public key encryption with OAEP padding
    
    PKCS1_OAEP (Optimal Asymmetric Encryption Padding) is used for security:
    - Provides semantic security (same message encrypts to different ciphertexts)
    - Protects against certain cryptographic attacks
    
    Args:
        plaintext_msg (str): The plaintext message to encrypt
        public_key: RSA public key object for encryption
        
    Returns:
        bytes: Base64 encoded encrypted message
    """
    # Create OAEP cipher object using the public key
    rsa_cipher = PKCS1_OAEP.new(public_key)
    
    # Encrypt the message (first convert string to bytes using UTF-8 encoding)
    ciphertext_bytes = rsa_cipher.encrypt(plaintext_msg.encode('utf-8'))
    
    # Encode the binary encrypted data to base64 for safe text representation
    encoded_ciphertext = base64.b64encode(ciphertext_bytes)
    
    return encoded_ciphertext

def decrypt_message(encoded_ciphertext, private_key):
    """
    Decrypt a message using RSA private key decryption with OAEP padding
    
    This function reverses the encryption process by:
    1. Decoding the base64 encoded message back to binary
    2. Using the private key to decrypt the binary data
    3. Converting the decrypted bytes back to a string
    
    Args:
        encoded_ciphertext (bytes): Base64 encoded encrypted message
        private_key: RSA private key object for decryption
        
    Returns:
        str: The original plaintext message
    """
    # Create OAEP cipher object using the private key
    rsa_cipher = PKCS1_OAEP.new(private_key)
    
    # Decode the base64 encoded message back to binary encrypted data
    ciphertext_bytes = base64.b64decode(encoded_ciphertext)
    
    # Decrypt the binary data using the private key
    plaintext_bytes = rsa_cipher.decrypt(ciphertext_bytes)
    
    # Convert decrypted bytes back to string using UTF-8 encoding
    return plaintext_bytes.decode('utf-8')

# Demo: RSA Encryption and Decryption Example
# =============================================

# Original message to be encrypted
user_message = input("Please enter the message you want to encrypt here:")

# Step 1: Generate RSA key pair (private and public keys)
# Sequence unpacking
private_key, public_key = generate_keys()

# Step 2: Encrypt the message using the public key
encrypted_data = encrypt_message(user_message, public_key)

# Step 3: Decrypt the encrypted message using the private key
decrypted_text = decrypt_message(encrypted_data, private_key)

# Display Results
# ===============

# Show the private key in PEM format and its length in bytes
print("Private Key: %s - (%d bytes)" % (private_key.exportKey().decode('utf-8'), len(private_key.exportKey())))

# Show the public key in PEM format and its length in bytes
print("Public Key: %s - (%d bytes)" % (public_key.exportKey().decode('utf-8'), len(public_key.exportKey())))

# Show the original message and its length in characters
print("Original content: %s - (%d chars)" % (user_message, len(user_message)))

# Show the encrypted message (base64 encoded) and its length in bytes
print("Encrypted message: %s - (%d bytes)" % (encrypted_data.decode('utf-8'), len(encrypted_data)))

# Show the decrypted message and its length in characters (should match original)
print("Decrypted message: %s - (%d chars)" % (decrypted_text, len(decrypted_text)))

# Verification: Check if decryption was successful
if user_message == decrypted_text:
    print("\n✅ SUCCESS: Encryption and decryption completed successfully!")
    print("Original and decrypted messages match perfectly.")
else:
    print("\n❌ ERROR: Decryption failed - messages don't match!")