# Import necessary cryptographic libraries
from Crypto import Random          # For generating cryptographically secure random numbers
from Crypto.PublicKey import RSA   # For RSA key generation and management
from Crypto.Cipher import PKCS1_OAEP  # For RSA encryption/decryption with OAEP padding
import base64                      # For encoding binary data to text format

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
    modulus_length = 256*4
    
    # Generate private key using cryptographically secure random number generator
    privatekey = RSA.generate(modulus_length, Random.new().read)
    
    # Extract corresponding public key from the private key
    publickey = privatekey.publickey()
    
    return privatekey, publickey

def encrypt_message(a_message, publickey):
    """
    Encrypt a message using RSA public key encryption with OAEP padding
    
    PKCS1_OAEP (Optimal Asymmetric Encryption Padding) is used for security:
    - Provides semantic security (same message encrypts to different ciphertexts)
    - Protects against certain cryptographic attacks
    
    Args:
        a_message (str): The plaintext message to encrypt
        publickey: RSA public key object for encryption
        
    Returns:
        bytes: Base64 encoded encrypted message
    """
    # Create OAEP cipher object using the public key
    cipher = PKCS1_OAEP.new(publickey)
    
    # Encrypt the message (first convert string to bytes using UTF-8 encoding)
    encrypted_msg = cipher.encrypt(a_message.encode('utf-8'))
    
    # Encode the binary encrypted data to base64 for safe text representation
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    
    return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, privatekey):
    """
    Decrypt a message using RSA private key decryption with OAEP padding
    
    This function reverses the encryption process by:
    1. Decoding the base64 encoded message back to binary
    2. Using the private key to decrypt the binary data
    3. Converting the decrypted bytes back to a string
    
    Args:
        encoded_encrypted_msg (bytes): Base64 encoded encrypted message
        privatekey: RSA private key object for decryption
        
    Returns:
        str: The original plaintext message
    """
    # Create OAEP cipher object using the private key
    cipher = PKCS1_OAEP.new(privatekey)
    
    # Decode the base64 encoded message back to binary encrypted data
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    
    # Decrypt the binary data using the private key
    decoded_decrypted_msg = cipher.decrypt(decoded_encrypted_msg)
    
    # Convert decrypted bytes back to string using UTF-8 encoding
    return decoded_decrypted_msg.decode('utf-8')

# Demo: RSA Encryption and Decryption Example
# =============================================

# Original message to be encrypted
a_message = "This is the illustration of RSA algorithm of asymmetric cryptography"

# Step 1: Generate RSA key pair (private and public keys)
privatekey, publickey = generate_keys()

# Step 2: Encrypt the message using the public key
encrypted_msg = encrypt_message(a_message, publickey)

# Step 3: Decrypt the encrypted message using the private key
decrypted_msg = decrypt_message(encrypted_msg, privatekey)

# Display Results
# ===============

# Show the private key in PEM format and its length in bytes
print("Private Key: %s - (%d bytes)" % (privatekey.exportKey().decode('utf-8'), len(privatekey.exportKey())))

# Show the public key in PEM format and its length in bytes
print("Public Key: %s - (%d bytes)" % (publickey.exportKey().decode('utf-8'), len(publickey.exportKey())))

# Show the original message and its length in characters
print("Original content: %s - (%d chars)" % (a_message, len(a_message)))

# Show the encrypted message (base64 encoded) and its length in bytes
print("Encrypted message: %s - (%d bytes)" % (encrypted_msg.decode('utf-8'), len(encrypted_msg)))

# Show the decrypted message and its length in characters (should match original)
print("Decrypted message: %s - (%d chars)" % (decrypted_msg, len(decrypted_msg)))

# Verification: Check if decryption was successful
if a_message == decrypted_msg:
    print("\n✅ SUCCESS: Encryption and decryption completed successfully!")
    print("Original and decrypted messages match perfectly.")
else:
    print("\n❌ ERROR: Decryption failed - messages don't match!")