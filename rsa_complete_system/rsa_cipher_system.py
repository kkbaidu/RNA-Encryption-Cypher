# Import required cryptographic libraries for RSA operations
from Crypto.PublicKey import RSA           # For RSA key generation and management
from Crypto.Cipher import PKCS1_OAEP       # For RSA encryption/decryption with OAEP padding
from Crypto.Signature import PKCS1_v1_5    # For RSA digital signatures
from Crypto.Hash import SHA512, SHA384, SHA256, SHA1, MD5  # Hash algorithms for signatures
from Crypto import Random                   # Cryptographically secure random number generation
from base64 import b64encode, b64decode     # Base64 encoding for binary data representation

# Global variable to store the current hash algorithm being used
current_hash_algorithm = "SHA-256"


def generate_rsa_keypair(key_bit_size):
    """
    Generate a new RSA key pair (public and private keys)
    
    Args:
        key_bit_size (int): Size of the RSA key in bits (e.g., 1024, 2048, 4096)
        
    Returns:
        tuple: (public_key, private_key) - RSA key pair objects
    """
    # Create a cryptographically secure random number generator
    secure_random = Random.new().read
    
    # Generate the RSA key pair using the specified bit size and random generator
    rsa_key = RSA.generate(key_bit_size, secure_random)
    
    # Extract the private key (contains both public and private components)
    private_key = rsa_key
    
    # Extract the public key from the private key
    public_key = rsa_key.publickey()
    
    return public_key, private_key

def import_external_key(external_key_data):
    """
    Import an RSA key from external data (PEM format, bytes, etc.)
    
    Args:
        external_key_data: Key data in various formats (PEM string, bytes, etc.)
        
    Returns:
        RSA key object that can be used for cryptographic operations
    """
    return RSA.importKey(external_key_data)

def extract_public_key(private_key_obj):
    """
    Extract the public key from a private key object
    
    Args:
        private_key_obj: RSA private key object
        
    Returns:
        RSA public key object derived from the private key
    """
    return private_key_obj.publickey()

def encrypt_message(plaintext_data, public_key_obj):
    """
    Encrypt a message using RSA public key encryption with OAEP padding
    
    OAEP (Optimal Asymmetric Encryption Padding) provides:
    - Enhanced security against various cryptographic attacks
    - Semantic security (same message produces different ciphertexts)
    
    Args:
        plaintext_data (bytes): The message to encrypt (must be bytes)
        public_key_obj: RSA public key object for encryption
        
    Returns:
        bytes: Encrypted message as bytes
    """
    # Create an OAEP cipher object using the public key
    oaep_cipher = PKCS1_OAEP.new(public_key_obj)
    
    # Encrypt the message and return the ciphertext
    return oaep_cipher.encrypt(plaintext_data)

def decrypt_message(ciphertext_data, private_key_obj):
    """
    Decrypt a message using RSA private key decryption with OAEP padding
    
    Args:
        ciphertext_data (bytes): The encrypted message to decrypt
        private_key_obj: RSA private key object for decryption
        
    Returns:
        bytes: Decrypted plaintext message as bytes
    """
    # Create an OAEP cipher object using the private key
    oaep_cipher = PKCS1_OAEP.new(private_key_obj)
    
    # Decrypt the ciphertext and return the original message
    return oaep_cipher.decrypt(ciphertext_data)

# Digital Signature Functions
def create_digital_signature(message_data, private_key_obj, hash_algorithm="SHA-256"):
    """
    Create a digital signature for a message using RSA private key
    
    Digital signatures provide:
    - Authentication: Proves the message came from the private key holder
    - Integrity: Ensures the message hasn't been tampered with
    - Non-repudiation: Prevents denial of sending the message
    
    Args:
        message_data (bytes): The message to sign
        private_key_obj: RSA private key object for signing
        hash_algorithm (str): Hash algorithm to use ("SHA-256", "SHA-512", etc.)
        
    Returns:
        bytes: Digital signature for the message
    """
    # Update global hash algorithm variable
    global current_hash_algorithm
    current_hash_algorithm = hash_algorithm
    
    # Create a digital signature object using the private key
    signature_obj = PKCS1_v1_5.new(private_key_obj)
    
    # Select and create the appropriate hash object based on the algorithm
    if (current_hash_algorithm == "SHA-512"):
        hash_obj = SHA512.new()
    elif (current_hash_algorithm == "SHA-384"):
        hash_obj = SHA384.new()
    elif (current_hash_algorithm == "SHA-256"):
        hash_obj = SHA256.new()
    elif (current_hash_algorithm == "SHA-1"):
        hash_obj = SHA1.new()
    else:
        # Default to MD5 if no recognized algorithm is specified
        hash_obj = MD5.new()
    
    # Hash the message data
    hash_obj.update(message_data)
    
    # Create and return the digital signature
    return signature_obj.sign(hash_obj)

# Digital Signature Verification
def verify_digital_signature(message_data, signature_data, public_key_obj):
    """
    Verify a digital signature using RSA public key
    
    This function checks if:
    - The signature was created by the corresponding private key
    - The message data hasn't been tampered with since signing
    
    Args:
        message_data (bytes): The original message that was signed
        signature_data (bytes): The digital signature to verify
        public_key_obj: RSA public key object for verification
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Create a signature verification object using the public key
    verifier_obj = PKCS1_v1_5.new(public_key_obj)
    
    # Select the same hash algorithm used for signing
    if (current_hash_algorithm == "SHA-512"):
        hash_obj = SHA512.new()
    elif (current_hash_algorithm == "SHA-384"):
        hash_obj = SHA384.new()
    elif (current_hash_algorithm == "SHA-256"):
        hash_obj = SHA256.new()
    elif (current_hash_algorithm == "SHA-1"):
        hash_obj = SHA1.new()
    else:
        hash_obj = MD5.new()
    
    # Hash the message data
    hash_obj.update(message_data)
    
    # Verify the signature and return the result
    return verifier_obj.verify(hash_obj, signature_data)


# Interactive Test Function
def run_rsa_demonstration():
    """
    Interactive demonstration of RSA encryption, decryption, and digital signatures
    This function provides a complete test of all RSA functionality with user input
    """
    print("=== RSA Cryptographic System Demonstration ===")
    
    # 1. RSA Key Pair Generation
    print("\n1. Generating RSA key pair...")
    print("Available key sizes: 1024, 2048, 3072, 4096 bits")
    print("Note: Larger keys are more secure but slower to generate and use")
    
    # Get user input for key size with validation
    while True:
        try:
            key_bit_size = int(input("Enter key size in bits (recommended: 2048): ") or "2048")
            if key_bit_size in [1024, 2048, 3072, 4096]:
                break
            else:
                print("Please choose from: 1024, 2048, 3072, 4096")
        except ValueError:
            print("Please enter a valid number")
    
    print(f"Generating {key_bit_size}-bit RSA key pair...")
    public_key, private_key = generate_rsa_keypair(key_bit_size)
    print("✓ Keys generated successfully")
    
    # 2. Message Encryption and Decryption Test
    print("\n2. Testing message encryption and decryption...")
    user_input_message = input("Enter a message to encrypt: ")
    original_message_bytes = user_input_message.encode('utf-8')
    print(f"Original message: {original_message_bytes.decode()}")
    
    # Encrypt the user's message
    encrypted_message = encrypt_message(original_message_bytes, public_key)
    print(f"✓ Message encrypted (ciphertext length: {len(encrypted_message)} bytes)")
    
    # Decrypt the encrypted message
    decrypted_message = decrypt_message(encrypted_message, private_key)
    print(f"Decrypted message: {decrypted_message.decode()}")
    print(f"✓ Encryption/Decryption {'SUCCESS' if original_message_bytes == decrypted_message else 'FAILED'}")
    
    # 3. Digital Signature Creation and Verification Test
    print("\n3. Testing digital signature creation and verification...")
    signature_input_message = input("Enter a message to sign: ")
    message_to_sign_bytes = signature_input_message.encode('utf-8')
    print(f"Message to sign: {message_to_sign_bytes.decode()}")
    
    # Create digital signature for the message
    digital_signature = create_digital_signature(message_to_sign_bytes, private_key, "SHA-256")
    print(f"✓ Digital signature created (signature length: {len(digital_signature)} bytes)")
    
    # Verify the digital signature
    signature_is_valid = verify_digital_signature(message_to_sign_bytes, digital_signature, public_key)
    print(f"Signature verification result: {'VALID' if signature_is_valid else 'INVALID'}")
    
    # Test signature verification with tampered message
    tampered_message_bytes = b"This message has been tampered with by an attacker"
    tampered_signature_valid = verify_digital_signature(tampered_message_bytes, digital_signature, public_key)
    print(f"Tampered message verification: {'VALID' if tampered_signature_valid else 'INVALID'} (should be INVALID)")
    
    # Test signature verification with tampered message
    tampered_message_bytes = b"This message has been tampered with by an attacker"
    tampered_signature_valid = verify_digital_signature(tampered_message_bytes, digital_signature, public_key)
    print(f"Tampered message verification: {'VALID' if tampered_signature_valid else 'INVALID'} (should be INVALID)")
    
    # 4. Test Different Hash Algorithms (Optional)
    print("\n4. Testing different hash algorithms for digital signatures...")
    test_various_hashes = input("Do you want to test different hash algorithms? (y/n): ").lower().strip()
    
    if test_various_hashes == 'y' or test_various_hashes == 'yes':
        print("Testing signature creation and verification with various hash algorithms...")
        
        # List of hash algorithms to test
        hash_algorithms_to_test = ["SHA-512", "SHA-384", "SHA-256", "SHA-1", "MD5"]
        
        for hash_algorithm in hash_algorithms_to_test:
            try:
                # Create signature with current hash algorithm
                test_signature = create_digital_signature(message_to_sign_bytes, private_key, hash_algorithm)
                
                # Verify the signature
                signature_valid = verify_digital_signature(message_to_sign_bytes, test_signature, public_key)
                
                print(f"✓ {hash_algorithm}: {'VALID' if signature_valid else 'INVALID'}")
            except Exception as error:
                print(f"✗ {hash_algorithm}: Error - {error}")
    else:
        print("Skipping hash algorithm tests.")
    
    print("\n=== RSA Demonstration Complete ===")
    print("All cryptographic operations have been tested successfully!")


# Main execution point
if __name__ == "__main__":
    run_rsa_demonstration()
