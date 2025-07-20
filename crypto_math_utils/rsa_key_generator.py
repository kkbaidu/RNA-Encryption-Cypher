# RSA Key Generation Module
# This module generates RSA public and private key pairs and saves them to files
# RSA is an asymmetric cryptographic algorithm that uses two mathematically related keys

import random, sys, os
from rabin_miller import generateLargePrime
from crypto_math import gcd, findModInverse

def main():
    """
    Main function to demonstrate RSA key generation
    Creates RSA key files with a 1024-bit key size for demonstration
    """
    create_rsa_key_files('RSA_demo', 1024)

def generate_rsa_keypair(key_bit_size):
    """
    Generate RSA public and private key pair using the RSA algorithm
    
    RSA Key Generation Steps:
    1. Generate two large prime numbers (p and q)
    2. Calculate n = p * q (modulus for both keys)
    3. Calculate φ(n) = (p-1) * (q-1) (Euler's totient function)
    4. Choose e such that gcd(e, φ(n)) = 1 (public exponent)
    5. Calculate d such that (d * e) ≡ 1 (mod φ(n)) (private exponent)
    
    Args:
        key_bit_size (int): The size of the RSA key in bits
        
    Returns:
        tuple: (public_key_tuple, private_key_tuple) where each tuple is (n, exponent)
    """
    # Step 1: Generate two distinct large prime numbers
    print('Generating first prime number (p)...')
    first_prime_p = generateLargePrime(key_bit_size)
    print('First prime (p) generated:', first_prime_p)
    
    print('Generating second prime number (q)...')
    second_prime_q = generateLargePrime(key_bit_size)
    print('Second prime (q) generated:', second_prime_q)

    # Step 2: Calculate the modulus n = p * q
    modulus_n = first_prime_p * second_prime_q
    print('Modulus n (p * q) calculated:', modulus_n)

    # Step 3: Calculate Euler's totient function φ(n) = (p-1) * (q-1)
    euler_totient = (first_prime_p - 1) * (second_prime_q - 1)
    
    # Step 4: Find a suitable public exponent e
    print('Finding public exponent e that is coprime to φ(n)...')
    # Common choices for e: start with 65537, then try other small primes
    common_public_exponents = [65537, 3, 5, 17, 257]
    public_exponent_e = None
    
    for candidate_e in common_public_exponents:
        if gcd(candidate_e, euler_totient) == 1:
            public_exponent_e = candidate_e
            break
    
    # If none of the common values work, search for a small odd number
    if public_exponent_e is None:
        public_exponent_e = 3
        while gcd(public_exponent_e, euler_totient) != 1:
            public_exponent_e += 2  # Only try odd numbers
    
    print('Public exponent e found:', public_exponent_e)

    # Step 5: Calculate the private exponent d (modular multiplicative inverse of e)
    print('Calculating private exponent d (modular inverse of e)...')
    private_exponent_d = findModInverse(public_exponent_e, euler_totient)

    # Construct the key pairs
    public_key_pair = (modulus_n, public_exponent_e)
    private_key_pair = (modulus_n, private_exponent_d)
    
    print('Public key (n, e):', public_key_pair)
    print('Private key (n, d):', private_key_pair)
    
    return (public_key_pair, private_key_pair)
   

def create_rsa_key_files(file_prefix, key_bit_size):
    """
    Generate RSA key pair and save them to separate files
    
    Creates two files:
    - '{file_prefix}_pubkey.txt': Contains the public key (key_size, n, e)
    - '{file_prefix}_privkey.txt': Contains the private key (key_size, n, d)
    
    Args:
        file_prefix (str): Prefix name for the key files
        key_bit_size (int): Size of the RSA key in bits
        
    Raises:
        SystemExit: If key files already exist to prevent accidental overwriting
    """
    # Check if key files already exist to prevent accidental overwriting
    public_key_filename = '%s_pubkey.txt' % (file_prefix)
    private_key_filename = '%s_privkey.txt' % (file_prefix)
    
    if os.path.exists(public_key_filename) or os.path.exists(private_key_filename):
        sys.exit('WARNING: The file %s or %s already exists! Use a different name or delete these files and re-run this program.' %
                  (public_key_filename, private_key_filename))
    
    # Generate the RSA key pair
    public_key_data, private_key_data = generate_rsa_keypair(key_bit_size)

    print()

    # Display information about the public key and save it to file
    print('The public key components have %s and %s digits respectively.' %
          (len(str(public_key_data[0])), len(str(public_key_data[1]))))
    print('Writing public key to file %s...' % public_key_filename)
    
    with open(public_key_filename, 'w') as public_key_file:
        # Format: key_size,n,e
        public_key_file.write('%s,%s,%s' % (key_bit_size, public_key_data[0], public_key_data[1]))

    print()

    # Display information about the private key and save it to file
    print('The private key components have %s and %s digits respectively.' %
          (len(str(private_key_data[0])), len(str(private_key_data[1]))))
    print('Writing private key to file %s...' % private_key_filename)
    
    with open(private_key_filename, 'w') as private_key_file:
        # Format: key_size,n,d
        private_key_file.write('%s,%s,%s' % (key_bit_size, private_key_data[0], private_key_data[1]))
    
    print('RSA key pair generation completed successfully!')

# Entry point: Execute the main function when script is run directly
if __name__ == '__main__':
    main()