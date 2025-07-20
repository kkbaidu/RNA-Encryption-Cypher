
# RSA Cryptanalysis Module
# This module demonstrates how RSA can be broken when the modulus n can be factored
# WARNING: This is for educational purposes only - demonstrates RSA vulnerabilities

def factorize_modulus(rsa_modulus):
    """
    Factor the RSA modulus n into its prime components p and q
    
    This is the critical weakness in RSA - if an attacker can factor n,
    they can break the encryption. This brute force method only works
    for small values of n.
    
    Args:
        rsa_modulus (int): The RSA modulus n = p * q
        
    Returns:
        tuple: (p, q) - the prime factors of n
    """
    prime_factors = []
    
    # Try all possible divisors from 2 to n-1 (brute force factorization)
    for potential_factor in range(2, rsa_modulus):
        if rsa_modulus % potential_factor == 0:
            prime_factors.append(potential_factor)
    
    return tuple(prime_factors)

def calculate_euler_totient(first_prime, second_prime):
    """
    Calculate Euler's totient function φ(n) = (p-1) * (q-1)
    
    For RSA, φ(n) represents the count of integers from 1 to n that are
    coprime to n. This value is used to calculate the private exponent.
    
    Args:
        first_prime (int): First prime factor p
        second_prime (int): Second prime factor q
        
    Returns:
        int: φ(n) = (p-1) * (q-1)
    """
    return (first_prime - 1) * (second_prime - 1)

def find_private_exponent(public_exponent, totient_value):
    """
    Find the private exponent d by brute force search
    
    The private exponent d satisfies: (d * e) ≡ 1 (mod φ(n))
    This means d is the modular multiplicative inverse of e modulo φ(n).
    
    Args:
        public_exponent (int): The public exponent e
        totient_value (int): Euler's totient φ(n)
        
    Returns:
        int: The private exponent d, or None if not found
    """
    # Try all possible values until we find d such that (d * e) mod φ(n) = 1
    for candidate_d in range(2, totient_value):
        if candidate_d * public_exponent % totient_value == 1:
            return candidate_d
    
    # Return None if no private exponent is found (shouldn't happen with valid RSA parameters)
    return None

def decrypt_ciphertext(private_exponent, modulus, ciphertext):
    """
    Decrypt the RSA ciphertext using the recovered private key
    
    RSA decryption formula: plaintext = ciphertext^d mod n
    where d is the private exponent and n is the modulus.
    
    Args:
        private_exponent (int): The private exponent d
        modulus (int): The RSA modulus n
        ciphertext (int): The encrypted message
        
    Returns:
        int: The decrypted plaintext message
    """
    # Apply RSA decryption: m = c^d mod n
    return ciphertext ** private_exponent % modulus 

def demonstrate_rsa_attack():
    """
    Interactive demonstration of RSA cryptanalysis attack
    
    This function shows how RSA can be broken when:
    1. The modulus n can be factored into p and q
    2. The private exponent d can be calculated
    3. The ciphertext can be decrypted
    
    WARNING: This only works for small RSA keys and is for educational purposes only!
    """
    print("=== RSA Cryptanalysis Demonstration ===")
    print("WARNING: This attack only works on small RSA keys!")
    print("Real RSA uses much larger primes that cannot be factored easily.\n")
    
    # Get RSA parameters from user
    public_exponent_e = int(input("Enter the public exponent (e): "))
    modulus_n = int(input("Enter the modulus (n): "))
    ciphertext_c = int(input("Enter the ciphertext (c): "))
    
    print(f"\n=== Step 1: Factoring the modulus n = {modulus_n} ===")
    # Factor the modulus to find p and q
    prime_factors = factorize_modulus(modulus_n)
    print(f"Prime factors found: p = {prime_factors[0]}, q = {prime_factors[1]}")
    
    print(f"\n=== Step 2: Calculating Euler's totient φ(n) ===")
    # Calculate Euler's totient function
    totient_phi = calculate_euler_totient(prime_factors[0], prime_factors[1])
    print(f"φ(n) = (p-1) × (q-1) = {totient_phi}")
    
    print(f"\n=== Step 3: Finding the private exponent d ===")
    # Find the private exponent d
    private_exponent_d = find_private_exponent(public_exponent_e, totient_phi)
    
    if private_exponent_d is None:
        print("ERROR: Could not find private exponent d. Invalid RSA parameters.")
        return
    
    print(f"Private exponent d = {private_exponent_d}")
    print(f"Verification: (d × e) mod φ(n) = ({private_exponent_d} × {public_exponent_e}) mod {totient_phi} = {(private_exponent_d * public_exponent_e) % totient_phi}")
    
    print(f"\n=== Step 4: Decrypting the ciphertext ===")
    # Decrypt the ciphertext
    decrypted_plaintext = decrypt_ciphertext(private_exponent_d, modulus_n, ciphertext_c)
    print(f"Decrypted plaintext: {decrypted_plaintext}")
    
    print(f"\n=== Attack Summary ===")
    print(f"Public Key: (n={modulus_n}, e={public_exponent_e})")
    print(f"Recovered Private Key: (n={modulus_n}, d={private_exponent_d})")
    print(f"Ciphertext: {ciphertext_c}")
    print(f"Recovered Plaintext: {decrypted_plaintext}")
    print(f"\n✅ RSA attack successful! The encryption has been broken.")

if __name__ == "__main__":
    demonstrate_rsa_attack()