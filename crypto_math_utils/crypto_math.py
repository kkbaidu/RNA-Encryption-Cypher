# Cryptographic Mathematical Functions Module
# This module provides essential mathematical functions for RSA cryptography
# including Greatest Common Divisor (GCD) and Modular Multiplicative Inverse

def gcd(first_number, second_number):
    """
    Calculate the Greatest Common Divisor (GCD) of two integers using Euclidean algorithm
    
    The GCD is the largest positive integer that divides both numbers without remainder.
    This is crucial for RSA to ensure the public exponent e is coprime to φ(n).
    
    Args:
        first_number (int): First integer
        second_number (int): Second integer
        
    Returns:
        int: The greatest common divisor of the two input numbers
        
    Example:
        gcd(48, 18) returns 6
    """
    # Use Euclidean algorithm: repeatedly apply the division algorithm
    while first_number != 0:
        first_number, second_number = second_number % first_number, first_number
    return second_number
  
def findModInverse(base_number, modulus):
    """
    Find the modular multiplicative inverse using the Extended Euclidean Algorithm
    
    The modular multiplicative inverse of 'a' modulo 'm' is a number 'x' such that:
    (a * x) ≡ 1 (mod m)
    
    This is essential for RSA to calculate the private exponent d from public exponent e.
    
    Args:
        base_number (int): The number to find the inverse of
        modulus (int): The modulus
        
    Returns:
        int: The modular multiplicative inverse, or None if it doesn't exist
        
    Note:
        The inverse exists only if gcd(base_number, modulus) = 1
    """
    # Check if modular inverse exists (base_number and modulus must be coprime)
    if gcd(base_number, modulus) != 1:
        return None
    
    # Extended Euclidean Algorithm variables
    # u represents coefficients for base_number, v represents coefficients for modulus
    u1, u2, u3 = 1, 0, base_number  # Coefficients and remainder for base_number
    v1, v2, v3 = 0, 1, modulus      # Coefficients and remainder for modulus
    
    # Continue until we find the GCD
    while v3 != 0:
        quotient = u3 // v3  # Integer division quotient
        # Update all coefficients and remainders simultaneously
        v1, v2, v3, u1, u2, u3 = (u1 - quotient * v1), (u2 - quotient * v2), (u3 - quotient * v3), v1, v2, v3
    
    # Return the positive modular inverse
    return u1 % modulus