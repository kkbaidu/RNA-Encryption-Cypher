# Rabin-Miller Primality Testing Module
# This module implements the Rabin-Miller probabilistic primality test
# Used to generate large prime numbers essential for RSA cryptography

import random

def rabin_miller_test(candidate_number):
    """
    Perform the Rabin-Miller probabilistic primality test
    
    This is a Monte Carlo algorithm that determines whether a number is likely prime.
    It's much faster than deterministic tests for large numbers.
    
    The algorithm works by:
    1. Express n-1 as 2^r * d where d is odd
    2. Pick random witnesses and test specific conditions
    3. If any witness proves compositeness, return False
    4. If all witnesses pass, the number is probably prime
    
    Args:
        candidate_number (int): The number to test for primality
        
    Returns:
        bool: True if probably prime, False if definitely composite
    """
    # Express candidate_number - 1 as 2^r * d where d is odd
    # This is the key transformation for the Rabin-Miller test
    odd_factor_d = candidate_number - 1  # Start with n-1
    power_of_two_r = 0
    
    # Factor out all powers of 2
    while odd_factor_d % 2 == 0:
        odd_factor_d = odd_factor_d // 2
        power_of_two_r += 1
    
    # Perform multiple rounds with different random witnesses
    # More rounds = higher confidence but slower execution
    number_of_trials = 5
    for trial_round in range(number_of_trials):
        # Choose a random witness between 2 and candidate_number-2
        random_witness = random.randrange(2, candidate_number - 1)
        
        # Calculate witness^d mod candidate_number
        witness_power = pow(random_witness, odd_factor_d, candidate_number)
        
        # If witness^d ≡ 1 (mod n), this witness doesn't prove compositeness
        if witness_power != 1:
            iteration_count = 0
            
            # Check if witness^(2^i * d) ≡ -1 (mod n) for some i
            while witness_power != (candidate_number - 1):
                if iteration_count == power_of_two_r - 1:
                    # If we've checked all powers and never found -1, it's composite
                    return False
                else:
                    iteration_count = iteration_count + 1
                    # Square the witness power: witness^(2^i * d) → witness^(2^(i+1) * d)
                    witness_power = (witness_power * witness_power) % candidate_number

    # All witnesses passed the test - probably prime
    return True


def is_prime_number(test_number):
    """
    Comprehensive primality test combining trial division and Rabin-Miller test
    
    This function provides a two-stage primality test:
    1. Quick trial division against small known primes (fast elimination)
    2. Rabin-Miller probabilistic test for remaining candidates (high accuracy)
    
    Args:
        test_number (int): The number to test for primality
        
    Returns:
        bool: True if the number is prime, False if composite
    """
    # Handle edge cases: numbers less than 2 are not prime
    if (test_number < 2):
        return False
    
    # List of the first 168 prime numbers for quick trial division
    # This eliminates most composite numbers very quickly
    small_prime_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                        59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
                        139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
                        229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 
                        317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
                        421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
                        521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
                        619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727,
                        733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
                        839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
                        953, 967, 971, 977, 983, 991, 997]

    # Check if the number is in our list of known small primes
    if test_number in small_prime_list:
        return True
    
    # Quick trial division: if divisible by any small prime, it's composite
    for small_prime in small_prime_list:
        if (test_number % small_prime == 0):
            return False
    
    # If it passes trial division, use Rabin-Miller for final verification
    return rabin_miller_test(test_number)


def generateLargePrime(key_bit_size=1024):
    """
    Generate a large prime number suitable for RSA cryptography
    
    This function generates cryptographically strong prime numbers by:
    1. Creating random numbers in the specified bit range
    2. Testing each candidate for primality
    3. Returning the first prime found
    
    The generated primes are suitable for RSA because they:
    - Are large enough to be cryptographically secure
    - Are randomly distributed to prevent prediction
    - Pass rigorous primality tests
    
    Args:
        key_bit_size (int): The desired bit length of the prime (default: 1024)
        
    Returns:
        int: A large prime number with approximately key_bit_size bits
        
    Note:
        The actual bit length may vary slightly but will be close to key_bit_size
    """
    while True:
        # Generate a random number in the range [2^(key_bit_size-1), 2^key_bit_size)
        # This ensures the number has approximately key_bit_size bits
        random_candidate = random.randrange(2**(key_bit_size-1), 2**(key_bit_size))
        
        # Test if the candidate is prime
        if is_prime_number(random_candidate):
            return random_candidate