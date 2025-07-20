# RSA Encryption Cipher Project

A comprehensive Python implementation of RSA asymmetric cryptography featuring secure encryption/decryption, digital signatures, cryptanalysis demonstrations, and custom RSA key generation from scratch.

## 📋 Project Overview

This educational project provides a complete RSA cryptographic system with multiple implementations ranging from high-level library usage to low-level mathematical implementations. It demonstrates both the power and vulnerabilities of RSA encryption through practical examples and educational tools.

## 🚀 Features

### Core Cryptographic Operations

- **RSA Key Pair Generation** (1024, 2048, 3072, 4096-bit support)
- **Secure Message Encryption** with PKCS1_OAEP padding
- **Message Decryption** with comprehensive error handling
- **Digital Signatures** with multiple hash algorithms (SHA-256, SHA-512, SHA-384, SHA-1, MD5)
- **Signature Verification** with tamper detection
- **Base64 encoding** for safe text representation

### Educational Components

- **Custom RSA Implementation** from mathematical primitives
- **Prime Number Generation** with Rabin-Miller primality testing
- **Cryptographic Mathematics** (GCD, Modular Inverse, Euler's Totient)
- **RSA Cryptanalysis** demonstration for small keys
- **Security Vulnerability** examples and explanations

### Advanced Features

- **Multiple Hash Algorithm Support** for digital signatures
- **Interactive Demonstrations** with user input
- **File-based Key Storage** and management
- **Comprehensive Error Handling** and validation
- **Educational Cryptanalysis Tools**

## 📁 Project Structure

```
security/
├── rsa_demo_basic.py            # High-level RSA encryption/decryption demo
├── rsa_cryptanalysis_demo.py    # RSA cryptanalysis and attack demonstration
├── requirements.txt             # Project dependencies
├── README.md                   # Project documentation
├── crypto_math_utils/          # Custom mathematical implementations
│   ├── crypto_math.py          # GCD and modular inverse functions
│   ├── rabin_miller.py         # Prime number generation and testing
│   └── rsa_key_generator.py    # Custom RSA key generation from scratch
└── rsa_complete_system/
    └── rsa_cipher_system.py    # Complete RSA system with signatures
```

## 🛠️ Installation

1. **Clone the repository:**

```bash
git clone https://github.com/kkbaidu/RNA-Encryption-Cypher.git
cd RNA-Encryption-Cypher
```

2. **Create virtual environment:**

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

## 🎯 Usage Examples

### Basic RSA Encryption/Decryption

```bash
python rsa_demo_basic.py
```

- Interactive message encryption and decryption
- Key generation demonstration
- Base64 encoding examples

### Complete RSA Cryptographic System

```bash
python rsa_complete_system/rsa_cipher_system.py
```

- Full RSA implementation with digital signatures
- Multiple key sizes (1024, 2048, 3072, 4096 bits)
- Hash algorithm testing (SHA-256, SHA-512, etc.)
- Signature verification and tamper detection

### Custom RSA Key Generation

```bash
cd crypto_math_utils
python rsa_key_generator.py
```

- Generate RSA keys from mathematical primitives
- Save keys to files for later use
- Educational demonstration of RSA mathematics

### RSA Cryptanalysis (Educational)

```bash
python rsa_cryptanalysis_demo.py
```

- Demonstrate RSA vulnerabilities with small keys
- Factor RSA modulus through brute force
- Calculate private keys from public components
- **⚠️ Warning: Educational purposes only!**

## 📚 Module Documentation

### `asym_crypto_rsa.py`

**Purpose:** High-level RSA encryption demonstration using pycryptodome

- `generate_keys()`: Create RSA key pair with secure random generation
- `encrypt_message()`: Encrypt messages with OAEP padding
- `decrypt_message()`: Decrypt ciphertext with error handling

### `rsa_cryptanalysis_demo.py`

**Purpose:** Educational RSA cryptanalysis for small keys

- `factorize_modulus()`: Brute force factorization of RSA modulus
- `calculate_euler_totient()`: Compute Euler's totient function φ(n)
- `find_private_exponent()`: Recover private key from public components
- `decrypt_ciphertext()`: Decrypt using recovered private key

### `Cryptomath&RabinMiller/cryptomath_module.py`

**Purpose:** Fundamental cryptographic mathematics

- `gcd()`: Greatest Common Divisor using Euclidean algorithm
- `findModInverse()`: Modular multiplicative inverse calculation

### `Cryptomath&RabinMiller/rabinMiller_module.py`

**Purpose:** Prime number generation and testing

- `rabin_miller_test()`: Probabilistic primality testing
- `is_prime_number()`: Comprehensive primality verification
- `generateLargePrime()`: Generate cryptographically strong primes

### `Cryptomath&RabinMiller/generate_rsa_keys`

**Purpose:** Custom RSA key generation from scratch

- `generate_rsa_keypair()`: Complete RSA key generation process
- `create_rsa_key_files()`: Save generated keys to files

### `RSA Cipher/cypher.py`

**Purpose:** Complete RSA cryptographic system

- `generate_rsa_keypair()`: Professional key generation
- `encrypt_message()` / `decrypt_message()`: OAEP encryption/decryption
- `create_digital_signature()`: Multi-algorithm digital signatures
- `verify_digital_signature()`: Signature verification with tamper detection

## 🔒 Security Features

### Encryption Security

- **PKCS1_OAEP Padding**: Provides semantic security and prevents various attacks
- **Multiple Key Sizes**: Support for 1024, 2048, 3072, and 4096-bit keys
- **Cryptographically Secure Random Numbers**: Using Crypto.Random for key generation

### Digital Signature Security

- **Multiple Hash Algorithms**: SHA-256, SHA-512, SHA-384, SHA-1, MD5 support
- **Tamper Detection**: Automatic verification of message integrity
- **Non-repudiation**: Cryptographic proof of message origin

### Educational Security Warnings

- **Small Key Vulnerabilities**: Demonstration of why large keys are essential
- **Factorization Attacks**: Shows how RSA can be broken with insufficient key sizes
- **Best Practice Guidelines**: Recommendations for production use

## ⚠️ Security Considerations

### For Production Use

- **Minimum 2048-bit keys** (4096-bit recommended for high security)
- **Use SHA-256 or stronger** hash algorithms for signatures
- **Proper key management** and secure storage practices
- **Regular key rotation** according to security policies

### Educational Warnings

- The cryptanalysis tools work only on **small keys** (demonstration purposes)
- **Never use small keys** in production environments
- The brute force attacks shown are **computationally infeasible** for proper key sizes
- This project is for **educational purposes** - use established libraries for production

## 🎓 Educational Value

### Learning Objectives

1. **Understanding RSA Mathematics**: Prime generation, modular arithmetic, Euler's totient
2. **Cryptographic Padding**: Why OAEP is essential for semantic security
3. **Digital Signatures**: Authentication, integrity, and non-repudiation
4. **Security Vulnerabilities**: How weak implementations can be exploited
5. **Best Practices**: Modern cryptographic standards and recommendations

### Recommended Learning Path

1. Start with `asym_crypto_rsa.py` for basic concepts
2. Explore `RSA Cipher/cypher.py` for complete implementation
3. Study `Cryptomath&RabinMiller/` modules for mathematical foundations
4. Understand vulnerabilities with `rsa_cryptanalysis_demo.py` (responsibly)
5. Experiment with different key sizes and algorithms

## 📦 Dependencies

```txt
pyasn1==0.6.1          # ASN.1 types and codecs for cryptographic standards
pycryptodome==3.23.0    # Modern cryptographic library (successor to PyCrypto)
random2==1.0.2          # Enhanced random number generation
rsa==4.9.1              # Pure Python RSA implementation
```

## 🔬 Technical Details

### RSA Algorithm Implementation

1. **Prime Generation**: Uses Rabin-Miller probabilistic primality testing
2. **Key Generation**: Follows standard RSA key generation procedures
3. **Encryption**: PKCS1_OAEP padding for semantic security
4. **Signatures**: PKCS1_v1_5 signatures with multiple hash algorithms

### Mathematical Components

- **Euclidean Algorithm**: For GCD calculation
- **Extended Euclidean Algorithm**: For modular inverse computation
- **Fermat's Little Theorem**: Foundation for Rabin-Miller testing
- **Euler's Totient Function**: Essential for RSA key generation

## 🤝 Contributing

Contributions are welcome! Please consider:

- Adding new cryptographic demonstrations
- Improving educational explanations
- Enhancing security documentation
- Adding support for additional algorithms

## 📄 License

This project is intended for educational purposes. Please ensure compliance with local cryptographic regulations.

## 👨‍💻 Author

**kkbaidu** - [GitHub](https://github.com/kkbaidu)

## 🔗 Related Resources

- [RSA Cryptosystem - Wikipedia](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>)
- [OAEP Padding - RFC 3447](https://tools.ietf.org/html/rfc3447)
- [Digital Signatures - PKCS #1](https://tools.ietf.org/html/rfc3447)
- [Rabin-Miller Primality Test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
