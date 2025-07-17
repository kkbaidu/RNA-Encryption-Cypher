# RSA Encryption Cipher

A Python implementation of RSA asymmetric cryptography for secure message encryption and decryption.

## Overview

This project demonstrates RSA encryption using the pycryptodome library with PKCS1_OAEP padding for enhanced security.

## Features

- RSA Key Pair Generation (1024-bit)
- Secure Message Encryption with OAEP padding
- Message Decryption
- Base64 encoding for text representation
- Comprehensive code documentation

## Installation

1. Clone the repository:

```bash
git clone https://github.com/kkbaidu/RNA-Encryption-Cypher.git
cd RNA-Encryption-Cypher
```

2. Create virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the main script:

```bash
python main.py
```

## Dependencies

- pycryptodome: Cryptographic library
- pyasn1: ASN.1 types and codecs
- random2: Enhanced random number generation
- rsa: RSA implementation

## How It Works

1. **Key Generation**: Creates RSA private/public key pair
2. **Encryption**: Uses public key with OAEP padding
3. **Decryption**: Uses private key to recover original message

## Security Notes

- Uses 1024-bit keys (increase to 2048+ for production)
- Implements PKCS1_OAEP padding for security
- Uses cryptographically secure random numbers

## Author

**kkbaidu** - [GitHub](https://github.com/kkbaidu)
