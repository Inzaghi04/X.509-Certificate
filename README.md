# X.509 Certificate Demo (Pure C - No External Libraries)

## 📌 Overview

This project is a **pure C implementation** of RSA encryption and X.509 certificate simulation **without using any external cryptography libraries** (no OpenSSL, no mbedTLS).
link slide: https://www.canva.com/design/DAG73ulnjUs/4g9jLjhAtrmtqn2CKgx9Ig/edit?fbclid=IwY2xjawPWlplleHRuA2FlbQIxMABicmlkETFQV3hHNjIyV2VxbUxObngyc3J0YwZhcHBfaWQQMjIyMDM5MTc4ODIwMDg5MgABHqLfiEpgcSHwhynx471mN5ZQE3-8f-T4H4S0ClhmM2a2Zg6xWJ0zE8AQgbWn_aem_hHspp4VrCeDqqf0RsAz16g


Everything is implemented from scratch to demonstrate:
- **RSA encryption/decryption algorithm** (mathematical implementation)
- **Big number arithmetic** (for handling large integers)
- **X.509 certificate structure** (simplified)
- **Asymmetric key cryptography** principles
- **Security tests** (tampering, wrong key, size limits)

⚠️ **This is purely educational code.** Do NOT use in production!

---

## 🎯 Educational Goals

After studying this project, you will understand:

1. **How RSA really works** (mathematical operations)
2. **What's inside an X.509 certificate** (structure and fields)
3. **Why asymmetric encryption is secure** (different keys for encrypt/decrypt)
4. **Common cryptographic attacks** and how systems defend against them
5. **Why we use libraries in production** (complexity, security, performance)

---

## 🔐 X.509 Certificate Flow (Implemented)

```
┌────────┐                                    ┌───────────┐
│ SENDER │                                    │ RECIPIENT │
└────┬───┘                                    └─────┬─────┘
     │                                              │
     │  1. Recipient generates RSA key pair        │
     │     • Public Key:  (n, e)                   │
     │     • Private Key: (n, d)                   │
     │                                              │
     │  2. Recipient creates X.509 certificate     │
     │     containing PUBLIC KEY                   │
     │                                              │
     │  3. Sender gets certificate                 │
     │ ◄────────────────────────────────────────── │
     │                                              │
     │  4. Sender extracts PUBLIC KEY (n, e)       │
     │                                              │
     │  5. Encrypt with PUBLIC KEY                 │
     │     C = M^e mod n                           │
     │                                              │
     │  6. Send CIPHERTEXT                         │
     │ ─────────────────────────────────────────► │
     │                                              │
     │                    7. Decrypt with PRIVATE KEY
     │                       M = C^d mod n
     │                                              │
```

---

## 📁 Project Structure

```text
X.509-Pure-C/
├── main.c           # Main implementation (Sender/Recipient simulation)
├── tests.c    # Security robustness tests
├── MakeFile                # Build script
└── README.md               # This file
```

### File Descriptions

| File | Lines | Description |
|------|-------|-------------|
| `main.c` | ~350 | Complete RSA + X.509 implementation with demo |
| `tests.c` | ~450 | Security tests (tampering, wrong key, size limits) |

---

## ⚙️ Requirements

**Only standard C libraries:**
- `stdio.h` - Input/output
- `stdlib.h` - Memory allocation
- `string.h` - String operations
- `stdint.h` - Fixed-width integers
- `time.h` - Random seed (optional)

**No external dependencies!**

### System Requirements
- **OS:** Linux / WSL / macOS / Windows
- **Compiler:** GCC or Clang
- **Math library:** `-lm` (for modular arithmetic)

---

## 🔨 Build Instructions

### Using Makefile

```bash
make all
```

This creates two executables:
- `main` - Main implementation demo
- `tests` - Security tests

### Build Individual Programs

```bash
# Main demo
make main

# Security tests  
make tests
```

### Manual Build

```bash
# Main implementation
gcc main.c -o x509_pure_demo -lm

# Security tests
gcc tests.c -o tests -lm
```

### Clean Build

```bash
make clean
```

---

## 🚀 How to Run

### 1. Main Demo

```bash
./x509_pure_demo
```

**Expected Output:**
```
╔════════════════════════════════════════════════════╗
║   X.509 RSA ENCRYPTION (No External Libraries)     ║
║            Pure C Implementation                   ║
╚════════════════════════════════════════════════════╝

🔧 STEP 0: Recipient generates RSA key pair
========================================
Generated RSA keys (DEMO - small numbers):
  p = 61, q = 53
  n = 3233 (modulus)
  e = 17 (public exponent)
  d = 2753 (private exponent)

📜 STEP 1: Recipient creates X.509 certificate
========================================
Created X.509 Certificate:
  Subject: CN=Recipient,O=Demo Corp
  Issuer: CN=Demo CA,O=Demo Corp
  Public Key (n,e): (3233, 17)

📤 STEP 2: SENDER encrypts message
========================================
Plaintext message: "Hello!"

Encrypting message byte-by-byte:
  'H' (ASCII 72) -> 2181
  'e' (ASCII 101) -> 2344
  'l' (ASCII 108) -> 2991
  'l' (ASCII 108) -> 2991
  'o' (ASCII 111) -> 19
  '!' (ASCII 33) -> 68

Ciphertext (hex): 0885 0928 0BAF 0BAF 0013 0044

📡 Transmitting ciphertext over network...

📥 STEP 3: RECIPIENT decrypts message
========================================
Recipient uses their PRIVATE KEY:
  n = 3233
  d = 2753

Decrypting ciphertext:
  2181 -> 'H' (ASCII 72)
  2344 -> 'e' (ASCII 101)
  2991 -> 'l' (ASCII 108)
  2991 -> 'l' (ASCII 108)
  19 -> 'o' (ASCII 111)
  68 -> '!' (ASCII 33)

✅ Decrypted plaintext: "Hello!"
```

### 2. Security Tests

```bash
./tests
```

**Tests Performed:**

#### TEST 0: Baseline (Correct Operation)
```
✅ PASS: Correct encryption/decryption
```

#### TEST 1: Tampering Attack
```
Original Ciphertext: 0885 0928 0BAF ...
Tampered Ciphertext: F77A 0928 0BAF ...  (first byte modified)
>>> ✅ PASS: System detected tampering (decryption failed)
```

#### TEST 2: Wrong Key Attack
```
Attacker's key: n=3953, d=3713 (different from recipient's)
Decrypted text: "±Ó¶¶Ø<"  (garbage)
>>> ✅ PASS: Wrong key produced garbage
```

#### TEST 3: Size Limit Check
```
Attempting to encrypt 250 bytes...
>>> ✅ PASS: System rejected oversized message
```

---

## 🧠 Implementation Details

### 1. Big Number Arithmetic

```c
typedef struct {
    uint64_t data[64];  // Array to store large numbers
    int len;            // Number of significant words
} BigNum;
```

**Implemented Operations:**
- `bn_set()` - Set value
- `bn_copy()` - Copy numbers
- `bn_modexp()` - Modular exponentiation (a^b mod n)

**Algorithm Used:**
- **Square-and-Multiply** for efficient modular exponentiation

### 2. RSA Key Structure

```c
typedef struct {
    BigNum n;  // Modulus (n = p × q)
    BigNum e;  // Public exponent
    BigNum d;  // Private exponent
} RSAKey;
```

**Key Generation (Simplified):**
```
1. Choose two primes: p = 61, q = 53
2. Calculate modulus: n = p × q = 3233
3. Calculate totient: φ(n) = (p-1)(q-1) = 3120
4. Choose public exponent: e = 17
5. Calculate private exponent: d = e^(-1) mod φ(n) = 2753
```

### 3. RSA Encryption/Decryption

```c
// Encryption: C = M^e mod n
uint64_t ciphertext = rsa_encrypt(plaintext_byte, &public_key);

// Decryption: M = C^d mod n
uint64_t plaintext_byte = rsa_decrypt(ciphertext, &private_key);
```

**Mathematical Proof:**
```
Given: M^e ≡ C (mod n)
Then:  C^d ≡ M (mod n)

Because: ed ≡ 1 (mod φ(n))
So:      C^d = (M^e)^d = M^(ed) = M^1 = M (mod n)
```

### 4. X.509 Certificate (Simplified)

```c
typedef struct {
    char subject[128];    // Certificate owner
    char issuer[128];     // Who signed it
    RSAKey public_key;    // Public key
} X509Certificate;
```

**What's Missing (for simplicity):**
- ASN.1/DER encoding
- Digital signature
- Validity period (notBefore, notAfter)
- Extensions (KeyUsage, SubjectAltName, etc.)
- Certificate chain validation

---

## 🔬 Why Small Numbers?

This implementation uses **small RSA keys** for educational purposes:

| Parameter | Demo Value | Real-world Value |
|-----------|------------|------------------|
| Primes (p, q) | 61, 53 | 1024-bit each (300+ digits) |
| Modulus (n) | 3233 | 2048-4096 bits (600-1200 digits) |
| Public exponent (e) | 17 | 65537 (0x10001) |
| Private exponent (d) | 2753 | ~2048 bits |

**Why real RSA uses large numbers:**
- Security: Factoring large `n` is computationally infeasible
- Our demo `n=3233` can be factored in microseconds
- Real 2048-bit `n` would take millions of years to factor

---

## 🛡️ Security Analysis

### ✅ What This Demo Demonstrates Correctly:

1. **Asymmetric Encryption**
   - Different keys for encryption/decryption
   - Public key can be shared safely
   - Only private key holder can decrypt

2. **Data Integrity**
   - Tampering with ciphertext → decryption fails
   - RSA without padding still has structure validation

3. **Confidentiality**
   - Wrong private key → garbage output
   - Knowledge of public key doesn't help decrypt

4. **Input Validation**
   - Message size limits enforced
   - Prevents buffer overflows

### ❌ What's Missing for Production:

1. **Secure Key Generation**
   - No prime number testing
   - No cryptographically secure random numbers
   - Hardcoded demo keys

2. **Padding Schemes**
   - Missing OAEP (encryption)
   - Missing PSS (signatures)
   - Vulnerable to mathematical attacks

3. **Certificate Validation**
   - No signature verification
   - No CA chain checking
   - No expiry validation

4. **Side-Channel Protection**
   - No constant-time operations
   - Vulnerable to timing attacks

5. **Performance**
   - Naive big number arithmetic
   - No Montgomery multiplication
   - No Chinese Remainder Theorem optimization

---

## 📊 Comparison: Pure C vs OpenSSL

| Feature | Pure C (This Project) | OpenSSL |
|---------|----------------------|---------|
| **Lines of Code** | ~800 lines | ~400,000 lines |
| **Key Size** | Hardcoded small (demo) | 2048-4096 bits |
| **Security** | Educational only | Production-grade |
| **Performance** | Slow (naive algorithms) | Highly optimized |
| **Padding** | None | OAEP, PSS |
| **Side-Channel Protection** | None | Constant-time ops |
| **Certificate Validation** | None | Full X.509 validation |
| **Learning Value** | ⭐⭐⭐⭐⭐ | ⭐⭐ (black box) |

---

## 🎓 Learning Exercises

Try these modifications to deepen your understanding:

### Beginner Level:
1. Change the message to encrypt longer text
2. Modify prime numbers (p, q) and recalculate d
3. Add comments explaining each RSA step

### Intermediate Level:
4. Implement proper prime number generation
5. Add support for 128-bit numbers (instead of 64-bit)
6. Create a function to verify RSA key correctness

### Advanced Level:
7. Implement PKCS#1 v1.5 padding
8. Add digital signature creation and verification
9. Implement Montgomery multiplication for speed
10. Parse a real X.509 certificate (ASN.1/DER format)

---

## 🐛 Known Limitations

1. **Security:**
   - ⚠️ Keys are too small (easily breakable)
   - ⚠️ No padding (vulnerable to attacks)
   - ⚠️ Not constant-time (timing attacks possible)

2. **Functionality:**
   - Only encrypts small messages (byte-by-byte)
   - No support for large files
   - No certificate chain validation

3. **Performance:**
   - Slow for large numbers
   - No optimization techniques
   - Single-threaded only

4. **Compatibility:**
   - Simplified X.509 format
   - Cannot interoperate with real certificates
   - No ASN.1 encoding/decoding

---

## 📚 Further Reading

### RSA Algorithm:
- [RSA (cryptosystem) - Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [The RSA Algorithm - Khan Academy](https://www.khanacademy.org/computing/computer-science/cryptography)

### X.509 Certificates:
- [X.509 Standard (ITU-T)](https://www.itu.int/rec/T-REC-X.509)
- [RFC 5280 - Internet X.509 PKI](https://tools.ietf.org/html/rfc5280)

### Big Number Arithmetic:
- [Handbook of Applied Cryptography - Chapter 14](http://cacr.uwaterloo.ca/hac/)
- [GMP (GNU Multiple Precision) Library](https://gmplib.org/)

### Cryptographic Padding:
- [RSA-OAEP - Wikipedia](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding)
- [PKCS#1 Standard](https://tools.ietf.org/html/rfc8017)

---

## 💡 Why This Project Exists

### Educational Philosophy:

> "To truly understand a system, you must build it from scratch."

**Learning Goals:**
1. **Demystify cryptography** - Show it's just math and logic
2. **Appreciate libraries** - Understand why we use OpenSSL
3. **Security awareness** - See what can go wrong
4. **Foundation knowledge** - Prepare for advanced topics

**NOT Goals:**
- Replace production libraries
- Provide secure implementations
- Optimize for performance

---

## ⚠️ Security Warning

```
╔══════════════════════════════════════════════════════╗
║                   ⚠️  WARNING  ⚠️                    ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  This code is for EDUCATIONAL purposes ONLY!         ║
║                                                      ║
║  DO NOT use this in production systems because:      ║
║                                                      ║
║  • Keys are too small (easily broken)                ║
║  • No cryptographic padding (insecure)               ║
║  • No side-channel protection (timing attacks)       ║
║  • No secure random number generation                ║
║  • Simplified certificate validation                 ║
║                                                      ║
║  For production, ALWAYS use:                         ║
║  ✓ OpenSSL, LibreSSL, or BoringSSL                  ║
║  ✓ mbedTLS (for embedded systems)                   ║
║  ✓ Crypto libraries audited by experts              ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
```

---

## 🤝 Contributing

This is an educational project. Contributions welcome for:
- Additional security tests
- Better documentation
- More learning exercises
- Bug fixes in demo code

Please note: Do not submit "security fixes" - the insecurity is intentional for educational clarity.

---

## 📝 License

This project is for **educational purposes only**. No warranty provided.

Released under MIT License for maximum educational freedom.

---

## 👨‍💻 Author

Created to teach cryptography fundamentals through hands-on implementation.

**"The best way to learn is to build it yourself!"** 🚀

---

## 🎯 Conclusion

You've now seen:
- ✅ How RSA encryption really works (math level)
- ✅ What's inside an X.509 certificate
- ✅ Why asymmetric encryption is powerful
- ✅ How to detect common attacks
- ✅ Why we need cryptographic libraries

**Next Step:** Study real cryptographic libraries (OpenSSL) and see how they solve the problems you've encountered here!

**Happy Learning! 🎓**