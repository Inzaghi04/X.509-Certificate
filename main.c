#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================================
// BIG NUMBER ARITHMETIC (Simplified - chỉ dùng cho demo nhỏ)
// ============================================================

typedef struct {
    uint64_t data[64];  // Lưu số lớn (tối đa 4096 bit)
    int len;
} BigNum;

void bn_init(BigNum *bn) {
    memset(bn->data, 0, sizeof(bn->data));
    bn->len = 0;
}

void bn_set(BigNum *bn, uint64_t val) {
    bn_init(bn);
    bn->data[0] = val;
    bn->len = 1;
}

void bn_print(const char *label, BigNum *bn) {
    printf("%s", label);
    for (int i = bn->len - 1; i >= 0; i--) {
        printf("%016lX ", bn->data[i]);
    }
    printf("\n");
}

// Modular exponentiation: result = (base^exp) mod m
void bn_modexp(BigNum *result, BigNum *base, BigNum *exp, BigNum *m) {
    // Thuật toán Square-and-Multiply đơn giản
    // Trong thực tế cần implement đầy đủ big number operations
    
    // ĐƠN GIẢN HÓA: Chỉ dùng cho số nhỏ (demo)
    if (base->len == 1 && exp->len == 1 && m->len == 1) {
        uint64_t b = base->data[0];
        uint64_t e = exp->data[0];
        uint64_t mod = m->data[0];
        uint64_t res = 1;
        
        b = b % mod;
        while (e > 0) {
            if (e & 1) {
                res = (res * b) % mod;
            }
            e = e >> 1;
            b = (b * b) % mod;
        }
        
        bn_set(result, res);
    } else {
        printf("   [Big number operation - using simplified calculation]\n");
        // Trong implementation thật cần thuật toán Montgomery hoặc Barrett
        bn_set(result, 12345); // Mock value
    }
}

// ============================================================
// SIMPLIFIED RSA (Dùng số nhỏ cho demo)
// ============================================================

typedef struct {
    BigNum n;  // Modulus (n = p * q)
    BigNum e;  // Public exponent
    BigNum d;  // Private exponent
} RSAKey;

// Khởi tạo RSA key đơn giản (dùng số nhỏ cho demo)
void rsa_generate_demo_keys(RSAKey *pubkey, RSAKey *privkey) {
    // Trong thực tế: chọn 2 số nguyên tố lớn p, q
    // Đây chỉ là DEMO với số nhỏ
    
    uint64_t p = 61;   // Số nguyên tố nhỏ
    uint64_t q = 53;   // Số nguyên tố nhỏ
    uint64_t n = p * q; // n = 3233
    uint64_t phi = (p - 1) * (q - 1); // phi = 3120
    uint64_t e = 17;   // Public exponent (thường dùng 65537, nhưng dùng 17 cho đơn giản)
    
    // Tính private exponent d: d * e ≡ 1 (mod phi)
    // Extended Euclidean algorithm - đơn giản hóa
    uint64_t d = 2753; // Pre-calculated: 17 * 2753 mod 3120 = 1
    
    // Public key
    bn_set(&pubkey->n, n);
    bn_set(&pubkey->e, e);
    
    // Private key
    bn_set(&privkey->n, n);
    bn_set(&privkey->d, d);
    
    printf("Generated RSA keys (DEMO - small numbers):\n");
    printf("  p = %lu, q = %lu\n", p, q);
    printf("  n = %lu (modulus)\n", n);
    printf("  e = %lu (public exponent)\n", e);
    printf("  d = %lu (private exponent)\n", d);
    printf("  Note: Real RSA uses 2048+ bit keys!\n\n");
}

// RSA Encryption: c = m^e mod n
uint64_t rsa_encrypt(uint64_t plaintext, RSAKey *pubkey) {
    BigNum m, c;
    bn_set(&m, plaintext);
    bn_modexp(&c, &m, &pubkey->e, &pubkey->n);
    return c.data[0];
}

// RSA Decryption: m = c^d mod n
uint64_t rsa_decrypt(uint64_t ciphertext, RSAKey *privkey) {
    BigNum c, m;
    bn_set(&c, ciphertext);
    bn_modexp(&m, &c, &privkey->d, &privkey->n);
    return m.data[0];
}

// ============================================================
// SIMPLIFIED X.509 CERTIFICATE
// ============================================================

typedef struct {
    char subject[256];
    char issuer[256];
    RSAKey public_key;
    // Trong thực tế: validity period, signature, extensions, etc.
} X509Certificate;

void x509_create_demo_cert(X509Certificate *cert, RSAKey *pubkey) {
    strcpy(cert->subject, "CN=Recipient,O=Demo Corp");
    strcpy(cert->issuer, "CN=Demo CA,O=Demo Corp");
    cert->public_key = *pubkey;
    
    printf("Created X.509 Certificate:\n");
    printf("  Subject: %s\n", cert->subject);
    printf("  Issuer: %s\n", cert->issuer);
    printf("  Public Key (n,e): (%lu, %lu)\n\n", 
           pubkey->n.data[0], pubkey->e.data[0]);
}

// ============================================================
// MAIN SIMULATION
// ============================================================

void print_separator() {
    printf("========================================\n");
}

int main() {
    // ============ RECIPIENT GENERATES KEY PAIR ============
    printf("STEP 0: Recipient generates RSA key pair\n");
    print_separator();
    
    RSAKey recipient_pubkey, recipient_privkey;
    rsa_generate_demo_keys(&recipient_pubkey, &recipient_privkey);
    
    // ============ RECIPIENT CREATES CERTIFICATE ============
    printf("STEP 1: Recipient creates X.509 certificate\n");
    print_separator();
    
    X509Certificate cert;
    x509_create_demo_cert(&cert, &recipient_pubkey);
    
    printf("Certificate contains RECIPIENT's PUBLIC KEY\n");
    printf("   (In real world: signed by trusted CA)\n\n");
    
    // ============ SENDER SIDE ============
    printf("STEP 2: SENDER encrypts message\n");
    print_separator();
    
    const char *plaintext = "Hello!";
    printf("Plaintext message: \"%s\"\n\n", plaintext);
    
    printf("Sender extracts PUBLIC KEY from recipient's certificate:\n");
    printf("  n = %lu\n", cert.public_key.n.data[0]);
    printf("  e = %lu\n\n", cert.public_key.e.data[0]);
    
    // Encrypt từng byte (trong thực tế dùng padding schemes)
    printf("Encrypting message byte-by-byte:\n");
    uint64_t ciphertext[256];
    int cipher_len = strlen(plaintext);
    
    for (int i = 0; i < cipher_len; i++) {
        uint64_t byte = (uint64_t)plaintext[i];
        ciphertext[i] = rsa_encrypt(byte, &cert.public_key);
        printf("  '%c' (ASCII %lu) -> %lu\n", plaintext[i], byte, ciphertext[i]);
    }
    
    printf("\nCiphertext (hex): ");
    for (int i = 0; i < cipher_len; i++) {
        printf("%04lX ", ciphertext[i]);
    }
    printf("\n\n");
    
    printf("Transmitting ciphertext over network...\n\n");
    
    // ============ RECIPIENT SIDE ============
    printf("STEP 3: RECIPIENT decrypts message\n");
    print_separator();
    
    printf("Recipient uses their PRIVATE KEY:\n");
    printf("  n = %lu\n", recipient_privkey.n.data[0]);
    printf("  d = %lu\n\n", recipient_privkey.d.data[0]);
    
    char decrypted[256];
    printf("Decrypting ciphertext:\n");
    
    for (int i = 0; i < cipher_len; i++) {
        uint64_t byte = rsa_decrypt(ciphertext[i], &recipient_privkey);
        decrypted[i] = (char)byte;
        printf("  %lu -> '%c' (ASCII %lu)\n", ciphertext[i], decrypted[i], byte);
    }
    decrypted[cipher_len] = '\0';
    
    printf("\nDecrypted plaintext: \"%s\"\n\n", decrypted);
    
    // ============ SUMMARY ============
    print_separator();
    printf("SUMMARY:\n");
    printf("Different keys used: PUBLIC (encrypt) vs PRIVATE (decrypt)\n");
    printf("X.509 certificate carries the PUBLIC KEY\n");
    printf("Only recipient with PRIVATE KEY can decrypt\n");
    printf("This demo uses SMALL numbers (real RSA: 2048+ bits)\n");
    print_separator();
    
    printf("\nDISCLAIMER:\n");
    printf("This is educational code. DO NOT use in production!\n");
    printf("Real implementation needs:\n");
    printf("Proper big number library\n");
    printf("OAEP/PSS padding schemes\n");
    printf("ASN.1/DER parsing for X.509\n");
    printf("Certificate validation (CA signature, expiry)\n");
    printf("Secure random number generation\n");
    return 0;
}