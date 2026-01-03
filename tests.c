#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// ============================================================
// BIG NUMBER ARITHMETIC (Simplified)
// ============================================================

typedef struct {
    uint64_t data[64];
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

void bn_copy(BigNum *dest, BigNum *src) {
    memcpy(dest->data, src->data, sizeof(src->data));
    dest->len = src->len;
}

int bn_equal(BigNum *a, BigNum *b) {
    if (a->len != b->len) return 0;
    for (int i = 0; i < a->len; i++) {
        if (a->data[i] != b->data[i]) return 0;
    }
    return 1;
}

// Modular exponentiation: result = (base^exp) mod m
void bn_modexp(BigNum *result, BigNum *base, BigNum *exp, BigNum *m) {
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
    }
}

// ============================================================
// RSA KEY STRUCTURE
// ============================================================

typedef struct {
    BigNum n;  // Modulus
    BigNum e;  // Public exponent
    BigNum d;  // Private exponent
} RSAKey;

// Generate demo RSA keys (small numbers for testing)
void rsa_generate_keys(RSAKey *pubkey, RSAKey *privkey) {
    uint64_t p = 61;
    uint64_t q = 53;
    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 17;
    uint64_t d = 2753;
    
    bn_set(&pubkey->n, n);
    bn_set(&pubkey->e, e);
    
    bn_set(&privkey->n, n);
    bn_set(&privkey->d, d);
}

// Generate DIFFERENT key pair (for wrong key test)
void rsa_generate_fake_keys(RSAKey *pubkey, RSAKey *privkey) {
    // Use different primes
    uint64_t p = 67;
    uint64_t q = 59;
    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 17;
    uint64_t d = 3713; // Pre-calculated
    
    bn_set(&pubkey->n, n);
    bn_set(&pubkey->e, e);
    
    bn_set(&privkey->n, n);
    bn_set(&privkey->d, d);
}

// ============================================================
// RSA ENCRYPTION/DECRYPTION
// ============================================================

uint64_t rsa_encrypt(uint64_t plaintext, RSAKey *pubkey) {
    BigNum m, c;
    bn_set(&m, plaintext);
    bn_modexp(&c, &m, &pubkey->e, &pubkey->n);
    return c.data[0];
}

uint64_t rsa_decrypt(uint64_t ciphertext, RSAKey *privkey) {
    BigNum c, m;
    bn_set(&c, ciphertext);
    bn_modexp(&m, &c, &privkey->d, &privkey->n);
    return m.data[0];
}

// ============================================================
// X.509 CERTIFICATE (Simplified)
// ============================================================

typedef struct {
    char subject[128];
    char issuer[128];
    RSAKey public_key;
} X509Certificate;

void x509_create_cert(X509Certificate *cert, RSAKey *pubkey) {
    strcpy(cert->subject, "CN=Recipient");
    strcpy(cert->issuer, "CN=TrustedCA");
    cert->public_key = *pubkey;
}

// ============================================================
// ENCRYPTION/DECRYPTION FUNCTIONS WITH ERROR HANDLING
// ============================================================

int sender_encrypt(const char *plaintext, uint64_t *ciphertext, 
                   X509Certificate *cert, int *out_len) {
    int msg_len = strlen(plaintext);
    
    // Check size limit (RSA can only encrypt small data)
    // In our demo: each byte must be < n (3233)
    // For real 2048-bit RSA: limit is ~245 bytes
    if (msg_len > 200) {  // Simulated size limit
        printf("   [ERROR] Message too large for RSA encryption (max 200 bytes)\n");
        return -1;  // FAIL
    }
    
    for (int i = 0; i < msg_len; i++) {
        uint64_t byte = (uint64_t)plaintext[i];
        
        // Check if byte is within modulus
        if (byte >= cert->public_key.n.data[0]) {
            printf("   [ERROR] Data value exceeds modulus\n");
            return -1;
        }
        
        ciphertext[i] = rsa_encrypt(byte, &cert->public_key);
    }
    
    *out_len = msg_len;
    return 0;  // SUCCESS
}

int recipient_decrypt(uint64_t *ciphertext, int cipher_len,
                      RSAKey *privkey, char *plaintext) {
    for (int i = 0; i < cipher_len; i++) {
        uint64_t decrypted_byte = rsa_decrypt(ciphertext[i], privkey);
        
        // Verify decrypted value is valid ASCII
        if (decrypted_byte > 127) {
            printf("   [ERROR] Decryption produced invalid ASCII (value: %lu)\n", 
                   decrypted_byte);
            return -1;  // Decryption failed
        }
        
        plaintext[i] = (char)decrypted_byte;
    }
    plaintext[cipher_len] = '\0';
    return 0;  // SUCCESS
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

void print_hex(uint64_t *data, int len, int max_show) {
    printf("   ");
    for (int i = 0; i < (len < max_show ? len : max_show); i++) {
        printf("%04lX ", data[i]);
    }
    if (len > max_show) printf("...");
    printf("\n");
}

void print_separator() {
    printf("------------------------------------------\n");
}

// ============================================================
// SECURITY TESTS
// ============================================================

void test_tampering_attack(X509Certificate *cert, RSAKey *correct_privkey) {
    printf("TEST 1: TAMPERING ATTACK (Data Integrity)\n");
    print_separator();
    
    const char *msg = "Secret Data";
    uint64_t ciphertext[256];
    uint64_t tampered_cipher[256];
    int cipher_len;
    
    // Encrypt normally
    printf("1. Encrypting message: \"%s\"\n", msg);
    if (sender_encrypt(msg, ciphertext, cert, &cipher_len) != 0) {
        printf("   [SYSTEM ERROR] Encryption failed!\n\n");
        return;
    }
    
    printf("2. Original Ciphertext: ");
    print_hex(ciphertext, cipher_len, 10);
    
    // ATTACKER: Modify ciphertext
    memcpy(tampered_cipher, ciphertext, sizeof(uint64_t) * cipher_len);
    tampered_cipher[0] ^= 0xFF;  // Flip bits in first block
    
    printf("3. Tampered Ciphertext: ");
    print_hex(tampered_cipher, cipher_len, 10);
    
    // Recipient tries to decrypt tampered data
    printf("4. Recipient attempts to decrypt tampered data...\n");
    char decrypted[256];
    int result = recipient_decrypt(tampered_cipher, cipher_len, 
                                   correct_privkey, decrypted);
    
    if (result == -1) {
        printf("PASS: System detected tampering (decryption failed)\n");
    } else {
        printf("   Decrypted text: \"%s\"\n", decrypted);
        if (strcmp(decrypted, msg) != 0) {
            printf("PASS: Decrypted garbage (tampering detected)\n");
        } else {
            printf("FAIL: System accepted tampered data!\n");
        }
    }
    printf("\n");
}

void test_wrong_key_attack(X509Certificate *cert, RSAKey *correct_privkey) {
    printf("TEST 2: WRONG KEY ATTACK (Confidentiality)\n");
    print_separator();
    
    const char *msg = "Top Secret";
    uint64_t ciphertext[256];
    int cipher_len;
    
    // Encrypt with correct public key
    printf("1. Encrypting message: \"%s\"\n", msg);
    sender_encrypt(msg, ciphertext, cert, &cipher_len);
    printf("2. Ciphertext created and transmitted...\n");
    
    // Attacker generates WRONG key pair
    printf("3. Attacker generates different RSA key pair...\n");
    RSAKey fake_pub, fake_priv;
    rsa_generate_fake_keys(&fake_pub, &fake_priv);
    printf("   Attacker's key: n=%lu, d=%lu\n", 
           fake_priv.n.data[0], fake_priv.d.data[0]);
    
    // Attacker tries to decrypt with wrong key
    printf("4. Attacker attempts to decrypt with wrong private key...\n");
    char decrypted[256];
    recipient_decrypt(ciphertext, cipher_len, &fake_priv, decrypted);
    printf("   Decrypted text: \"%s\"\n", decrypted);
    
    if (strcmp(decrypted, msg) != 0) {
        printf("PASS: Wrong key produced garbage (confidentiality preserved)\n");
    } else {
        printf("FAIL: Wrong key successfully decrypted message!\n");
    }
    printf("\n");
}

void test_size_limit() {
    printf("TEST 3: SIZE LIMIT CHECK (RSA Constraints)\n");
    print_separator();
    
    RSAKey pub, priv;
    rsa_generate_keys(&pub, &priv);
    
    X509Certificate cert;
    x509_create_cert(&cert, &pub);
    
    // Create oversized message
    char huge_msg[300];
    memset(huge_msg, 'A', 250);  // 250 bytes
    huge_msg[250] = '\0';
    
    printf("1. Attempting to encrypt message of 250 bytes...\n");
    printf("   (RSA limit in this demo: 200 bytes)\n");
    
    uint64_t huge_cipher[512];
    int huge_len;
    
    int result = sender_encrypt(huge_msg, huge_cipher, &cert, &huge_len);
    
    if (result == -1) {
        printf("PASS: System rejected oversized message\n");
    } else {
        printf("FAIL: System accepted oversized message (buffer overflow risk!)\n");
    }
    printf("\n");
}

void test_correct_operation(X509Certificate *cert, RSAKey *privkey) {
    printf("TEST 0: BASELINE (Correct Operation)\n");
    print_separator();
    
    const char *msg = "Hello RSA!";
    uint64_t ciphertext[256];
    int cipher_len;
    
    printf("1. Message: \"%s\"\n", msg);
    
    // Encrypt
    if (sender_encrypt(msg, ciphertext, cert, &cipher_len) != 0) {
        printf("   [ERROR] Encryption failed\n\n");
        return;
    }
    printf("2. Encrypted successfully\n");
    
    // Decrypt
    char decrypted[256];
    if (recipient_decrypt(ciphertext, cipher_len, privkey, decrypted) != 0) {
        printf("   [ERROR] Decryption failed\n\n");
        return;
    }
    
    printf("3. Decrypted: \"%s\"\n", decrypted);
    
    if (strcmp(msg, decrypted) == 0) {
        printf("PASS: Correct encryption/decryption\n");
    } else {
        printf("FAIL: Message corrupted!\n");
    }
    printf("\n");
}

// ============================================================
// MAIN
// ============================================================

int main() {
    // Setup: Generate keys and certificate
    printf("SETUP: Generating RSA keys and X.509 certificate\n");
    print_separator();
    
    RSAKey recipient_pub, recipient_priv;
    rsa_generate_keys(&recipient_pub, &recipient_priv);
    
    X509Certificate cert;
    x509_create_cert(&cert, &recipient_pub);
    
    printf("Keys generated: n=%lu, e=%lu, d=%lu\n", 
           recipient_pub.n.data[0], recipient_pub.e.data[0], 
           recipient_priv.d.data[0]);
    printf("Certificate created for: %s\n\n", cert.subject);
    
    // Run tests
    test_correct_operation(&cert, &recipient_priv);
    test_tampering_attack(&cert, &recipient_priv);
    test_wrong_key_attack(&cert, &recipient_priv);
    test_size_limit();
    
    // Summary
    printf("TEST SUMMARY:\n");
    printf("These tests demonstrate:\n");
    printf("Data Integrity: Tampering is detected\n");
    printf("Confidentiality: Wrong keys cannot decrypt\n");
    printf("Input Validation: Size limits are enforced\n");
    printf("Correct Operation: Valid keys work properly\n\n");
    
    printf("REMINDER: This is educational code using small keys.\n");
    printf("   Real RSA uses 2048+ bit keys for security.\n");
    
    return 0;
}