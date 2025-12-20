#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

void print_hex(const unsigned char *data, int len)
{
    printf("   ");
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n   ");
    }
    printf("\n");
}

// Mô phỏng SENDER (người gửi)
int sender_encrypt(const char *plaintext, unsigned char *ciphertext, 
                   const char *recipient_cert_file)
{
    printf("\n=== SENDER SIDE ===\n");
    printf("1. Plaintext message:\n   \"%s\"\n\n", plaintext);
    
    // Load recipient's certificate (public key)
    FILE *fp = fopen(recipient_cert_file, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open certificate file\n");
        return -1;
    }
    
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) {
        fprintf(stderr, "Cannot read X.509 certificate\n");
        return -1;
    }
    
    printf("2. Loaded recipient's X.509 certificate\n");
    
    // Verify certificate (trong thực tế cần verify CA signature, expiry, etc.)
    printf("3. [Should verify certificate here - skipped in demo]\n");
    
    // Extract public key
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    RSA *rsa_pub = EVP_PKEY_get1_RSA(pubkey);
    
    printf("4. Extracted recipient's PUBLIC KEY from certificate\n");
    printf("   RSA key size: %d bits\n\n", RSA_size(rsa_pub) * 8);
    
    // Encrypt with recipient's public key
    int enc_len = RSA_public_encrypt(
        strlen(plaintext),
        (unsigned char *)plaintext,
        ciphertext,
        rsa_pub,
        RSA_PKCS1_PADDING
    );
    
    printf("5. Encrypted message (Ciphertext):\n");
    print_hex(ciphertext, enc_len);
    
    printf("6. Sending ciphertext to recipient...\n");
    
    // Cleanup
    RSA_free(rsa_pub);
    EVP_PKEY_free(pubkey);
    X509_free(cert);
    
    return enc_len;
}

// Mô phỏng RECIPIENT (người nhận)
void recipient_decrypt(unsigned char *ciphertext, int ciphertext_len,
                       const char *private_key_file)
{
    printf("\n=== RECIPIENT SIDE ===\n");
    printf("1. Received ciphertext (%d bytes)\n\n", ciphertext_len);
    
    // Load recipient's private key
    FILE *fp = fopen(private_key_file, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open private key file\n");
        return;
    }
    
    RSA *rsa_priv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!rsa_priv) {
        fprintf(stderr, "Cannot read private key\n");
        return;
    }
    
    printf("2. Loaded recipient's PRIVATE KEY\n");
    printf("   RSA key size: %d bits\n\n", RSA_size(rsa_priv) * 8);
    
    // Decrypt with recipient's private key
    unsigned char decrypted[256];
    int dec_len = RSA_private_decrypt(
        ciphertext_len,
        ciphertext,
        decrypted,
        rsa_priv,
        RSA_PKCS1_PADDING
    );
    
    if (dec_len == -1) {
        fprintf(stderr, "Decryption failed\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa_priv);
        return;
    }
    
    decrypted[dec_len] = '\0';
    
    printf("3. Decrypted message (Plaintext):\n   \"%s\"\n", decrypted);
    
    // Cleanup
    RSA_free(rsa_priv);
}

int main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const char *plaintext = "Hello X.509 RSA!";
    unsigned char ciphertext[256];
    
    // SENDER encrypts with recipient's public key (from certificate)
    int ciphertext_len = sender_encrypt(
        plaintext, 
        ciphertext, 
        "cert.pem"  // Recipient's certificate
    );
    
    if (ciphertext_len == -1) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    
    printf("\n[--- Message transmitted over network ---]\n");
    
    // RECIPIENT decrypts with their private key
    recipient_decrypt(
        ciphertext, 
        ciphertext_len, 
        "private.pem"  // Recipient's private key
    );
    
    printf("Key Points:                                       \n");
    printf("Sender uses RECIPIENT's PUBLIC KEY (from cert)\n");
    printf("Recipient uses their own PRIVATE KEY           \n");
    printf("Different keys encrypt/decrypt (Asymmetric)     \n");
    printf("X.509 cert provides trusted public key          \n");

    
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}