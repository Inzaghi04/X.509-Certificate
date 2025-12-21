#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// --- CÁC HÀM TIỆN ÍCH (HELPER) ---

void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < (len > 20 ? 20 : len); i++) printf("%02X ", data[i]);
    if (len > 20) printf("...");
    printf("\n");
}

// Hàm này tạo nhanh một file Private Key giả để test
void create_fake_key_file(const char *filename) {
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bne, NULL);
    
    FILE *fp = fopen(filename, "w");
    PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    
    RSA_free(rsa);
    BN_free(bne);
    printf("   [System] Created temporary fake key file: %s\n", filename);
}

// --- LOGIC GỐC (SENDER/RECIPIENT) ---

int sender_encrypt(const char *plaintext, unsigned char *ciphertext, const char *cert_file) {
    FILE *fp = fopen(cert_file, "r");
    if (!fp) return -1;
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) return -1;

    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    RSA *rsa_pub = EVP_PKEY_get1_RSA(pubkey);
    
    int enc_len = RSA_public_encrypt(strlen(plaintext), (unsigned char *)plaintext, ciphertext, rsa_pub, RSA_PKCS1_PADDING);
    
    RSA_free(rsa_pub);
    EVP_PKEY_free(pubkey);
    X509_free(cert);
    return enc_len;
}

// Hàm decrypt có trả về int (status) để kiểm tra lỗi dễ hơn
int recipient_decrypt_test(unsigned char *ciphertext, int len, const char *key_file) {
    FILE *fp = fopen(key_file, "r");
    if (!fp) return -1;
    RSA *rsa_priv = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    unsigned char decrypted[2048];
    int dec_len = RSA_private_decrypt(len, ciphertext, decrypted, rsa_priv, RSA_PKCS1_PADDING);
    
    RSA_free(rsa_priv);
    
    if (dec_len == -1) {
        // Lấy mã lỗi từ OpenSSL để in ra
        unsigned long err = ERR_get_error();
        char err_msg[120];
        ERR_error_string(err, err_msg);
        printf("   [OpenSSL Error]: %s\n", err_msg);
        return -1; // Thất bại
    }
    return 0; // Thành công
}

// --- MAIN TESTING ---

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("==========================================\n");
    printf("   RSA/X.509 SECURITY & ROBUSTNESS TESTS  \n");
    printf("==========================================\n\n");

    const char *msg = "Secret Data";
    unsigned char ciphertext[256];
    
    // Tạo ciphertext chuẩn ban đầu để dùng cho các bài test
    int len = sender_encrypt(msg, ciphertext, "cert.pem");
    if (len == -1) {
        printf("CRITICAL ERROR: Cannot encrypt initial message. Check cert.pem!\n");
        return 1;
    }

    // ---------------------------------------------------------
    // TEST 1: TAMPERING ATTACK (Sửa đổi dữ liệu trên đường truyền)
    // ---------------------------------------------------------
    printf("TEST 1: TAMPERING ATTACK (Data Integrity)\n");
    printf("-----------------------------------------\n");
    printf("1. Original Ciphertext (first bytes): ");
    print_hex(ciphertext, len);
    
    // Hacker sửa đổi byte đầu tiên
    ciphertext[0] ^= 0xFF; 
    printf("2. Modified Ciphertext (HACKED):      ");
    print_hex(ciphertext, len);
    
    printf("3. Recipient attempts to decrypt...\n");
    if (recipient_decrypt_test(ciphertext, len, "private.pem") == -1) {
        printf(">>> RESULT: PASS (System detected tampering and refused decryption)\n");
    } else {
        printf(">>> RESULT: FAIL (System accepted corrupted data!)\n");
    }
    printf("\n");

    // Khôi phục lại ciphertext chuẩn cho test sau
    ciphertext[0] ^= 0xFF; 

    // ---------------------------------------------------------
    // TEST 2: WRONG KEY ATTACK (Dùng sai khóa để giải mã)
    // ---------------------------------------------------------
    printf("TEST 2: WRONG KEY ATTACK (Confidentiality)\n");
    printf("------------------------------------------\n");
    // Tạo file khóa giả
    create_fake_key_file("fake_key.pem");
    
    printf("1. Attacker tries to decrypt using 'fake_key.pem'...\n");
    if (recipient_decrypt_test(ciphertext, len, "fake_key.pem") == -1) {
        printf(">>> RESULT: PASS (Wrong key could not decrypt message)\n");
    } else {
        printf(">>> RESULT: FAIL (Wrong key successfully decrypted message!)\n");
    }
    // Xóa file tạm
    remove("fake_key.pem");
    printf("\n");

    // ---------------------------------------------------------
    // TEST 3: SIZE LIMIT CHECK (Giới hạn kích thước RSA)
    // ---------------------------------------------------------
    printf("TEST 3: SIZE LIMIT CHECK (RSA Constraints)\n");
    printf("------------------------------------------\n");
    
    // Tạo message cực lớn (300 bytes > 256 bytes key size)
    char huge_msg[300];
    memset(huge_msg, 'A', 299);
    huge_msg[299] = '\0';
    
    printf("1. Sender tries to encrypt 299 bytes (RSA 2048 limit is ~245 bytes)...\n");
    
    unsigned char huge_cipher[512];
    int huge_len = sender_encrypt(huge_msg, huge_cipher, "cert.pem");
    
    if (huge_len == -1) {
        unsigned long err = ERR_get_error();
        char err_msg[120];
        ERR_error_string(err, err_msg);
        printf("   [OpenSSL Error]: %s\n", err_msg);
        printf(">>> RESULT: PASS (System prevented encrypting oversized data)\n");
    } else {
        printf(">>> RESULT: FAIL (System allowed oversized data - likely buffer overflow!)\n");
    }

    printf("\n==========================================\n");
    printf("   END OF TESTS\n");
    
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}