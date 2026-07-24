#include "aes_c.h"
#include "aes_file.h"
#include "aes_keygen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FAILED(msg) do { printf("Failed: %s\n", msg); return 1; } while(0)

static int test_ecb() {
    uint8_t key_128[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                           0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t expected[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                            0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key_128, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_encrypt(&ctx, plaintext, 16, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &out_size);
    if (!ciphertext || out_size != 16) TEST_FAILED("aes_encrypt");
    
    for (i = 0; i < 16; ++i) {
        if (ciphertext[i] != expected[i]) {
            printf("ECB ciphertext mismatch at %d: 0x%02X vs 0x%02X\n", i, ciphertext[i], expected[i]);
            free(ciphertext);
            aes_free(&ctx);
            return 1;
        }
    }
    
    decrypted = aes_decrypt(&ctx, ciphertext, 16, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &out_size);
    if (!decrypted || out_size != 16) TEST_FAILED("aes_decrypt");
    
    for (i = 0; i < 16; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("ECB decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_cbc() {
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plaintext[32] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                             0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                             0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                             0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_encrypt(&ctx, plaintext, 32, AES_MODE_CBC, AES_PADDING_NONE, iv, 16, &out_size);
    if (!ciphertext || out_size != 32) TEST_FAILED("aes_cbc_encrypt");
    
    decrypted = aes_decrypt(&ctx, ciphertext, 32, AES_MODE_CBC, AES_PADDING_NONE, iv, 16, &out_size);
    if (!decrypted || out_size != 32) TEST_FAILED("aes_cbc_decrypt");
    
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("CBC decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_ctr() {
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
                      0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
    uint8_t plaintext[32] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                             0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                             0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                             0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_encrypt(&ctx, plaintext, 32, AES_MODE_CTR, AES_PADDING_NONE, iv, 16, &out_size);
    if (!ciphertext || out_size != 32) TEST_FAILED("aes_ctr_encrypt");
    
    decrypted = aes_decrypt(&ctx, ciphertext, 32, AES_MODE_CTR, AES_PADDING_NONE, iv, 16, &out_size);
    if (!decrypted || out_size != 32) TEST_FAILED("aes_ctr_decrypt");
    
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("CTR decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_ofb() {
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plaintext[32] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                             0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                             0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                             0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_encrypt(&ctx, plaintext, 32, AES_MODE_OFB, AES_PADDING_NONE, iv, 16, &out_size);
    if (!ciphertext || out_size != 32) TEST_FAILED("aes_ofb_encrypt");
    
    decrypted = aes_decrypt(&ctx, ciphertext, 32, AES_MODE_OFB, AES_PADDING_NONE, iv, 16, &out_size);
    if (!decrypted || out_size != 32) TEST_FAILED("aes_ofb_decrypt");
    
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("OFB decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_cfb8() {
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plaintext[32] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                             0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                             0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                             0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_encrypt(&ctx, plaintext, 32, AES_MODE_CFB8, AES_PADDING_NONE, iv, 16, &out_size);
    if (!ciphertext || out_size != 32) TEST_FAILED("aes_cfb8_encrypt");
    
    decrypted = aes_decrypt(&ctx, ciphertext, 32, AES_MODE_CFB8, AES_PADDING_NONE, iv, 16, &out_size);
    if (!decrypted || out_size != 32) TEST_FAILED("aes_cfb8_decrypt");
    
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("CFB8 decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_cfb128() {
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t plaintext[32] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                             0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                             0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                             0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_encrypt(&ctx, plaintext, 32, AES_MODE_CFB128, AES_PADDING_NONE, iv, 16, &out_size);
    if (!ciphertext || out_size != 32) TEST_FAILED("aes_cfb128_encrypt");
    
    decrypted = aes_decrypt(&ctx, ciphertext, 32, AES_MODE_CFB128, AES_PADDING_NONE, iv, 16, &out_size);
    if (!decrypted || out_size != 32) TEST_FAILED("aes_cfb128_decrypt");
    
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("CFB128 decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_gcm() {
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t nonce[12] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                         0x00,0x00,0x00,0x01};
    uint8_t plaintext[32] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                             0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                             0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                             0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    uint8_t aad[16] = {0};
    uint8_t expected_tag[16] = {0x97,0x15,0x0d,0xab,0x5a,0xc1,0x8a,0xa8,
                                0x2e,0x2e,0x46,0x68,0x27,0x22,0x81,0x09};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    uint8_t tag[16];
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_gcm_encrypt(&ctx, plaintext, 32, nonce, 12, aad, 16, tag, 16, &out_size);
    if (!ciphertext || out_size != 32) TEST_FAILED("aes_gcm_encrypt");
    
    for (i = 0; i < 16; ++i) {
        if (tag[i] != expected_tag[i]) {
            printf("GCM tag mismatch at %d: 0x%02X vs 0x%02X\n", i, tag[i], expected_tag[i]);
            free(ciphertext);
            aes_free(&ctx);
            return 1;
        }
    }
    
    decrypted = aes_gcm_decrypt(&ctx, ciphertext, 32, nonce, 12, aad, 16, tag, 16, &out_size);
    if (!decrypted || out_size != 32) TEST_FAILED("aes_gcm_decrypt");
    
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("GCM decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_ccm() {
    uint8_t key[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
                       0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f};
    uint8_t nonce[11] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                         0x18,0x19,0x1a};
    uint8_t plaintext[32] = {0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
                             0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
                             0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                             0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f};
    uint8_t aad[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    uint8_t tag[16];
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_ccm_encrypt(&ctx, plaintext, 32, nonce, 11, aad, 16, tag, 16, &out_size);
    if (!ciphertext || out_size != 32) TEST_FAILED("aes_ccm_encrypt");
    
    decrypted = aes_ccm_decrypt(&ctx, ciphertext, 32, nonce, 11, aad, 16, tag, 16, &out_size);
    if (!decrypted || out_size != 32) TEST_FAILED("aes_ccm_decrypt");
    
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("CCM decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_padding() {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t plaintext[20] = "Hello World!";
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    ciphertext = aes_encrypt(&ctx, plaintext, 12, AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &out_size);
    if (!ciphertext || out_size != 16) TEST_FAILED("aes_cbc_encrypt_padding");
    
    decrypted = aes_decrypt(&ctx, ciphertext, 16, AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &out_size);
    if (!decrypted || out_size != 12) TEST_FAILED("aes_cbc_decrypt_padding");
    
    for (i = 0; i < 12; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("Padding decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return 1;
        }
    }
    
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    return 0;
}

static int test_keygen() {
    uint8_t* key;
    uint8_t* iv;
    
    key = aes_generate_key(32);
    if (!key) TEST_FAILED("aes_generate_key");
    free(key);
    
    iv = aes_generate_iv(16);
    if (!iv) TEST_FAILED("aes_generate_iv");
    free(iv);
    
    return 0;
}

static int test_file_encrypt_decrypt() {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
    uint8_t plaintext[100000];
    uint8_t decrypted[100000];
    FILE* fp;
    AES_Context ctx;
    int i;
    
    for (i = 0; i < 100000; ++i) {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }
    
    fp = fopen("test_plain.txt", "wb");
    if (!fp) TEST_FAILED("fopen test_plain.txt");
    fwrite(plaintext, 1, 100000, fp);
    fclose(fp);
    
    if (aes_init(&ctx, AES_128, key, 16, NULL, 0) != 0) TEST_FAILED("aes_init");
    
    if (aes_encrypt_file(&ctx, "test_plain.txt", "test_encrypted.bin",
                         AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16) != 0) {
        remove("test_plain.txt");
        TEST_FAILED("aes_encrypt_file");
    }
    
    if (aes_decrypt_file(&ctx, "test_encrypted.bin", "test_decrypted.txt",
                         AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16) != 0) {
        remove("test_plain.txt");
        remove("test_encrypted.bin");
        TEST_FAILED("aes_decrypt_file");
    }
    
    aes_free(&ctx);
    
    fp = fopen("test_decrypted.txt", "rb");
    if (!fp) {
        remove("test_plain.txt");
        remove("test_encrypted.bin");
        TEST_FAILED("fopen test_decrypted.txt");
    }
    fread(decrypted, 1, 100000, fp);
    fclose(fp);
    
    for (i = 0; i < 100000; ++i) {
        if (decrypted[i] != plaintext[i]) {
            printf("File decrypt mismatch at %d: 0x%02X vs 0x%02X\n", i, decrypted[i], plaintext[i]);
            remove("test_plain.txt");
            remove("test_encrypted.bin");
            remove("test_decrypted.txt");
            return 1;
        }
    }
    
    remove("test_plain.txt");
    remove("test_encrypted.bin");
    remove("test_decrypted.txt");
    
    return 0;
}

int main() {
    printf("Running AES self-test...\n\n");
    
    printf("Test ECB... ");
    if (test_ecb() != 0) return 1;
    printf("passed!\n");
    
    printf("Test CBC... ");
    if (test_cbc() != 0) return 1;
    printf("passed!\n");
    
    printf("Test CTR... ");
    if (test_ctr() != 0) return 1;
    printf("passed!\n");
    
    printf("Test OFB... ");
    if (test_ofb() != 0) return 1;
    printf("passed!\n");
    
    printf("Test CFB8... ");
    if (test_cfb8() != 0) return 1;
    printf("passed!\n");
    
    printf("Test CFB128... ");
    if (test_cfb128() != 0) return 1;
    printf("passed!\n");
    
    printf("Test GCM... ");
    if (test_gcm() != 0) return 1;
    printf("passed!\n");
    
    printf("Test CCM... ");
    if (test_ccm() != 0) return 1;
    printf("passed!\n");
    
    printf("Test Padding... ");
    if (test_padding() != 0) return 1;
    printf("passed!\n");
    
    printf("Test Keygen... ");
    if (test_keygen() != 0) return 1;
    printf("passed!\n");
    
    printf("Test File Encrypt/Decrypt... ");
    if (test_file_encrypt_decrypt() != 0) return 1;
    printf("passed!\n");
    
    printf("\nAll %d tests passed!\n", 11);
    return 0;
}