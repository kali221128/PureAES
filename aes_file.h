#ifndef AES_FILE_H
#define AES_FILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "aes_c.h"

int aes_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                     AES_Mode mode, AES_Padding padding, const uint8_t* iv, size_t iv_size);

int aes_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                     AES_Mode mode, AES_Padding padding, const uint8_t* iv, size_t iv_size);

int aes_gcm_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t* tag_size);

int aes_gcm_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size);

int aes_ccm_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t* tag_size);

int aes_ccm_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size);

int aes_ecb_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         AES_Padding padding);

int aes_ecb_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         AES_Padding padding);

int aes_cbc_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size, AES_Padding padding);

int aes_cbc_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size, AES_Padding padding);

int aes_cfb8_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                          const uint8_t* iv, size_t iv_size);

int aes_cfb8_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                          const uint8_t* iv, size_t iv_size);

int aes_cfb128_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                            const uint8_t* iv, size_t iv_size, AES_Padding padding);

int aes_cfb128_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                            const uint8_t* iv, size_t iv_size, AES_Padding padding);

int aes_ofb_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size);

int aes_ofb_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size);

int aes_ctr_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size);

int aes_ctr_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size);

int aes_secure_delete_file(const char* filename, int passes);

int aes_zero_fill_delete_file(const char* filename);

#ifdef __cplusplus
}
#endif

#endif