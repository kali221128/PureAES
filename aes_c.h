#ifndef AES_C_H
#define AES_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define BLOCK_SIZE 16

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
#else
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#include <stdint.h>
#else
#if defined(__GNUC__)
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;
#endif
#endif
#endif

typedef enum {
    AES_MODE_ECB = 0,
    AES_MODE_CBC = 1,
    AES_MODE_CFB8 = 2,
    AES_MODE_CFB128 = 3,
    AES_MODE_OFB = 4,
    AES_MODE_CTR = 5,
    AES_MODE_GCM = 6,
    AES_MODE_CCM = 7,
    AES_MODE_XTS = 8
} AES_Mode;

typedef enum {
    AES_PADDING_NONE = 0,
    AES_PADDING_ZERO = 1,
    AES_PADDING_PKCS5 = 2,
    AES_PADDING_PKCS7 = 3,
    AES_PADDING_ANSIX923 = 4,
    AES_PADDING_ISO10126 = 5,
    AES_PADDING_ISO7816 = 6
} AES_Padding;

typedef enum {
    AES_128 = 16,
    AES_192 = 24,
    AES_256 = 32
} AES_KeyLength;

typedef enum {
    AES_KEY_RAW = 0,
    AES_KEY_HEX = 1,
    AES_KEY_BASE64 = 2
} AES_KeyType;

/* 硬件能力标志位 */
#define AES_HW_NONE      0x00000000
#define AES_HW_NI        0x00000001  /* x86 AES-NI (CPUID.01H:ECX.AESNI[bit25] = 1) */
#define AES_HW_PCLMUL    0x00000002  /* x86 PCLMULQDQ (用于 GCM/GMAC 硬件加速) */
#define AES_HW_NEON      0x00000004  /* ARMv8 NEON AES Extension (__ARM_FEATURE_AES) */

typedef struct {
    int Nk;
    int Nr;
    uint8_t* w;           /* 原始轮密钥 (key expansion 结果), 加密直接用 */
    uint8_t* dw;          /* AES-NI 专用解密等效轮密钥 (rk[1..Nr-1] 经 InvMixColumns), 可选 */
    uint32_t hw_flags;    /* 硬件加速能力 (AES_HW_*) */
    AES_KeyLength key_len;
    uint8_t iv[16];
    int iv_set;
} AES_Context;

typedef struct {
    AES_Context* ctx;
    AES_Mode mode;
    AES_Padding padding;
    uint8_t iv[16];
    uint8_t feedback[16];
    uint8_t counter[16];
    uint8_t counter_0[16];
    uint8_t buffer[16];
    size_t buffer_len;
    size_t total_bytes;
    /* 解密时暂存最后一个已解密块，用于 finish 时去填充 */
    uint8_t last_decrypted[16];
    int has_last_decrypted;
    
    uint8_t gcm_h[16];
    uint8_t gcm_x[16];
    size_t gcm_aad_len;
    size_t gcm_data_len;
    
    uint8_t ccm_mac[16];
    size_t ccm_total_len;
    
    int is_encrypt;
} AES_StreamContext;

int aes_init(AES_Context* ctx, AES_KeyLength key_len, const uint8_t* key, size_t key_size,
             const uint8_t* iv, size_t iv_size);

int aes_init_with_key_string(AES_Context* ctx, AES_KeyLength key_len, const char* key_str,
                             AES_KeyType key_type, const char* iv_str, AES_KeyType iv_type);

void aes_free(AES_Context* ctx);

uint8_t* aes_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                     AES_Mode mode, AES_Padding padding,
                     const uint8_t* iv, size_t iv_size, size_t* out_size);

uint8_t* aes_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                     AES_Mode mode, AES_Padding padding,
                     const uint8_t* iv, size_t iv_size, size_t* out_size);

uint8_t* aes_gcm_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t tag_size, size_t* out_size);

uint8_t* aes_gcm_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size, size_t* out_size);

uint8_t* aes_ccm_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t tag_size, size_t* out_size);

uint8_t* aes_ccm_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size, size_t* out_size);

char* aes_bytes_to_hex(const uint8_t* data, size_t size);

uint8_t* aes_hex_to_bytes(const char* hex, size_t* out_size);

int aes_self_test(void);

int aes_stream_init(AES_StreamContext* sctx, AES_Context* ctx, AES_Mode mode, AES_Padding padding,
                    const uint8_t* iv, size_t iv_size, int is_encrypt);

int aes_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                      uint8_t* out, size_t* out_size);

int aes_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size);

void aes_stream_free(AES_StreamContext* sctx);

int aes_gcm_stream_init(AES_StreamContext* sctx, AES_Context* ctx,
                        const uint8_t* nonce, size_t nonce_size,
                        const uint8_t* aad, size_t aad_size, int is_encrypt);

int aes_gcm_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                          uint8_t* out, size_t* out_size);

int aes_gcm_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size,
                          uint8_t* tag, size_t* tag_size);

int aes_ccm_stream_init(AES_StreamContext* sctx, AES_Context* ctx,
                        const uint8_t* nonce, size_t nonce_size,
                        const uint8_t* aad, size_t aad_size,
                        size_t total_len, int is_encrypt);

int aes_ccm_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                          uint8_t* out, size_t* out_size);

int aes_ccm_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size,
                          uint8_t* tag, size_t* tag_size);

/* XTS mode (NIST SP 800-38E).
 * ctx      : 主 key (AES-128/192/256, Nk = 4/6/8)
 * tweak_key: XTS 第二把 key, 长度须 = 主 key; NULL 时使用 ctx 同一 key (XTS single-key)
 * tweak    : 128-bit tweak 值, 通常由 nonce || sector_number 组成
 * tweak_size: 通常 16
 */
uint8_t* aes_xts_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* tweak_key, const uint8_t* tweak, size_t tweak_size,
                         size_t* out_size);

uint8_t* aes_xts_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* tweak_key, const uint8_t* tweak, size_t tweak_size,
                         size_t* out_size);

#ifdef __cplusplus
}
#endif

#endif