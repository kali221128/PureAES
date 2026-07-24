#include "aes_c.h"
#include "hex_convert.h"
#include "base64_convert.h"
#include "aes_keygen.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define BLOCK_SIZE 16
#define Nb 4

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit;
    int i;
    for (i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static int KeyExpansion(AES_Context* ctx, const uint8_t* key) {
    int key_len, w_size, i;
    uint8_t temp[4];
    uint8_t t;
    
    if (ctx->w) free(ctx->w);
    ctx->w = NULL;
    
    key_len = (int)ctx->key_len;
    ctx->Nk = key_len / 4;
    ctx->Nr = ctx->Nk + 6;
    
    w_size = Nb * (ctx->Nr + 1) * 4;
    ctx->w = (uint8_t*)malloc(w_size);
    if (!ctx->w) {
        return -1;
    }
    
    i = 0;
    while (i < ctx->Nk) {
        ctx->w[4 * i] = key[4 * i];
        ctx->w[4 * i + 1] = key[4 * i + 1];
        ctx->w[4 * i + 2] = key[4 * i + 2];
        ctx->w[4 * i + 3] = key[4 * i + 3];
        ++i;
    }
    
    i = ctx->Nk;
    while (i < Nb * (ctx->Nr + 1)) {
        temp[0] = ctx->w[4 * (i - 1) + 0];
        temp[1] = ctx->w[4 * (i - 1) + 1];
        temp[2] = ctx->w[4 * (i - 1) + 2];
        temp[3] = ctx->w[4 * (i - 1) + 3];
        
        if (i % ctx->Nk == 0) {
            t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            
            temp[0] ^= Rcon[i / ctx->Nk];
        } else if (ctx->Nk > 6 && i % ctx->Nk == 4) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }
        
        ctx->w[4 * i + 0] = ctx->w[4 * (i - ctx->Nk) + 0] ^ temp[0];
        ctx->w[4 * i + 1] = ctx->w[4 * (i - ctx->Nk) + 1] ^ temp[1];
        ctx->w[4 * i + 2] = ctx->w[4 * (i - ctx->Nk) + 2] ^ temp[2];
        ctx->w[4 * i + 3] = ctx->w[4 * (i - ctx->Nk) + 3] ^ temp[3];
        ++i;
    }
    
    return 0;
}

static void AddRoundKey(uint8_t* state, const uint8_t* w, int round) {
    int i;
    for (i = 0; i < 16; ++i) {
        state[i] ^= w[round * 16 + i];
    }
}

static void SubBytes(uint8_t* state) {
    int i;
    for (i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

static void InvSubBytes(uint8_t* state) {
    int i;
    for (i = 0; i < 16; ++i) {
        state[i] = inv_sbox[state[i]];
    }
}

static void ShiftRows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void InvShiftRows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    temp = state[10];
    state[10] = state[2];
    state[2] = temp;
    temp = state[14];
    state[14] = state[6];
    state[6] = temp;
    
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

static void MixColumns(uint8_t* state) {
    uint8_t temp[16];
    int col, base;
    for (col = 0; col < 4; ++col) {
        base = col * 4;
        temp[base] = gf_mult(0x02, state[base]) ^ gf_mult(0x03, state[base + 1]) ^ state[base + 2] ^ state[base + 3];
        temp[base + 1] = state[base] ^ gf_mult(0x02, state[base + 1]) ^ gf_mult(0x03, state[base + 2]) ^ state[base + 3];
        temp[base + 2] = state[base] ^ state[base + 1] ^ gf_mult(0x02, state[base + 2]) ^ gf_mult(0x03, state[base + 3]);
        temp[base + 3] = gf_mult(0x03, state[base]) ^ state[base + 1] ^ state[base + 2] ^ gf_mult(0x02, state[base + 3]);
    }
    memcpy(state, temp, 16);
}

static void InvMixColumns(uint8_t* state) {
    uint8_t temp[16];
    int col, base;
    for (col = 0; col < 4; ++col) {
        base = col * 4;
        temp[base] = gf_mult(0x0e, state[base]) ^ gf_mult(0x0b, state[base + 1]) ^ gf_mult(0x0d, state[base + 2]) ^ gf_mult(0x09, state[base + 3]);
        temp[base + 1] = gf_mult(0x09, state[base]) ^ gf_mult(0x0e, state[base + 1]) ^ gf_mult(0x0b, state[base + 2]) ^ gf_mult(0x0d, state[base + 3]);
        temp[base + 2] = gf_mult(0x0d, state[base]) ^ gf_mult(0x09, state[base + 1]) ^ gf_mult(0x0e, state[base + 2]) ^ gf_mult(0x0b, state[base + 3]);
        temp[base + 3] = gf_mult(0x0b, state[base]) ^ gf_mult(0x0d, state[base + 1]) ^ gf_mult(0x09, state[base + 2]) ^ gf_mult(0x0e, state[base + 3]);
    }
    memcpy(state, temp, 16);
}

static void Cipher(const uint8_t* w, int Nr, const uint8_t* in, uint8_t* out) {
    uint8_t state[16];
    int round;
    memcpy(state, in, 16);
    
    AddRoundKey(state, w, 0);
    
    for (round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w, round);
    }
    
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w, Nr);
    
    memcpy(out, state, 16);
}

static void InvCipher(const uint8_t* w, int Nr, const uint8_t* in, uint8_t* out) {
    uint8_t state[16];
    int round;
    memcpy(state, in, 16);
    
    AddRoundKey(state, w, Nr);
    
    for (round = Nr - 1; round > 0; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w, round);
        InvMixColumns(state);
    }
    
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, w, 0);
    
    memcpy(out, state, 16);
}

static uint8_t* pad(const uint8_t* data, size_t size, AES_Padding padding, size_t* out_size) {
    size_t block_size, padding_len;
    uint8_t* padded;
    size_t i;
    
    block_size = BLOCK_SIZE;
    
    if (padding == AES_PADDING_NONE) {
        *out_size = size;
        padded = (uint8_t*)malloc(*out_size);
        if (!padded) {
            *out_size = 0;
            return NULL;
        }
        memcpy(padded, data, size);
        return padded;
    }
    
    padding_len = block_size - (size % block_size);
    
    if (padding_len == 0) {
        padding_len = block_size;
    }
    
    *out_size = size + padding_len;
    padded = (uint8_t*)malloc(*out_size);
    if (!padded) {
        *out_size = 0;
        return NULL;
    }
    memcpy(padded, data, size);
    
    switch (padding) {
        case AES_PADDING_NONE:
            break;
        case AES_PADDING_ZERO:
            memset(padded + size, 0, padding_len);
            break;
        case AES_PADDING_PKCS5:
        case AES_PADDING_PKCS7:
            for (i = 0; i < padding_len; ++i) {
                padded[size + i] = (uint8_t)padding_len;
            }
            break;
        case AES_PADDING_ANSIX923:
            memset(padded + size, 0, padding_len - 1);
            padded[size + padding_len - 1] = (uint8_t)padding_len;
            break;
        case AES_PADDING_ISO10126:
            if (padding_len > 1) {
                aes_random_bytes(padded + size, padding_len - 1);
            }
            padded[size + padding_len - 1] = (uint8_t)padding_len;
            break;
        case AES_PADDING_ISO7816:
            padded[size] = 0x80;
            memset(padded + size + 1, 0, padding_len - 1);
            break;
    }
    
    return padded;
}

static uint8_t* unpad(const uint8_t* data, size_t size, AES_Padding padding, size_t* out_size) {
    size_t padding_len;
    uint8_t last_byte;
    uint8_t* result;
    int i, j;
    
    if (size == 0 || size % BLOCK_SIZE != 0) {
        *out_size = 0;
        return NULL;
    }
    
    padding_len = 0;
    
    switch (padding) {
        case AES_PADDING_NONE:
            *out_size = size;
            break;
        case AES_PADDING_ZERO:
            padding_len = 0;
            for (i = (int)size - 1; i >= 0; --i) {
                if (data[i] != 0) {
                    padding_len = size - (size_t)(i + 1);
                    break;
                }
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_PKCS5:
        case AES_PADDING_PKCS7:
            last_byte = data[size - 1];
            padding_len = (size_t)last_byte;
            if (padding_len == 0 || padding_len > size || padding_len > BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            for (j = (int)(size - padding_len); j < (int)size; ++j) {
                if (data[j] != last_byte) {
                    *out_size = 0;
                    return NULL;
                }
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_ANSIX923:
            last_byte = data[size - 1];
            padding_len = (size_t)last_byte;
            if (padding_len == 0 || padding_len > size || padding_len > BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            for (j = (int)(size - padding_len); j < (int)(size - 1); ++j) {
                if (data[j] != 0) {
                    *out_size = 0;
                    return NULL;
                }
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_ISO10126:
            last_byte = data[size - 1];
            padding_len = (size_t)last_byte;
            if (padding_len == 0 || padding_len > size || padding_len > BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_ISO7816:
            padding_len = 0;
            for (i = (int)size - 1; i >= 0; --i) {
                if (data[i] == 0x80) {
                    padding_len = size - (size_t)i;
                    break;
                } else if (data[i] != 0) {
                    *out_size = 0;
                    return NULL;
                }
            }
            if (padding_len == 0) {
                *out_size = 0;
                return NULL;
            }
            *out_size = size - padding_len;
            break;
    }
    
    result = (uint8_t*)malloc(*out_size);
    if (!result) {
        *out_size = 0;
        return NULL;
    }
    memcpy(result, data, *out_size);
    return result;
}

int aes_init(AES_Context* ctx, AES_KeyLength key_len, const uint8_t* key, size_t key_size,
             const uint8_t* iv, size_t iv_size) {
    if (!ctx || !key || key_size != (size_t)key_len) {
        return -1;
    }
    
    ctx->key_len = key_len;
    ctx->iv_set = 0;
    ctx->w = NULL;
    
    if (KeyExpansion(ctx, key) != 0) {
        return -1;
    }
    
    if (iv && iv_size == BLOCK_SIZE) {
        memcpy(ctx->iv, iv, BLOCK_SIZE);
        ctx->iv_set = 1;
    }
    
    return 0;
}

int aes_init_with_key_string(AES_Context* ctx, AES_KeyLength key_len, const char* key_str,
                             AES_KeyType key_type, const char* iv_str, AES_KeyType iv_type) {
    uint8_t* key = NULL;
    uint8_t* iv = NULL;
    size_t key_size = 0;
    size_t iv_size = 0;
    int result;
    
    if (!ctx || !key_str) {
        return -1;
    }
    
    switch (key_type) {
        case AES_KEY_RAW:
            key_size = (size_t)key_len;
            key = (uint8_t*)malloc(key_size);
            if (!key) return -1;
            memcpy(key, key_str, key_size);
            break;
        case AES_KEY_HEX:
            key = string_to_hex(key_str, &key_size);
            if (!key) return -1;
            if (key_size != (size_t)key_len) {
                free(key);
                return -1;
            }
            break;
        case AES_KEY_BASE64:
            key = base64_decode(key_str, &key_size);
            if (!key) return -1;
            if (key_size != (size_t)key_len) {
                free(key);
                return -1;
            }
            break;
        default:
            return -1;
    }
    
    if (iv_str) {
        switch (iv_type) {
            case AES_KEY_RAW:
                iv_size = BLOCK_SIZE;
                iv = (uint8_t*)malloc(iv_size);
                if (!iv) { free(key); return -1; }
                memcpy(iv, iv_str, iv_size);
                break;
            case AES_KEY_HEX:
                iv = string_to_hex(iv_str, &iv_size);
                if (!iv) { free(key); return -1; }
                if (iv_size != BLOCK_SIZE) {
                    free(key); free(iv);
                    return -1;
                }
                break;
            case AES_KEY_BASE64:
                iv = base64_decode(iv_str, &iv_size);
                if (!iv) { free(key); return -1; }
                if (iv_size != BLOCK_SIZE) {
                    free(key); free(iv);
                    return -1;
                }
                break;
            default:
                free(key);
                return -1;
        }
    }
    
    result = aes_init(ctx, key_len, key, key_size, iv, iv_size);
    
    memset(key, 0, key_size);
    free(key);
    if (iv) {
        memset(iv, 0, iv_size);
        free(iv);
    }
    
    return result;
}

void aes_free(AES_Context* ctx) {
    int i;
    if (ctx) {
        if (ctx->w) {
            for (i = 0; i < (ctx->Nr + 1) * 4; ++i) {
                ctx->w[i] = 0;
            }
            free(ctx->w);
            ctx->w = NULL;
        }
        memset(ctx->iv, 0, BLOCK_SIZE);
    }
}

static uint8_t* ecb_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            AES_Padding padding, size_t* out_size) {
    size_t padded_size;
    uint8_t* padded;
    size_t num_blocks;
    uint8_t* ciphertext;
    size_t i;
    
    padded = pad(plaintext, plaintext_size, padding, &padded_size);
    if (!padded) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = padded_size / BLOCK_SIZE;
    ciphertext = (uint8_t*)malloc(padded_size);
    if (!ciphertext) {
        free(padded);
        *out_size = 0;
        return NULL;
    }
    
    for (i = 0; i < num_blocks; ++i) {
        Cipher(ctx->w, ctx->Nr, padded + i * BLOCK_SIZE, ciphertext + i * BLOCK_SIZE);
    }
    
    free(padded);
    *out_size = padded_size;
    return ciphertext;
}

static uint8_t* ecb_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                            AES_Padding padding, size_t* out_size) {
    size_t num_blocks;
    uint8_t* plaintext;
    uint8_t* result;
    size_t i;
    
    if (ciphertext_size % BLOCK_SIZE != 0) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = ciphertext_size / BLOCK_SIZE;
    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        *out_size = 0;
        return NULL;
    }
    
    for (i = 0; i < num_blocks; ++i) {
        InvCipher(ctx->w, ctx->Nr, ciphertext + i * BLOCK_SIZE, plaintext + i * BLOCK_SIZE);
    }
    
    result = unpad(plaintext, ciphertext_size, padding, out_size);
    free(plaintext);
    return result;
}

static uint8_t* cbc_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            const uint8_t* iv, AES_Padding padding, size_t* out_size) {
    size_t padded_size;
    uint8_t* padded;
    size_t num_blocks;
    uint8_t* ciphertext;
    uint8_t prev_block[BLOCK_SIZE];
    size_t i, j;
    
    padded = pad(plaintext, plaintext_size, padding, &padded_size);
    if (!padded) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = padded_size / BLOCK_SIZE;
    ciphertext = (uint8_t*)malloc(padded_size);
    if (!ciphertext) {
        free(padded);
        *out_size = 0;
        return NULL;
    }
    memcpy(prev_block, iv, BLOCK_SIZE);
    
    for (i = 0; i < num_blocks; ++i) {
        for (j = 0; j < BLOCK_SIZE; ++j) {
            padded[i * BLOCK_SIZE + j] ^= prev_block[j];
        }
        Cipher(ctx->w, ctx->Nr, padded + i * BLOCK_SIZE, ciphertext + i * BLOCK_SIZE);
        memcpy(prev_block, ciphertext + i * BLOCK_SIZE, BLOCK_SIZE);
    }
    
    free(padded);
    *out_size = padded_size;
    return ciphertext;
}

static uint8_t* cbc_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                            const uint8_t* iv, AES_Padding padding, size_t* out_size) {
    size_t num_blocks;
    uint8_t* plaintext;
    uint8_t prev_block[BLOCK_SIZE];
    uint8_t current_block[BLOCK_SIZE];
    uint8_t* result;
    size_t i, j;
    
    if (ciphertext_size % BLOCK_SIZE != 0) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = ciphertext_size / BLOCK_SIZE;
    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        *out_size = 0;
        return NULL;
    }
    
    memcpy(prev_block, iv, BLOCK_SIZE);
    
    for (i = 0; i < num_blocks; ++i) {
        memcpy(current_block, ciphertext + i * BLOCK_SIZE, BLOCK_SIZE);
        InvCipher(ctx->w, ctx->Nr, ciphertext + i * BLOCK_SIZE, plaintext + i * BLOCK_SIZE);
        for (j = 0; j < BLOCK_SIZE; ++j) {
            plaintext[i * BLOCK_SIZE + j] ^= prev_block[j];
        }
        memcpy(prev_block, current_block, BLOCK_SIZE);
    }
    
    result = unpad(plaintext, ciphertext_size, padding, out_size);
    free(plaintext);
    return result;
}

static uint8_t* cfb8_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                             const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t feedback[BLOCK_SIZE];
    uint8_t encrypted[BLOCK_SIZE];
    size_t i;
    
    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    
    for (i = 0; i < plaintext_size; ++i) {
        Cipher(ctx->w, ctx->Nr, feedback, encrypted);
        ciphertext[i] = plaintext[i] ^ encrypted[0];
        memmove(feedback, feedback + 1, BLOCK_SIZE - 1);
        feedback[BLOCK_SIZE - 1] = ciphertext[i];
    }
    
    *out_size = plaintext_size;
    return ciphertext;
}

static uint8_t* cfb8_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                             const uint8_t* iv, size_t* out_size) {
    uint8_t* plaintext;
    uint8_t feedback[BLOCK_SIZE];
    uint8_t encrypted[BLOCK_SIZE];
    size_t i;
    
    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    
    for (i = 0; i < ciphertext_size; ++i) {
        Cipher(ctx->w, ctx->Nr, feedback, encrypted);
        plaintext[i] = ciphertext[i] ^ encrypted[0];
        memmove(feedback, feedback + 1, BLOCK_SIZE - 1);
        feedback[BLOCK_SIZE - 1] = ciphertext[i];
    }
    
    *out_size = ciphertext_size;
    return plaintext;
}

static uint8_t* cfb128_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                               const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t feedback[BLOCK_SIZE];
    uint8_t encrypted[BLOCK_SIZE];
    size_t i, j;
    
    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    
    i = 0;
    while (i < plaintext_size) {
        Cipher(ctx->w, ctx->Nr, feedback, encrypted);
        if (i + BLOCK_SIZE <= plaintext_size) {
            for (j = 0; j < BLOCK_SIZE; ++j) {
                ciphertext[i + j] = plaintext[i + j] ^ encrypted[j];
            }
            memcpy(feedback, ciphertext + i, BLOCK_SIZE);
            i += BLOCK_SIZE;
        } else {
            for (j = 0; i + j < plaintext_size; ++j) {
                ciphertext[i + j] = plaintext[i + j] ^ encrypted[j];
            }
            memmove(feedback, feedback + j, BLOCK_SIZE - j);
            memcpy(feedback + BLOCK_SIZE - j, ciphertext + i, j);
            i += j;
        }
    }
    
    *out_size = plaintext_size;
    return ciphertext;
}

static uint8_t* cfb128_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                               const uint8_t* iv, size_t* out_size) {
    uint8_t* plaintext;
    uint8_t feedback[BLOCK_SIZE];
    uint8_t encrypted[BLOCK_SIZE];
    uint8_t temp[BLOCK_SIZE];
    size_t i, j;
    
    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    
    i = 0;
    while (i < ciphertext_size) {
        Cipher(ctx->w, ctx->Nr, feedback, encrypted);
        if (i + BLOCK_SIZE <= ciphertext_size) {
            memcpy(temp, ciphertext + i, BLOCK_SIZE);
            for (j = 0; j < BLOCK_SIZE; ++j) {
                plaintext[i + j] = ciphertext[i + j] ^ encrypted[j];
            }
            memcpy(feedback, temp, BLOCK_SIZE);
            i += BLOCK_SIZE;
        } else {
            memcpy(temp, ciphertext + i, ciphertext_size - i);
            for (j = 0; i + j < ciphertext_size; ++j) {
                plaintext[i + j] = ciphertext[i + j] ^ encrypted[j];
            }
            memmove(feedback, feedback + j, BLOCK_SIZE - j);
            memcpy(feedback + BLOCK_SIZE - j, temp, j);
            i += j;
        }
    }
    
    *out_size = ciphertext_size;
    return plaintext;
}

static uint8_t* ofb_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t feedback[BLOCK_SIZE];
    uint8_t encrypted[BLOCK_SIZE];
    int num;
    size_t i;
    
    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    
    num = 0;
    for (i = 0; i < plaintext_size; ++i) {
        if (num == 0) {
            Cipher(ctx->w, ctx->Nr, feedback, encrypted);
            memcpy(feedback, encrypted, BLOCK_SIZE);
        }
        ciphertext[i] = plaintext[i] ^ feedback[num];
        num = (num + 1) % BLOCK_SIZE;
    }
    
    *out_size = plaintext_size;
    return ciphertext;
}

static uint8_t* ctr_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t counter[BLOCK_SIZE];
    uint8_t stream_block[BLOCK_SIZE];
    size_t stream_pos;
    size_t i;
    int j;
    
    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(counter, iv, BLOCK_SIZE);
    
    stream_pos = 0;
    
    for (i = 0; i < plaintext_size; ++i) {
        if (stream_pos == 0) {
            Cipher(ctx->w, ctx->Nr, counter, stream_block);
            for (j = BLOCK_SIZE - 1; j >= 0; --j) {
                if (++counter[j] != 0) {
                    break;
                }
            }
        }
        ciphertext[i] = plaintext[i] ^ stream_block[stream_pos];
        stream_pos = (stream_pos + 1) % BLOCK_SIZE;
    }
    
    *out_size = plaintext_size;
    return ciphertext;
}

static void gcm_mult(uint8_t* x, const uint8_t* h) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    uint8_t lsb;
    int i, j, k;
    
    memcpy(v, x, 16);
    
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            if ((h[i] >> j) & 1) {
                for (k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }
            lsb = v[15] & 1;
            for (k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
            }
            v[0] >>= 1;
            if (lsb) {
                v[0] ^= 0xE1;
            }
        }
    }
    
    memcpy(x, z, 16);
}

static void gcm_ghash(uint8_t* x, const uint8_t* h, const uint8_t* data, size_t data_len) {
    uint8_t block[16];
    size_t i, j;
    
    for (i = 0; i < data_len; i += 16) {
        memset(block, 0, 16);
        for (j = 0; j < 16; j++) {
            if (i + j < data_len) {
                block[j] = data[i + j];
            }
        }
        for (j = 0; j < 16; j++) {
            x[j] ^= block[j];
        }
        gcm_mult(x, h);
    }
}

static void gcm_ghash_final(uint8_t* x, const uint8_t* h, size_t aad_len, size_t ciphertext_len) {
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len << 3;
    uint64_t cipher_bits = (uint64_t)ciphertext_len << 3;
    int i;
    
    for (i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (8 * (7 - i)));
        len_block[i + 8] = (uint8_t)(cipher_bits >> (8 * (7 - i)));
    }
    
    for (i = 0; i < 16; i++) {
        x[i] ^= len_block[i];
    }
    gcm_mult(x, h);
}

uint8_t* aes_gcm_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t h[16];
    uint8_t zero_block[16] = {0};
    uint8_t counter[16] = {0};
    uint8_t x[16];
    uint8_t len_block[16];
    uint8_t* ciphertext;
    uint8_t counter_0[16];
    uint8_t stream_block[16];
    uint64_t nonce_bits;
    size_t stream_pos;
    int i, j;
    
    if (!ctx || !plaintext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }
    
    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }
    
    if (nonce_size == 0 || nonce_size > 16) {
        *out_size = 0;
        return NULL;
    }
    
    if (tag_size > 16) {
        tag_size = 16;
    }
    
    Cipher(ctx->w, ctx->Nr, zero_block, h);
    
    if (nonce_size == 12) {
        memcpy(counter, nonce, 12);
        counter[15] = 1;
    } else {
        memset(x, 0, 16);
        gcm_ghash(x, h, nonce, nonce_size);
        memset(len_block, 0, 16);
        nonce_bits = (uint64_t)nonce_size << 3;
        for (i = 7; i >= 0; --i) {
            len_block[i + 8] = (uint8_t)(nonce_bits >> (8 * (7 - i)));
        }
        for (i = 0; i < 16; ++i) {
            x[i] ^= len_block[i];
        }
        gcm_mult(x, h);
        memcpy(counter, x, 16);
    }
    
    if (plaintext_size == 0) {
        *out_size = 0;
        ciphertext = (uint8_t*)malloc(1);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
        ciphertext[0] = 0;
    } else {
        ciphertext = (uint8_t*)malloc(plaintext_size);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
    }
    
    memcpy(counter_0, counter, 16);
    
    for (j = 15; j >= 0; --j) {
        if (++counter[j] != 0) {
            break;
        }
    }
    
    stream_pos = 0;
    
    for (i = 0; i < (int)plaintext_size; ++i) {
        if (stream_pos == 0) {
            Cipher(ctx->w, ctx->Nr, counter, stream_block);
            for (j = 15; j >= 0; --j) {
                if (++counter[j] != 0) {
                    break;
                }
            }
        }
        ciphertext[i] = plaintext[i] ^ stream_block[stream_pos];
        stream_pos = (stream_pos + 1) % 16;
    }
    
    memset(x, 0, 16);
    if (aad_size > 0) {
        gcm_ghash(x, h, aad, aad_size);
    }
    if (plaintext_size > 0) {
        gcm_ghash(x, h, ciphertext, plaintext_size);
    }
    gcm_ghash_final(x, h, aad_size, plaintext_size);
    
    Cipher(ctx->w, ctx->Nr, counter_0, counter);
    for (i = 0; i < 16; ++i) {
        x[i] ^= counter[i];
    }
    
    memcpy(tag, x, tag_size);
    *out_size = plaintext_size;
    
    return ciphertext;
}

uint8_t* aes_gcm_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t h[16];
    uint8_t zero_block[16] = {0};
    uint8_t counter[16] = {0};
    uint8_t x[16];
    uint8_t len_block[16];
    uint8_t* plaintext;
    uint8_t counter_0[16];
    uint8_t stream_block[16];
    uint64_t nonce_bits;
    uint8_t result;
    size_t stream_pos;
    int i, j;
    
    if (!ctx || !ciphertext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }
    
    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }
    
    if (nonce_size == 0 || nonce_size > 16) {
        *out_size = 0;
        return NULL;
    }
    
    if (tag_size > 16) {
        tag_size = 16;
    }
    
    Cipher(ctx->w, ctx->Nr, zero_block, h);
    
    if (nonce_size == 12) {
        memcpy(counter, nonce, 12);
        counter[15] = 1;
    } else {
        memset(x, 0, 16);
        gcm_ghash(x, h, nonce, nonce_size);
        memset(len_block, 0, 16);
        nonce_bits = (uint64_t)nonce_size << 3;
        for (i = 7; i >= 0; --i) {
            len_block[i + 8] = (uint8_t)(nonce_bits >> (8 * (7 - i)));
        }
        for (i = 0; i < 16; ++i) {
            x[i] ^= len_block[i];
        }
        gcm_mult(x, h);
        memcpy(counter, x, 16);
    }
    
    if (ciphertext_size == 0) {
        *out_size = 0;
        plaintext = (uint8_t*)malloc(1);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
        plaintext[0] = 0;
    } else {
        plaintext = (uint8_t*)malloc(ciphertext_size);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
    }
    
    memcpy(counter_0, counter, 16);
    
    for (j = 15; j >= 0; --j) {
        if (++counter[j] != 0) {
            break;
        }
    }
    
    stream_pos = 0;
    
    for (i = 0; i < (int)ciphertext_size; ++i) {
        if (stream_pos == 0) {
            Cipher(ctx->w, ctx->Nr, counter, stream_block);
            for (j = 15; j >= 0; --j) {
                if (++counter[j] != 0) {
                    break;
                }
            }
        }
        plaintext[i] = ciphertext[i] ^ stream_block[stream_pos];
        stream_pos = (stream_pos + 1) % 16;
    }
    
    memset(x, 0, 16);
    if (aad_size > 0) {
        gcm_ghash(x, h, aad, aad_size);
    }
    if (ciphertext_size > 0) {
        gcm_ghash(x, h, ciphertext, ciphertext_size);
    }
    gcm_ghash_final(x, h, aad_size, ciphertext_size);
    
    Cipher(ctx->w, ctx->Nr, counter_0, counter);
    for (i = 0; i < 16; ++i) {
        x[i] ^= counter[i];
    }
    
    result = 0;
    for (i = 0; i < (int)tag_size; ++i) {
        result |= x[i] ^ tag[i];
    }
    
    if (result != 0) {
        free(plaintext);
        *out_size = 0;
        return NULL;
    }
    
    *out_size = ciphertext_size;
    return plaintext;
}

static void ccm_ctr(AES_Context* ctx, const uint8_t* nonce, size_t nonce_len,
                    uint8_t* out, size_t out_len) {
    uint8_t counter[16];
    uint8_t block[16];
    int q;
    size_t i, j;
    
    q = 15 - (int)nonce_len;
    
    counter[0] = (uint8_t)(q - 1);
    memcpy(counter + 1, nonce, nonce_len);
    
    for (i = 0; i < out_len; i += 16) {
        Cipher(ctx->w, ctx->Nr, counter, block);
        
        for (j = 0; j < 16 && i + j < out_len; ++j) {
            out[i + j] = block[j];
        }
        
        for (j = 15; j >= (size_t)(1 + nonce_len); --j) {
            if (++counter[j] != 0) {
                break;
            }
        }
    }
}

static void ccm_mac(AES_Context* ctx, const uint8_t* nonce, size_t nonce_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* data, size_t data_len,
                    uint8_t* mac) {
    uint8_t b0[16] = {0};
    uint8_t aad_block[16];
    uint8_t data_block[16];
    uint8_t len_block[16];
    int q, tag_size;
    size_t aad_remaining, data_remaining;
    const uint8_t* aad_ptr;
    const uint8_t* data_ptr;
    int i, j;
    
    q = 15 - (int)nonce_len;
    tag_size = 16;
    
    b0[0] = (uint8_t)(((aad_len > 0) ? 0x40 : 0x00) | ((tag_size - 2) << 2) | (q - 1));
    memcpy(b0 + 1, nonce, nonce_len);
    
    for (i = 7; i >= 0; --i) {
        b0[16 - 1 - i] = (uint8_t)(data_len >> (8 * i));
    }
    
    Cipher(ctx->w, ctx->Nr, b0, mac);
    
    if (aad_len > 0) {
        aad_remaining = aad_len;
        aad_ptr = aad;
        
        if (aad_remaining <= 16) {
            memset(aad_block, 0, 16);
            aad_block[0] = (uint8_t)(aad_len >> 8);
            aad_block[1] = (uint8_t)(aad_len & 0xFF);
            memcpy(aad_block + 2, aad_ptr, aad_remaining);
            for (j = 0; j < 16; ++j) {
                mac[j] ^= aad_block[j];
            }
            Cipher(ctx->w, ctx->Nr, mac, mac);
        } else {
            memset(len_block, 0, 16);
            len_block[0] = (uint8_t)(aad_len >> 8);
            len_block[1] = (uint8_t)(aad_len & 0xFF);
            for (j = 0; j < 16; ++j) {
                mac[j] ^= len_block[j];
            }
            Cipher(ctx->w, ctx->Nr, mac, mac);
            
            while (aad_remaining >= 16) {
                for (j = 0; j < 16; ++j) {
                    mac[j] ^= aad_ptr[j];
                }
                Cipher(ctx->w, ctx->Nr, mac, mac);
                aad_ptr += 16;
                aad_remaining -= 16;
            }
            
            if (aad_remaining > 0) {
                memset(aad_block, 0, 16);
                memcpy(aad_block, aad_ptr, aad_remaining);
                for (j = 0; j < 16; ++j) {
                    mac[j] ^= aad_block[j];
                }
                Cipher(ctx->w, ctx->Nr, mac, mac);
            }
        }
    }
    
    if (data_len > 0) {
        data_remaining = data_len;
        data_ptr = data;
        
        while (data_remaining >= 16) {
            for (j = 0; j < 16; ++j) {
                mac[j] ^= data_ptr[j];
            }
            Cipher(ctx->w, ctx->Nr, mac, mac);
            data_ptr += 16;
            data_remaining -= 16;
        }
        
        if (data_remaining > 0) {
            memset(data_block, 0, 16);
            memcpy(data_block, data_ptr, data_remaining);
            for (j = 0; j < 16; ++j) {
                mac[j] ^= data_block[j];
            }
            Cipher(ctx->w, ctx->Nr, mac, mac);
        }
    }
}

uint8_t* aes_ccm_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t mac[16];
    uint8_t* keystream;
    size_t i;
    
    if (!ctx || !plaintext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }
    
    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }
    
    if (nonce_size < 7 || nonce_size > 13) {
        *out_size = 0;
        return NULL;
    }
    
    if (tag_size < 4 || tag_size > 16 || tag_size % 2 != 0) {
        tag_size = 16;
    }
    
    if (plaintext_size == 0) {
        *out_size = 0;
        ciphertext = (uint8_t*)malloc(1);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
        ciphertext[0] = 0;
    } else {
        ciphertext = (uint8_t*)malloc(plaintext_size);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
    }
    
    ccm_mac(ctx, nonce, nonce_size, aad, aad_size, plaintext, plaintext_size, mac);
    
    keystream = (uint8_t*)malloc(plaintext_size + tag_size);
    if (!keystream) {
        free(ciphertext);
        *out_size = 0;
        return NULL;
    }
    
    ccm_ctr(ctx, nonce, nonce_size, keystream, plaintext_size + tag_size);
    
    for (i = 0; i < plaintext_size; ++i) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    
    for (i = 0; i < tag_size; ++i) {
        tag[i] = mac[i] ^ keystream[plaintext_size + i];
    }
    
    memset(keystream, 0, plaintext_size + tag_size);
    free(keystream);
    memset(mac, 0, 16);
    *out_size = plaintext_size;
    
    return ciphertext;
}

uint8_t* aes_ccm_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t* plaintext;
    uint8_t* keystream;
    uint8_t expected_tag[16] = {0};
    uint8_t mac[16];
    uint8_t result;
    size_t i;
    
    if (!ctx || !ciphertext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }
    
    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }
    
    if (nonce_size < 7 || nonce_size > 13) {
        *out_size = 0;
        return NULL;
    }
    
    if (tag_size < 4 || tag_size > 16 || tag_size % 2 != 0) {
        tag_size = 16;
    }
    
    if (ciphertext_size == 0) {
        *out_size = 0;
        plaintext = (uint8_t*)malloc(1);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
        plaintext[0] = 0;
    } else {
        plaintext = (uint8_t*)malloc(ciphertext_size);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
    }
    
    keystream = (uint8_t*)malloc(ciphertext_size + tag_size);
    if (!keystream) {
        free(plaintext);
        *out_size = 0;
        return NULL;
    }
    
    ccm_ctr(ctx, nonce, nonce_size, keystream, ciphertext_size + tag_size);
    
    for (i = 0; i < ciphertext_size; ++i) {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }
    
    for (i = 0; i < tag_size; ++i) {
        expected_tag[i] = tag[i] ^ keystream[ciphertext_size + i];
    }
    
    memset(keystream, 0, ciphertext_size + tag_size);
    free(keystream);
    
    ccm_mac(ctx, nonce, nonce_size, aad, aad_size, plaintext, ciphertext_size, mac);
    
    result = 0;
    for (i = 0; i < tag_size; ++i) {
        result |= mac[i] ^ expected_tag[i];
    }
    
    memset(mac, 0, 16);
    memset(expected_tag, 0, 16);
    
    if (result != 0) {
        memset(plaintext, 0, ciphertext_size);
        free(plaintext);
        *out_size = 0;
        return NULL;
    }
    
    *out_size = ciphertext_size;
    return plaintext;
}

uint8_t* aes_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                     AES_Mode mode, AES_Padding padding,
                     const uint8_t* iv, size_t iv_size, size_t* out_size) {
    const uint8_t* use_iv;
    
    if (!ctx || !plaintext || !out_size) {
        *out_size = 0;
        return NULL;
    }
    
    use_iv = iv;
    if (!use_iv && ctx->iv_set) {
        use_iv = ctx->iv;
        iv_size = BLOCK_SIZE;
    }
    
    switch (mode) {
        case AES_MODE_ECB:
            return ecb_encrypt(ctx, plaintext, plaintext_size, padding, out_size);
        case AES_MODE_CBC:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cbc_encrypt(ctx, plaintext, plaintext_size, use_iv, padding, out_size);
        case AES_MODE_CFB8:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb8_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_CFB128:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb128_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_OFB:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ofb_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_CTR:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ctr_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_GCM:
            *out_size = 0;
            return NULL;
        case AES_MODE_CCM:
            *out_size = 0;
            return NULL;
        default:
            *out_size = 0;
            return NULL;
    }
}

uint8_t* aes_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                     AES_Mode mode, AES_Padding padding,
                     const uint8_t* iv, size_t iv_size, size_t* out_size) {
    const uint8_t* use_iv;
    
    if (!ctx || !ciphertext || !out_size) {
        *out_size = 0;
        return NULL;
    }
    
    use_iv = iv;
    if (!use_iv && ctx->iv_set) {
        use_iv = ctx->iv;
        iv_size = BLOCK_SIZE;
    }
    
    switch (mode) {
        case AES_MODE_ECB:
            return ecb_decrypt(ctx, ciphertext, ciphertext_size, padding, out_size);
        case AES_MODE_CBC:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cbc_decrypt(ctx, ciphertext, ciphertext_size, use_iv, padding, out_size);
        case AES_MODE_CFB8:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb8_decrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_CFB128:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb128_decrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_OFB:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ofb_encrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_CTR:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ctr_encrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_GCM:
            *out_size = 0;
            return NULL;
        case AES_MODE_CCM:
            *out_size = 0;
            return NULL;
        default:
            *out_size = 0;
            return NULL;
    }
}

char* aes_bytes_to_hex(const uint8_t* data, size_t size) {
    char* hex;
    const char* hex_chars;
    size_t i;
    
    if (!data || size == 0) return NULL;
    
    hex = (char*)malloc(size * 2 + 1);
    if (!hex) return NULL;
    
    hex_chars = "0123456789abcdef";
    for (i = 0; i < size; ++i) {
        hex[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    hex[size * 2] = '\0';
    
    return hex;
}

uint8_t* aes_hex_to_bytes(const char* hex, size_t* out_size) {
    size_t len;
    uint8_t* bytes;
    char h, l;
    size_t i;
    
    if (!hex || !out_size) {
        *out_size = 0;
        return NULL;
    }
    
    len = strlen(hex);
    if (len % 2 != 0) {
        *out_size = 0;
        return NULL;
    }
    
    *out_size = len / 2;
    bytes = (uint8_t*)malloc(*out_size);
    if (!bytes) {
        *out_size = 0;
        return NULL;
    }
    
    for (i = 0; i < *out_size; ++i) {
        h = hex[i * 2];
        l = hex[i * 2 + 1];
        
        if (h >= '0' && h <= '9') h -= '0';
        else if (h >= 'a' && h <= 'f') h -= 'a' - 10;
        else if (h >= 'A' && h <= 'F') h -= 'A' - 10;
        else {
            free(bytes);
            *out_size = 0;
            return NULL;
        }
        
        if (l >= '0' && l <= '9') l -= '0';
        else if (l >= 'a' && l <= 'f') l -= 'a' - 10;
        else if (l >= 'A' && l <= 'F') l -= 'A' - 10;
        else {
            free(bytes);
            *out_size = 0;
            return NULL;
        }
        
        bytes[i] = (h << 4) | l;
    }
    
    return bytes;
}

int aes_self_test(void) {
    uint8_t key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t plaintext_128[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t expected_ciphertext_128[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                           0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    uint8_t gcm_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t gcm_nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x01};
    uint8_t gcm_plaintext[32] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    uint8_t gcm_aad[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected_gcm_tag[16] = {0x97, 0x15, 0x0d, 0xab, 0x5a, 0xc1, 0x8a, 0xa8,
                                     0x2e, 0x2e, 0x46, 0x68, 0x27, 0x22, 0x81, 0x09};
    uint8_t ccm_key[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                           0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    uint8_t ccm_nonce[11] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1a};
    uint8_t ccm_plaintext[32] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ccm_aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    uint8_t gcm_tag[16];
    uint8_t ccm_tag[16];
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key_128, 16, NULL, 0) != 0) {
        return -1;
    }
    ciphertext = ecb_encrypt(&ctx, plaintext_128, 16, AES_PADDING_NONE, &out_size);
    if (!ciphertext || out_size != 16) {
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 16; ++i) {
        if (ciphertext[i] != expected_ciphertext_128[i]) {
            free(ciphertext);
            aes_free(&ctx);
            return -1;
        }
    }
    free(ciphertext);
    aes_free(&ctx);
    
    if (aes_init(&ctx, AES_128, gcm_key, 16, NULL, 0) != 0) {
        return -1;
    }
    ciphertext = aes_gcm_encrypt(&ctx, gcm_plaintext, 32, gcm_nonce, 12, gcm_aad, 16, gcm_tag, 16, &out_size);
    if (!ciphertext || out_size != 32) {
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 16; ++i) {
        if (gcm_tag[i] != expected_gcm_tag[i]) {
            free(ciphertext);
            aes_free(&ctx);
            return -1;
        }
    }
    decrypted = aes_gcm_decrypt(&ctx, ciphertext, 32, gcm_nonce, 12, gcm_aad, 16, gcm_tag, 16, &out_size);
    if (!decrypted || out_size != 32) {
        free(ciphertext);
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != gcm_plaintext[i]) {
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return -1;
        }
    }
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    
    if (aes_init(&ctx, AES_128, ccm_key, 16, NULL, 0) != 0) {
        return -1;
    }
    ciphertext = aes_ccm_encrypt(&ctx, ccm_plaintext, 32, ccm_nonce, 11, ccm_aad, 16, ccm_tag, 16, &out_size);
    if (!ciphertext || out_size != 32) {
        aes_free(&ctx);
        return -1;
    }
    decrypted = aes_ccm_decrypt(&ctx, ciphertext, 32, ccm_nonce, 11, ccm_aad, 16, ccm_tag, 16, &out_size);
    if (!decrypted || out_size != 32) {
        free(ciphertext);
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != ccm_plaintext[i]) {
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return -1;
        }
    }
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    
    return 0;
}

int aes_stream_init(AES_StreamContext* sctx, AES_Context* ctx, AES_Mode mode, AES_Padding padding,
                    const uint8_t* iv, size_t iv_size, int is_encrypt) {
    if (!sctx || !ctx || iv_size != BLOCK_SIZE) {
        return -1;
    }
    
    memset(sctx, 0, sizeof(AES_StreamContext));
    sctx->ctx = ctx;
    sctx->mode = mode;
    sctx->padding = padding;
    memcpy(sctx->iv, iv, BLOCK_SIZE);
    memcpy(sctx->feedback, iv, BLOCK_SIZE);
    memcpy(sctx->counter, iv, BLOCK_SIZE);
    sctx->is_encrypt = is_encrypt;
    
    return 0;
}

static void stream_gcm_ghash_update(AES_StreamContext* sctx, const uint8_t* data, size_t data_len) {
    uint8_t block[16];
    size_t i, j;
    
    for (i = 0; i < data_len; i += 16) {
        memset(block, 0, 16);
        for (j = 0; j < 16; j++) {
            if (i + j < data_len) {
                block[j] = data[i + j];
            }
        }
        for (j = 0; j < 16; j++) {
            sctx->gcm_x[j] ^= block[j];
        }
        gcm_mult(sctx->gcm_x, sctx->gcm_h);
    }
}

static void stream_gcm_ghash_final(AES_StreamContext* sctx) {
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)sctx->gcm_aad_len << 3;
    uint64_t data_bits = (uint64_t)sctx->gcm_data_len << 3;
    int i;
    
    for (i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (8 * (7 - i)));
        len_block[i + 8] = (uint8_t)(data_bits >> (8 * (7 - i)));
    }
    
    for (i = 0; i < 16; i++) {
        sctx->gcm_x[i] ^= len_block[i];
    }
    gcm_mult(sctx->gcm_x, sctx->gcm_h);
}

int aes_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                      uint8_t* out, size_t* out_size) {
    uint8_t stream_block[16];
    uint8_t temp_block[16];
    size_t i, remaining;
    int idx, j;
    
    if (!sctx || !in || !out || !out_size) {
        return -1;
    }
    
    *out_size = 0;
    
    switch (sctx->mode) {
        case AES_MODE_ECB:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->buffer, out + *out_size);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        InvCipher(sctx->ctx->w, sctx->ctx->Nr, sctx->buffer, out + *out_size);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        case AES_MODE_CBC:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    idx = (int)remaining;
                    sctx->buffer[idx] = in[i] ^ sctx->feedback[idx];
                    remaining++;
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->buffer, out + *out_size);
                        memcpy(sctx->feedback, out + *out_size, BLOCK_SIZE);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        InvCipher(sctx->ctx->w, sctx->ctx->Nr, sctx->buffer, temp_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = temp_block[j] ^ sctx->feedback[j];
                        }
                        memcpy(sctx->feedback, sctx->buffer, BLOCK_SIZE);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        case AES_MODE_CFB8:
            remaining = sctx->buffer_len;
            for (i = 0; i < in_size; i++) {
                sctx->buffer[remaining++] = in[i];
                if (remaining == BLOCK_SIZE) {
                    for (j = 0; j < BLOCK_SIZE; j++) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                        out[*out_size + j] = sctx->buffer[j] ^ stream_block[0];
                        memmove(sctx->feedback, sctx->feedback + 1, BLOCK_SIZE - 1);
                        sctx->feedback[BLOCK_SIZE - 1] = sctx->is_encrypt ? out[*out_size + j] : sctx->buffer[j];
                    }
                    *out_size += BLOCK_SIZE;
                    remaining = 0;
                }
            }
            sctx->buffer_len = remaining;
            break;
            
        case AES_MODE_CFB128:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        memcpy(sctx->feedback, out + *out_size, BLOCK_SIZE);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        memcpy(sctx->feedback, sctx->buffer, BLOCK_SIZE);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        case AES_MODE_OFB:
            remaining = sctx->buffer_len;
            for (i = 0; i < in_size; i++) {
                sctx->buffer[remaining++] = in[i];
                if (remaining == BLOCK_SIZE) {
                    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                    for (j = 0; j < BLOCK_SIZE; j++) {
                        out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                    }
                    memcpy(sctx->feedback, stream_block, BLOCK_SIZE);
                    *out_size += BLOCK_SIZE;
                    remaining = 0;
                }
            }
            sctx->buffer_len = remaining;
            break;
            
        case AES_MODE_CTR:
            remaining = sctx->buffer_len;
            for (i = 0; i < in_size; i++) {
                sctx->buffer[remaining++] = in[i];
                if (remaining == BLOCK_SIZE) {
                    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
                    for (j = 0; j < BLOCK_SIZE; j++) {
                        out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                    }
                    for (j = BLOCK_SIZE - 1; j >= 0; --j) {
                        if (++sctx->counter[j] != 0) {
                            break;
                        }
                    }
                    *out_size += BLOCK_SIZE;
                    remaining = 0;
                }
            }
            sctx->buffer_len = remaining;
            break;
            
        case AES_MODE_GCM:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        stream_gcm_ghash_update(sctx, out + *out_size, BLOCK_SIZE);
                        sctx->gcm_data_len += BLOCK_SIZE;
                        for (j = BLOCK_SIZE - 1; j >= 0; --j) {
                            if (++sctx->counter[j] != 0) {
                                break;
                            }
                        }
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        stream_gcm_ghash_update(sctx, sctx->buffer, BLOCK_SIZE);
                        sctx->gcm_data_len += BLOCK_SIZE;
                        for (j = BLOCK_SIZE - 1; j >= 0; --j) {
                            if (++sctx->counter[j] != 0) {
                                break;
                            }
                        }
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        default:
            return -1;
    }
    
    memset(stream_block, 0, BLOCK_SIZE);
    memset(temp_block, 0, BLOCK_SIZE);
    
    return 0;
}

int aes_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size) {
    uint8_t padded[16];
    size_t i, j;
    
    if (!sctx || !out || !out_size) {
        return -1;
    }
    
    *out_size = 0;
    
    switch (sctx->mode) {
        case AES_MODE_ECB:
        case AES_MODE_CBC:
        case AES_MODE_CFB128:
            if (sctx->is_encrypt && sctx->padding != AES_PADDING_NONE) {
                if (sctx->buffer_len > 0) {
                    memset(padded, 0, BLOCK_SIZE);
                    memcpy(padded, sctx->buffer, sctx->buffer_len);
                    
                    switch (sctx->padding) {
                        case AES_PADDING_ZERO:
                            break;
                        case AES_PADDING_PKCS5:
                        case AES_PADDING_PKCS7:
                            for (i = sctx->buffer_len; i < BLOCK_SIZE; i++) {
                                padded[i] = (uint8_t)(BLOCK_SIZE - sctx->buffer_len);
                            }
                            break;
                        case AES_PADDING_ANSIX923:
                            padded[BLOCK_SIZE - 1] = (uint8_t)(BLOCK_SIZE - sctx->buffer_len);
                            break;
                        case AES_PADDING_ISO10126:
                            if (BLOCK_SIZE - sctx->buffer_len > 1) {
                                aes_random_bytes(padded + sctx->buffer_len, BLOCK_SIZE - sctx->buffer_len - 1);
                            }
                            padded[BLOCK_SIZE - 1] = (uint8_t)(BLOCK_SIZE - sctx->buffer_len);
                            break;
                        case AES_PADDING_ISO7816:
                            padded[sctx->buffer_len] = 0x80;
                            break;
                        default:
                            break;
                    }
                    
                    if (sctx->mode == AES_MODE_CBC) {
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            padded[j] ^= sctx->feedback[j];
                        }
                    }
                    
                    Cipher(sctx->ctx->w, sctx->ctx->Nr, padded, out);
                    *out_size = BLOCK_SIZE;
                    
                    if (sctx->mode == AES_MODE_CBC) {
                        memcpy(sctx->feedback, out, BLOCK_SIZE);
                    }
                } else if (sctx->padding != AES_PADDING_NONE) {
                    memset(padded, BLOCK_SIZE, BLOCK_SIZE);
                    
                    if (sctx->mode == AES_MODE_CBC) {
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            padded[j] ^= sctx->feedback[j];
                        }
                    }
                    
                    Cipher(sctx->ctx->w, sctx->ctx->Nr, padded, out);
                    *out_size = BLOCK_SIZE;
                    
                    if (sctx->mode == AES_MODE_CBC) {
                        memcpy(sctx->feedback, out, BLOCK_SIZE);
                    }
                }
            }
            break;
            
        case AES_MODE_CFB8:
        case AES_MODE_OFB:
        case AES_MODE_CTR:
            break;
            
        default:
            break;
    }
    
    memset(padded, 0, BLOCK_SIZE);
    
    return 0;
}

void aes_stream_free(AES_StreamContext* sctx) {
    if (sctx) {
        memset(sctx->iv, 0, BLOCK_SIZE);
        memset(sctx->feedback, 0, BLOCK_SIZE);
        memset(sctx->counter, 0, BLOCK_SIZE);
        memset(sctx->buffer, 0, BLOCK_SIZE);
        memset(sctx->gcm_h, 0, BLOCK_SIZE);
        memset(sctx->gcm_x, 0, BLOCK_SIZE);
        memset(sctx->ccm_mac, 0, BLOCK_SIZE);
        if (sctx->ccm_buffer) {
            memset(sctx->ccm_buffer, 0, sctx->ccm_buffer_len);
            free(sctx->ccm_buffer);
        }
    }
}

int aes_gcm_stream_init(AES_StreamContext* sctx, AES_Context* ctx,
                        const uint8_t* nonce, size_t nonce_size,
                        const uint8_t* aad, size_t aad_size, int is_encrypt) {
    uint8_t zero_block[16] = {0};
    uint8_t len_block[16];
    uint64_t nonce_bits;
    int i;
    
    if (!sctx || !ctx || !nonce) {
        return -1;
    }
    
    if (nonce_size == 0 || nonce_size > 16) {
        return -1;
    }
    
    memset(sctx, 0, sizeof(AES_StreamContext));
    sctx->ctx = ctx;
    sctx->mode = AES_MODE_GCM;
    sctx->is_encrypt = is_encrypt;
    
    Cipher(ctx->w, ctx->Nr, zero_block, sctx->gcm_h);
    
    if (nonce_size == 12) {
        memcpy(sctx->counter, nonce, 12);
        sctx->counter[15] = 1;
        memcpy(sctx->counter_0, sctx->counter, 16);
    } else {
        memset(sctx->gcm_x, 0, 16);
        stream_gcm_ghash_update(sctx, nonce, nonce_size);
        memset(len_block, 0, 16);
        nonce_bits = (uint64_t)nonce_size << 3;
        for (i = 7; i >= 0; --i) {
            len_block[i + 8] = (uint8_t)(nonce_bits >> (8 * (7 - i)));
        }
        for (i = 0; i < 16; ++i) {
            sctx->gcm_x[i] ^= len_block[i];
        }
        gcm_mult(sctx->gcm_x, sctx->gcm_h);
        memcpy(sctx->counter, sctx->gcm_x, 16);
        memcpy(sctx->counter_0, sctx->counter, 16);
        memset(sctx->gcm_x, 0, 16);
    }
    
    sctx->gcm_aad_len = aad_size;
    if (aad && aad_size > 0) {
        stream_gcm_ghash_update(sctx, aad, aad_size);
    }
    
    return 0;
}

int aes_gcm_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                          uint8_t* out, size_t* out_size) {
    return aes_stream_update(sctx, in, in_size, out, out_size);
}

int aes_gcm_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size,
                          uint8_t* tag, size_t* tag_size) {
    uint8_t encrypted[16];
    uint8_t stream_block[16];
    uint8_t temp[16];
    int i;
    size_t j;
    
    if (!sctx || !out || !out_size || !tag || !tag_size) {
        return -1;
    }
    
    *out_size = 0;
    if (*tag_size > 16) {
        *tag_size = 16;
    }
    
    if (sctx->buffer_len > 0) {
        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
        
        memset(temp, 0, BLOCK_SIZE);
        for (j = 0; j < sctx->buffer_len; j++) {
            temp[j] = sctx->buffer[j] ^ stream_block[j];
        }
        
        if (sctx->is_encrypt) {
            for (j = 0; j < sctx->buffer_len; j++) {
                out[j] = temp[j];
            }
        } else {
            for (j = 0; j < sctx->buffer_len; j++) {
                out[j] = temp[j];
            }
        }
        *out_size = sctx->buffer_len;
        
        stream_gcm_ghash_update(sctx, sctx->is_encrypt ? out : sctx->buffer, BLOCK_SIZE);
        sctx->gcm_data_len += sctx->buffer_len;
        
        memset(stream_block, 0, BLOCK_SIZE);
        memset(temp, 0, BLOCK_SIZE);
    }
    
    stream_gcm_ghash_final(sctx);
    
    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter_0, encrypted);
    for (i = 0; i < 16; ++i) {
        sctx->gcm_x[i] ^= encrypted[i];
    }
    
    memcpy(tag, sctx->gcm_x, *tag_size);
    
    memset(encrypted, 0, BLOCK_SIZE);
    
    return 0;
}

static int ccm_stream_mac_update(AES_StreamContext* sctx, const uint8_t* data, size_t data_len) {
    uint8_t block[16];
    uint8_t temp[16];
    size_t i, j;
    
    if (!sctx || !data) {
        return -1;
    }
    
    for (i = 0; i < data_len; i += 16) {
        memset(block, 0, 16);
        for (j = 0; j < 16 && i + j < data_len; j++) {
            block[j] = data[i + j];
        }
        for (j = 0; j < 16; j++) {
            temp[j] = sctx->ccm_mac[j] ^ block[j];
        }
        Cipher(sctx->ctx->w, sctx->ctx->Nr, temp, sctx->ccm_mac);
    }
    
    return 0;
}

int aes_ccm_stream_init(AES_StreamContext* sctx, AES_Context* ctx,
                        const uint8_t* nonce, size_t nonce_size,
                        const uint8_t* aad, size_t aad_size,
                        size_t total_len, int is_encrypt) {
    uint8_t b0[16] = {0};
    uint8_t aad_block[16];
    uint8_t len_block[16];
    int q;
    int i, j;
    
    if (!sctx || !ctx || !nonce) {
        return -1;
    }
    
    if (nonce_size < 7 || nonce_size > 13) {
        return -1;
    }
    
    memset(sctx, 0, sizeof(AES_StreamContext));
    sctx->ctx = ctx;
    sctx->mode = AES_MODE_CCM;
    sctx->is_encrypt = is_encrypt;
    memcpy(sctx->iv, nonce, nonce_size);
    sctx->ccm_total_len = total_len;
    
    q = 15 - (int)nonce_size;
    sctx->counter[0] = (uint8_t)(q - 1);
    memcpy(sctx->counter + 1, nonce, nonce_size);
    
    b0[0] = (uint8_t)(((aad_size > 0) ? 0x40 : 0x00) | (0x0C << 2) | (q - 1));
    memcpy(b0 + 1, nonce, nonce_size);
    for (i = 7; i >= 0; --i) {
        b0[16 - 1 - i] = (uint8_t)(total_len >> (8 * i));
    }
    
    Cipher(ctx->w, ctx->Nr, b0, sctx->ccm_mac);
    
    if (aad_size > 0 && aad) {
        if (aad_size <= 16) {
            memset(aad_block, 0, 16);
            aad_block[0] = (uint8_t)(aad_size >> 8);
            aad_block[1] = (uint8_t)(aad_size & 0xFF);
            memcpy(aad_block + 2, aad, aad_size);
            for (j = 0; j < 16; ++j) {
                b0[j] = sctx->ccm_mac[j] ^ aad_block[j];
            }
            Cipher(ctx->w, ctx->Nr, b0, sctx->ccm_mac);
        } else {
            memset(len_block, 0, 16);
            len_block[0] = (uint8_t)(aad_size >> 8);
            len_block[1] = (uint8_t)(aad_size & 0xFF);
            for (j = 0; j < 16; ++j) {
                b0[j] = sctx->ccm_mac[j] ^ len_block[j];
            }
            Cipher(ctx->w, ctx->Nr, b0, sctx->ccm_mac);
            
            ccm_stream_mac_update(sctx, aad, aad_size);
        }
    }
    
    sctx->ccm_buffer_len = 0;
    sctx->ccm_buffer = NULL;
    
    return 0;
}

int aes_ccm_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                          uint8_t* out, size_t* out_size) {
    uint8_t keystream[16];
    uint8_t temp[16];
    size_t i;
    int j;
    size_t remaining;
    
    if (!sctx || !in || !out || !out_size) {
        return -1;
    }
    
    *out_size = 0;
    remaining = sctx->ccm_buffer_len;
    
    if (sctx->is_encrypt) {
        for (i = 0; i < in_size; i++) {
            sctx->buffer[remaining++] = in[i];
            
            if (remaining == BLOCK_SIZE) {
                ccm_stream_mac_update(sctx, sctx->buffer, BLOCK_SIZE);
                
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
                for (j = 0; j < BLOCK_SIZE; j++) {
                    out[*out_size + j] = sctx->buffer[j] ^ keystream[j];
                }
                *out_size += BLOCK_SIZE;
                
                for (j = 15; j >= (int)(1 + (15 - sctx->counter[0] - 1)); --j) {
                    if (++sctx->counter[j] != 0) {
                        break;
                    }
                }
                remaining = 0;
            }
        }
        sctx->ccm_buffer_len = remaining;
    } else {
        for (i = 0; i < in_size; i++) {
            sctx->buffer[remaining++] = in[i];
            
            if (remaining == BLOCK_SIZE) {
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
                for (j = 0; j < BLOCK_SIZE; j++) {
                    temp[j] = sctx->buffer[j] ^ keystream[j];
                }
                
                ccm_stream_mac_update(sctx, temp, BLOCK_SIZE);
                
                for (j = 0; j < BLOCK_SIZE; j++) {
                    out[*out_size + j] = temp[j];
                }
                *out_size += BLOCK_SIZE;
                
                for (j = 15; j >= (int)(1 + (15 - sctx->counter[0] - 1)); --j) {
                    if (++sctx->counter[j] != 0) {
                        break;
                    }
                }
                remaining = 0;
            }
        }
        sctx->ccm_buffer_len = remaining;
    }
    
    memset(keystream, 0, BLOCK_SIZE);
    memset(temp, 0, BLOCK_SIZE);
    
    return 0;
}

int aes_ccm_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size,
                          uint8_t* tag, size_t* tag_size) {
    uint8_t keystream[16];
    uint8_t temp[16];
    uint8_t expected_tag[16] = {0};
    uint8_t result;
    size_t i;
    int j;
    
    if (!sctx || !out || !out_size || !tag || !tag_size) {
        return -1;
    }
    
    *out_size = 0;
    if (*tag_size > 16) {
        *tag_size = 16;
    }
    
    if (sctx->ccm_buffer_len > 0) {
        memset(temp, 0, BLOCK_SIZE);
        memcpy(temp, sctx->buffer, sctx->ccm_buffer_len);
        
        if (sctx->is_encrypt) {
            ccm_stream_mac_update(sctx, temp, BLOCK_SIZE);
            
            Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
            for (j = 0; j < (int)sctx->ccm_buffer_len; j++) {
                out[j] = sctx->buffer[j] ^ keystream[j];
            }
            *out_size = sctx->ccm_buffer_len;
        } else {
            Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
            for (j = 0; j < (int)sctx->ccm_buffer_len; j++) {
                temp[j] = sctx->buffer[j] ^ keystream[j];
            }
            ccm_stream_mac_update(sctx, temp, BLOCK_SIZE);
            
            for (j = 0; j < (int)sctx->ccm_buffer_len; j++) {
                out[j] = temp[j];
            }
            *out_size = sctx->ccm_buffer_len;
        }
        
        for (j = 15; j >= (int)(1 + (15 - sctx->counter[0] - 1)); --j) {
            if (++sctx->counter[j] != 0) {
                break;
            }
        }
    }
    
    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
    
    if (sctx->is_encrypt) {
        for (i = 0; i < *tag_size; i++) {
            tag[i] = sctx->ccm_mac[i] ^ keystream[i];
        }
    } else {
        for (i = 0; i < *tag_size; i++) {
            expected_tag[i] = tag[i] ^ keystream[i];
        }
        
        result = 0;
        for (i = 0; i < *tag_size; i++) {
            result |= sctx->ccm_mac[i] ^ expected_tag[i];
        }
        
        memset(expected_tag, 0, 16);
        
        if (result != 0) {
            memset(keystream, 0, BLOCK_SIZE);
            memset(temp, 0, BLOCK_SIZE);
            return -1;
        }
    }
    
    memset(keystream, 0, BLOCK_SIZE);
    memset(temp, 0, BLOCK_SIZE);
    
    return 0;
}