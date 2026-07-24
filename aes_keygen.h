#ifndef AES_KEYGEN_H
#define AES_KEYGEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
#else
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#include <stdint.h>
#else
#if defined(__GNUC__)
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
#endif
#endif
#endif

uint8_t* aes_generate_key(size_t key_size);

uint8_t* aes_generate_iv(size_t iv_size);

int aes_random_bytes(uint8_t* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif