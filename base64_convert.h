#ifndef BASE64_CONVERT_H
#define BASE64_CONVERT_H

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

char* base64_encode(const uint8_t* data, size_t size);

uint8_t* base64_decode(const char* base64, size_t* out_size);

#ifdef __cplusplus
}
#endif

#endif