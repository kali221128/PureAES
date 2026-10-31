#ifndef HEX_CONVERT_H
#define HEX_CONVERT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#if defined(_MSC_VER) && _MSC_VER < 1600
typedef unsigned char uint8_t;
#else
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#include <stdint.h>
#else
#if defined(__GNUC__)
#include <stdint.h>
#else
typedef unsigned char uint8_t;
#endif
#endif
#endif

char* hex_to_string(const uint8_t* data, size_t size);

uint8_t* string_to_hex(const char* hex, size_t* out_size);

#ifdef __cplusplus
}
#endif

#endif