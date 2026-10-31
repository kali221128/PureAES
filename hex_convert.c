#include "hex_convert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char hex_upper_tbl[] = "0123456789ABCDEF";

static uint8_t hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return 0xFF;
}

static int is_valid_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

char* hex_to_string(const uint8_t* data, size_t size) {
    char* hex;
    size_t i;
    
    if (!data || size == 0) return NULL;
    
    hex = (char*)malloc(size * 2 + 1);
    if (!hex) return NULL;
    
    for (i = 0; i < size; i++) {
        hex[i * 2]     = hex_upper_tbl[(data[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_upper_tbl[data[i] & 0x0F];
    }
    hex[size * 2] = '\0';
    
    return hex;
}

uint8_t* string_to_hex(const char* hex, size_t* out_size) {
    size_t len;
    uint8_t* data;
    size_t i;
    char hi, lo;
    
    if (!hex || !out_size) return NULL;
    
    len = strlen(hex);
    if (len % 2 != 0) {
        *out_size = 0;
        return NULL;
    }
    
    *out_size = len / 2;
    data = (uint8_t*)malloc(*out_size);
    if (!data) {
        *out_size = 0;
        return NULL;
    }
    
    for (i = 0; i < *out_size; i++) {
        hi = hex[i * 2];
        lo = hex[i * 2 + 1];
        
        if (!is_valid_hex_char(hi) || !is_valid_hex_char(lo)) {
            free(data);
            *out_size = 0;
            return NULL;
        }
        
        data[i] = (hex_char_to_byte(hi) << 4) | hex_char_to_byte(lo);
    }
    
    return data;
}