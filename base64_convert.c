#include "base64_convert.h"
#include <stdlib.h>
#include <string.h>

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";

static int base64_char_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

char* base64_encode(const uint8_t* data, size_t size) {
    size_t output_len;
    char* encoded;
    size_t i, j;
    uint32_t octet_a, octet_b, octet_c;
    uint32_t triple;
    
    if (!data || size == 0) return NULL;
    
    output_len = ((size + 2) / 3) * 4;
    encoded = (char*)malloc(output_len + 1);
    if (!encoded) return NULL;
    
    i = 0;
    j = 0;
    while (i < size) {
        octet_a = (i < size) ? data[i++] : 0;
        octet_b = (i < size) ? data[i++] : 0;
        octet_c = (i < size) ? data[i++] : 0;
        
        triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        encoded[j++] = base64_chars[(triple >> 18) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 12) & 0x3F];
        encoded[j++] = (i <= size + 1) ? base64_chars[(triple >> 6) & 0x3F] : '=';
        encoded[j++] = (i <= size) ? base64_chars[triple & 0x3F] : '=';
    }
    
    encoded[j] = '\0';
    return encoded;
}

uint8_t* base64_decode(const char* base64, size_t* out_size) {
    size_t len;
    size_t padding;
    uint8_t* decoded;
    size_t i, j;
    int octet_a, octet_b, octet_c, octet_d;
    uint32_t triple;
    
    if (!base64 || !out_size) return NULL;
    
    len = strlen(base64);
    if (len % 4 != 0) {
        *out_size = 0;
        return NULL;
    }
    
    padding = 0;
    if (base64[len - 1] == '=') padding++;
    if (base64[len - 2] == '=') padding++;
    
    *out_size = (len / 4) * 3 - padding;
    decoded = (uint8_t*)malloc(*out_size);
    if (!decoded) {
        *out_size = 0;
        return NULL;
    }
    
    i = 0;
    j = 0;
    while (i < len) {
        octet_a = base64_char_index(base64[i++]);
        octet_b = base64_char_index(base64[i++]);
        octet_c = base64_char_index(base64[i++]);
        octet_d = base64_char_index(base64[i++]);
        
        if (octet_a == -1 || octet_b == -1 || octet_c == -1 || octet_d == -1) {
            free(decoded);
            *out_size = 0;
            return NULL;
        }
        
        triple = ((uint32_t)octet_a << 18) | ((uint32_t)octet_b << 12) |
                          ((uint32_t)octet_c << 6) | (uint32_t)octet_d;
        
        if (j < *out_size) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < *out_size) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < *out_size) decoded[j++] = triple & 0xFF;
    }
    
    return decoded;
}