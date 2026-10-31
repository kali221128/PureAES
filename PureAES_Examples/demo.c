#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes_c.h"

int main(void) {
    AES_Context ctx;
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const char* msg = "Hello, PureAES!";
    size_t out_size;
    uint8_t *cipher, *plain;
    int i;

    if (aes_init(&ctx, AES_128, key, sizeof(key), iv, sizeof(iv)) != 0) {
        printf("aes_init failed\n");
        return 1;
    }
    printf("hw_flags = 0x%08x, Nr = %d\n", ctx.hw_flags, ctx.Nr);

    cipher = aes_encrypt(&ctx, (const uint8_t*)msg, strlen(msg),
                         AES_MODE_CBC, AES_PADDING_PKCS7, iv, sizeof(iv), &out_size);
    if (!cipher) { printf("encrypt failed\n"); return 1; }
    printf("cipher (%d bytes): ", (int)out_size);
    for (i = 0; i < (int)out_size; i++) printf("%02x", cipher[i]);
    printf("\n");

    plain = aes_decrypt(&ctx, cipher, out_size,
                        AES_MODE_CBC, AES_PADDING_PKCS7, iv, sizeof(iv), &out_size);
    if (!plain) { printf("decrypt failed\n"); return 1; }
    printf("plain: %.*s\n", (int)out_size, plain);

    free(cipher);
    free(plain);
    aes_free(&ctx);
    return 0;
}
