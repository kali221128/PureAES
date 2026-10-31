/* 纯 AES-NI 硬件路径最小化测试，不跑软件分支 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes_c.h"

int main(void) {
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t pt[64];
    AES_Context ctx;
    uint8_t *ct, *dt;
    size_t os, os2;
    int i, fail;

    for (i = 0; i < 16; ++i) { key[i] = (uint8_t)i; iv[i] = (uint8_t)(15-i); }
    for (i = 0; i < 64; ++i) pt[i] = (uint8_t)(0xA0 | i);

    printf("1. aes_init\n"); fflush(stdout);
    if (aes_init(&ctx, AES_128, key, 16, iv, 16) != 0) return 1;
    printf("   hw_flags=0x%08lx dw=%p\n", (unsigned long)ctx.hw_flags, (void*)ctx.dw);
    if (!(ctx.hw_flags & AES_HW_NI)) {
        printf("   CPU does NOT support AES-NI. Skipping HW tests.\n");
        return 0;
    }
    if (!ctx.dw) {
        printf("   dw NOT prepared! Skip HW tests.\n");
        return 0;
    }
    fflush(stdout);

    /* 从现在开始强制走 AES-NI: 保持 hw_flags 原样 */
    printf("2. ECB 16 bytes\n"); fflush(stdout);
    ct = aes_encrypt(&ctx, pt, 16, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &os);
    if (!ct) { printf("FAIL ECB enc NULL\n"); return 1; }
    dt = aes_decrypt(&ctx, ct, os, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &os2);
    if (!dt) { printf("FAIL ECB dec NULL\n"); return 1; }
    fail = memcmp(dt, pt, 16);
    printf("   ECB: %s\n", fail ? "FAIL" : "PASS");
    free(ct); free(dt);
    if (fail) return 1;

    printf("3. CBC 64 bytes + PKCS7\n"); fflush(stdout);
    ct = aes_encrypt(&ctx, pt, 64, AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &os);
    if (!ct) { printf("FAIL CBC enc NULL\n"); return 1; }
    printf("   enc os=%lu\n", (unsigned long)os); fflush(stdout);
    dt = aes_decrypt(&ctx, ct, os, AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &os2);
    if (!dt) { printf("FAIL CBC dec NULL\n"); return 1; }
    fail = (os2 != 64) || memcmp(dt, pt, 64);
    printf("   CBC: %s (os2=%lu)\n", fail ? "FAIL" : "PASS", (unsigned long)os2);
    free(ct); free(dt);
    if (fail) return 1;

    printf("4. CFB128 65 bytes\n"); fflush(stdout);
    ct = aes_encrypt(&ctx, pt, 65, AES_MODE_CFB128, AES_PADDING_NONE, iv, 16, &os);
    if (!ct) { printf("FAIL CFB128 enc NULL\n"); return 1; }
    dt = aes_decrypt(&ctx, ct, os, AES_MODE_CFB128, AES_PADDING_NONE, iv, 16, &os2);
    if (!dt) { printf("FAIL CFB128 dec NULL\n"); return 1; }
    fail = (os2 != 65) || memcmp(dt, pt, 65);
    printf("   CFB128: %s\n", fail ? "FAIL" : "PASS");
    free(ct); free(dt);
    if (fail) return 1;

    printf("5. OFB 256KB stress\n"); fflush(stdout);
    {
        size_t big = 256 * 1024;
        uint8_t *bpt = (uint8_t*)malloc(big);
        for (i = 0; i < (int)big; ++i) bpt[i] = (uint8_t)(i * 5);
        ct = aes_encrypt(&ctx, bpt, big, AES_MODE_OFB, AES_PADDING_NONE, iv, 16, &os);
        if (!ct) { printf("FAIL OFB enc\n"); return 1; }
        dt = aes_decrypt(&ctx, ct, os, AES_MODE_OFB, AES_PADDING_NONE, iv, 16, &os2);
        fail = (os2 != big) || memcmp(dt, bpt, big);
        printf("   OFB 256KB: %s\n", fail ? "FAIL" : "PASS");
        free(bpt); free(ct); free(dt);
        if (fail) return 1;
    }

    printf("6. CTR 512KB stress\n"); fflush(stdout);
    {
        size_t big = 512 * 1024;
        uint8_t *bpt = (uint8_t*)malloc(big);
        for (i = 0; i < (int)big; ++i) bpt[i] = (uint8_t)(i * 11 + 3);
        ct = aes_encrypt(&ctx, bpt, big, AES_MODE_CTR, AES_PADDING_NONE, iv, 16, &os);
        if (!ct) { printf("FAIL CTR enc\n"); return 1; }
        dt = aes_decrypt(&ctx, ct, os, AES_MODE_CTR, AES_PADDING_NONE, iv, 16, &os2);
        fail = (os2 != big) || memcmp(dt, bpt, big);
        printf("   CTR 512KB: %s\n", fail ? "FAIL" : "PASS");
        free(bpt); free(ct); free(dt);
        if (fail) return 1;
    }

    aes_free(&ctx);
    printf("ALL AES-NI HW TESTS PASSED.\n");
    return 0;
}
