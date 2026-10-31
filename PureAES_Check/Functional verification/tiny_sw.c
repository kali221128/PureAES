/* 最小化崩溃测试: 只跑 CPUID + ECB 纯C软件路径 + 简单 CBC */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes_c.h"

int main(void) {
    uint8_t key[16] = {0};
    uint8_t iv[16]  = {0};
    uint8_t  pt[32] = {0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                       0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                       0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
                       0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42};
    AES_Context ctx;
    uint8_t *ct, *dt;
    size_t os, os2;
    int i, fail;

    memset(&ctx, 0, sizeof(ctx));
    for (i = 0; i < 16; ++i) { key[i] = (uint8_t)i; iv[i] = (uint8_t)(15-i); }

    printf("1. aes_init...\n"); fflush(stdout);
    if (aes_init(&ctx, AES_128, key, 16, iv, 16) != 0) { printf("FAIL init\n"); return 1; }
    printf("   hw_flags=0x%08lx Nr=%d w=%p dw=%p\n",
           (unsigned long)ctx.hw_flags, ctx.Nr, (void*)ctx.w, (void*)ctx.dw);
    fflush(stdout);

    /* ==== 强制禁用 AES-NI: 清零 hw_flags ==== */
    ctx.hw_flags = 0;
    printf("2. Force software path. ECB enc(16)\n"); fflush(stdout);

    ct = aes_encrypt(&ctx, pt, 16, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &os);
    if (!ct) { printf("FAIL enc NULL\n"); return 1; }
    printf("   enc ok os=%lu\n", (unsigned long)os); fflush(stdout);

    dt = aes_decrypt(&ctx, ct, os, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &os2);
    if (!dt) { printf("FAIL dec NULL\n"); return 1; }
    fail = memcmp(dt, pt, 16);
    printf("3. ECB 16 roundtrip: %s\n", fail ? "FAIL" : "PASS");
    free(ct); free(dt);
    if (fail) return 1;

    printf("4. CBC 32 bytes + PKCS7\n"); fflush(stdout);
    ct = aes_encrypt(&ctx, pt, 32, AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &os);
    if (!ct) { printf("FAIL cbc enc\n"); return 1; }
    printf("   CBC enc os=%lu\n", (unsigned long)os); fflush(stdout);
    dt = aes_decrypt(&ctx, ct, os, AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &os2);
    if (!dt) { printf("FAIL cbc dec\n"); return 1; }
    fail = (os2 != 32) || memcmp(dt, pt, 32);
    printf("5. CBC 32 roundtrip: %s (os2=%lu)\n", fail?"FAIL":"PASS", (unsigned long)os2);
    free(ct); free(dt);
    if (fail) return 1;

    printf("6. CFB128 33 bytes\n"); fflush(stdout);
    ct = aes_encrypt(&ctx, pt, 33, AES_MODE_CFB128, AES_PADDING_NONE, iv, 16, &os);
    if (!ct) { printf("FAIL cfb128 enc\n"); return 1; }
    dt = aes_decrypt(&ctx, ct, os, AES_MODE_CFB128, AES_PADDING_NONE, iv, 16, &os2);
    if (!dt) { printf("FAIL cfb128 dec\n"); return 1; }
    fail = (os2 != 33) || memcmp(dt, pt, 33);
    printf("   CFB128 roundtrip: %s\n", fail?"FAIL":"PASS");
    free(ct); free(dt);
    if (fail) return 1;

    printf("7. OFB 64KB (65536 bytes) bulk stress\n"); fflush(stdout);
    {
        size_t big = 65536;
        uint8_t *bpt = (uint8_t*)malloc(big);
        for (i = 0; i < (int)big; ++i) bpt[i] = (uint8_t)(i*3);
        ct = aes_encrypt(&ctx, bpt, big, AES_MODE_OFB, AES_PADDING_NONE, iv, 16, &os);
        if (!ct) { printf("FAIL ofb enc\n"); return 1; }
        dt = aes_decrypt(&ctx, ct, os, AES_MODE_OFB, AES_PADDING_NONE, iv, 16, &os2);
        fail = (os2 != big) || memcmp(dt, bpt, big);
        printf("   OFB bulk: %s\n", fail?"FAIL":"PASS");
        free(bpt); free(ct); free(dt);
        if (fail) return 1;
    }

    printf("8. CTR 128KB bulk stress\n"); fflush(stdout);
    {
        size_t big = 128 * 1024;
        uint8_t *bpt = (uint8_t*)malloc(big);
        for (i = 0; i < (int)big; ++i) bpt[i] = (uint8_t)(i*7 + 1);
        ct = aes_encrypt(&ctx, bpt, big, AES_MODE_CTR, AES_PADDING_NONE, iv, 16, &os);
        if (!ct) { printf("FAIL ctr enc\n"); return 1; }
        dt = aes_decrypt(&ctx, ct, os, AES_MODE_CTR, AES_PADDING_NONE, iv, 16, &os2);
        fail = (os2 != big) || memcmp(dt, bpt, big);
        printf("   CTR bulk: %s\n", fail?"FAIL":"PASS");
        free(bpt); free(ct); free(dt);
        if (fail) return 1;
    }

    aes_free(&ctx);
    printf("ALL SW TESTS PASSED.\n");
    return 0;
}
