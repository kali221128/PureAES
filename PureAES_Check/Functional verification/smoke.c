/* 精确崩溃定位：self_test 里的每一步 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes_c.h"
#include "aes_keygen.h"

static void step(const char *s) {
    printf("  step: %s\n", s); fflush(stdout);
}

static int do_ecb_1blk_enc_dec(void) {
    /* AES-128 ECB: encrypt + decrypt 1 block (官方 FIPS 向量) */
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t  pt[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    uint8_t  ct[16] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
    AES_Context ctx;
    uint8_t *out; size_t osz;
    int rc;

    step("aes_init ECB");
    rc = aes_init(&ctx, AES_128, key, 16, NULL, 0);
    if (rc) { printf("aes_init fail %d\n", rc); return 1; }
    printf("  hw_flags=0x%08x Nr=%d\n", (unsigned)ctx.hw_flags, ctx.Nr); fflush(stdout);

    step("ECB encrypt 1 blk");
    out = aes_encrypt(&ctx, pt, 16, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &osz);
    if (!out) { printf("enc fail\n"); return 2; }
    printf("  enc osz=%lu out=", (unsigned long)osz);
    for (int i = 0; i < 16; ++i) printf("%02x", out[i]);
    printf("\n"); fflush(stdout);
    rc = memcmp(out, ct, 16);
    free(out);
    if (rc) { printf("enc vector mismatch!\n"); return 3; }
    step("ECB encrypt: pass");

    step("ECB decrypt 1 blk");
    out = aes_decrypt(&ctx, ct, 16, AES_MODE_ECB, AES_PADDING_NONE, NULL, 0, &osz);
    if (!out) { printf("dec fail\n"); return 4; }
    printf("  dec osz=%lu out=", (unsigned long)osz);
    for (int i = 0; i < 16; ++i) printf("%02x", out[i]);
    printf("\n"); fflush(stdout);
    rc = memcmp(out, pt, 16);
    free(out);
    aes_free(&ctx);
    if (rc) { printf("dec vector mismatch!\n"); return 5; }
    step("ECB decrypt: pass");
    return 0;
}

static int do_cbc_64kb(void) {
    /* 正好 64KB: 4096 blocks * 16 bytes */
    AES_Context ctx;
    uint8_t key[16] = {0}, iv[16] = {0};
    uint8_t *pt, *ct, *dt;
    size_t osz1, osz2;
    int fail;
    const size_t N = 4096 * 16;
    pt = (uint8_t*)malloc(N);
    ct = (uint8_t*)malloc(N + 16);
    dt = (uint8_t*)malloc(N + 16);
    if (!pt || !ct || !dt) { printf("alloc fail\n"); return 1; }
    for (size_t i = 0; i < N; ++i) pt[i] = (uint8_t)(i & 0xff);

    step("CBC 64KB: init");
    if (aes_init(&ctx, AES_128, key, 16, iv, 16) != 0) return 2;
    step("CBC 64KB: encrypt");
    {
        uint8_t *p = aes_encrypt(&ctx, pt, N, AES_MODE_CBC, AES_PADDING_NONE, iv, 16, &osz1);
        if (!p) { printf("enc fail\n"); return 3; }
        memcpy(ct, p, osz1); free(p);
        printf("  enc osz=%lu\n", (unsigned long)osz1); fflush(stdout);
    }
    step("CBC 64KB: decrypt");
    {
        uint8_t *p = aes_decrypt(&ctx, ct, osz1, AES_MODE_CBC, AES_PADDING_NONE, iv, 16, &osz2);
        if (!p) { printf("dec fail\n"); return 4; }
        memcpy(dt, p, osz2); free(p);
        printf("  dec osz=%lu\n", (unsigned long)osz2); fflush(stdout);
    }
    aes_free(&ctx);
    fail = (osz2 != N) || memcmp(dt, pt, N);
    free(pt); free(ct); free(dt);
    if (fail) { printf("CBC 64KB: MISMATCH\n"); return 5; }
    step("CBC 64KB: pass");
    return 0;
}

int main(void) {
    int r;
    printf("smoke2 start\n"); fflush(stdout);

    printf("=== test 1: ECB 1-block FIPS vector ===\n");
    r = do_ecb_1blk_enc_dec();
    if (r) { printf("TEST1 FAIL (%d)\n", r); return 1; }

    printf("=== test 2: CBC exactly 64KB (precise batch) ===\n");
    r = do_cbc_64kb();
    if (r) { printf("TEST2 FAIL (%d)\n", r); return 2; }

    printf("ALL TESTS PASSED.\n");
    return 0;
}
