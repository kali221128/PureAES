/* 全模式 AES 基准测试 (纯软件路径) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include "aes_c.h"
#include "aes_keygen.h"

#define MB (1024 * 1024)
#define DATA_SIZE (8 * MB)

static double get_sec(void) {
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER now;
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart / (double)freq.QuadPart;
}

static void bench_mode(AES_Context *ctx, AES_Mode mode, const char *name,
                       const uint8_t *plain, const uint8_t *iv, size_t data_size) {
    size_t out_sz;
    double t0, t1;
    uint8_t *cipher, *dec;

    /* warmup */
    cipher = aes_encrypt(ctx, plain, 4096, mode, AES_PADDING_NONE, iv, 16, &out_sz);
    if (cipher) free(cipher);

    /* encrypt */
    t0 = get_sec();
    cipher = aes_encrypt(ctx, plain, data_size, mode, AES_PADDING_NONE, iv, 16, &out_sz);
    t1 = get_sec();
    if (!cipher) { printf("%-10s  encrypt FAIL\n", name); return; }
    printf("%-10s  enc: %7.2f MB/s", name, (double)data_size / MB / (t1 - t0));

    /* decrypt */
    t0 = get_sec();
    dec = aes_decrypt(ctx, cipher, out_sz, mode, AES_PADDING_NONE, iv, 16, &out_sz);
    t1 = get_sec();
    if (!dec) { printf("  dec: FAIL\n"); free(cipher); return; }
    printf("  dec: %7.2f MB/s", (double)data_size / MB / (t1 - t0));

    /* correctness */
    int ok = (out_sz == data_size && memcmp(dec, plain, data_size) == 0);
    printf("  %s\n", ok ? "OK" : "MISMATCH");
    free(cipher); free(dec);
}

static void bench_gcm(AES_Context *ctx, const uint8_t *plain, const uint8_t *nonce, size_t data_size) {
    size_t out_sz;
    uint8_t tag[16];
    double t0, t1;
    uint8_t *cipher, *dec;

    /* warmup */
    cipher = aes_gcm_encrypt(ctx, plain, 4096, nonce, 12, NULL, 0, tag, 16, &out_sz);
    if (cipher) free(cipher);

    t0 = get_sec();
    cipher = aes_gcm_encrypt(ctx, plain, data_size, nonce, 12, NULL, 0, tag, 16, &out_sz);
    t1 = get_sec();
    if (!cipher) { printf("%-10s  encrypt FAIL\n", "GCM"); return; }
    printf("%-10s  enc: %7.2f MB/s", "GCM", (double)data_size / MB / (t1 - t0));

    t0 = get_sec();
    dec = aes_gcm_decrypt(ctx, cipher, out_sz, nonce, 12, NULL, 0, tag, 16, &out_sz);
    t1 = get_sec();
    if (!dec) { printf("  dec: FAIL (tag verify)\n"); free(cipher); return; }
    printf("  dec: %7.2f MB/s", (double)data_size / MB / (t1 - t0));

    int ok = (out_sz == data_size && memcmp(dec, plain, data_size) == 0);
    printf("  %s\n", ok ? "OK" : "MISMATCH");
    free(cipher); free(dec);
}

static void bench_ccm(AES_Context *ctx, const uint8_t *plain, const uint8_t *nonce, size_t data_size) {
    size_t out_sz;
    uint8_t tag[16];
    double t0, t1;
    uint8_t *cipher, *dec;

    /* warmup */
    cipher = aes_ccm_encrypt(ctx, plain, 4096, nonce, 12, NULL, 0, tag, 16, &out_sz);
    if (cipher) free(cipher);

    t0 = get_sec();
    cipher = aes_ccm_encrypt(ctx, plain, data_size, nonce, 12, NULL, 0, tag, 16, &out_sz);
    t1 = get_sec();
    if (!cipher) { printf("%-10s  encrypt FAIL\n", "CCM"); return; }
    printf("%-10s  enc: %7.2f MB/s", "CCM", (double)data_size / MB / (t1 - t0));

    t0 = get_sec();
    dec = aes_ccm_decrypt(ctx, cipher, out_sz, nonce, 12, NULL, 0, tag, 16, &out_sz);
    t1 = get_sec();
    if (!dec) { printf("  dec: FAIL (tag verify)\n"); free(cipher); return; }
    printf("  dec: %7.2f MB/s", (double)data_size / MB / (t1 - t0));

    int ok = (out_sz == data_size && memcmp(dec, plain, data_size) == 0);
    printf("  %s\n", ok ? "OK" : "MISMATCH");
    free(cipher); free(dec);
}

int main(void) {
    AES_Context ctx;
    uint8_t key[32], iv[16], nonce[12];
    uint8_t *plain;

    aes_random_bytes(key, 32);
    aes_random_bytes(iv, 16);
    aes_random_bytes(nonce, 12);

    plain = (uint8_t*)malloc(DATA_SIZE + 64);
    for (size_t i = 0; i < DATA_SIZE; i++) plain[i] = (uint8_t)(i * 31 + 17);

    /* AES-128 基准 */
    aes_init(&ctx, AES_128, key, 16, iv, 16);
    printf("=== AES-128 全模式基准 (纯软件, %lu MB) ===\n\n", (unsigned long)(DATA_SIZE / MB));
    printf("%-10s  %s\n", "Mode", "Throughput");
    printf("------------------------------------------\n");
    bench_mode(&ctx, AES_MODE_ECB,    "ECB",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CBC,    "CBC",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CTR,    "CTR",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_OFB,    "OFB",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CFB128, "CFB128", plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CFB8,   "CFB8",   plain, iv, DATA_SIZE / 4);
    bench_gcm(&ctx,                   plain, nonce, DATA_SIZE);
    bench_ccm(&ctx,                   plain, nonce, DATA_SIZE);
    aes_free(&ctx);

    printf("\n");
    /* AES-256 基准 */
    aes_init(&ctx, AES_256, key, 32, iv, 16);
    printf("=== AES-256 全模式基准 (纯软件, %lu MB) ===\n\n", (unsigned long)(DATA_SIZE / MB));
    printf("%-10s  %s\n", "Mode", "Throughput");
    printf("------------------------------------------\n");
    bench_mode(&ctx, AES_MODE_ECB,    "ECB",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CBC,    "CBC",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CTR,    "CTR",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_OFB,    "OFB",    plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CFB128, "CFB128", plain, iv, DATA_SIZE);
    bench_mode(&ctx, AES_MODE_CFB8,   "CFB8",   plain, iv, DATA_SIZE / 4);
    bench_gcm(&ctx,                   plain, nonce, DATA_SIZE);
    bench_ccm(&ctx,                   plain, nonce, DATA_SIZE);
    aes_free(&ctx);

    free(plain);
    return 0;
}
