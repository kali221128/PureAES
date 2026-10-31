#include "aes_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    uint8_t main_key[32]; for (int i=0;i<32;i++) main_key[i]=i+1;
    uint8_t tweak_key[32]; for (int i=0;i<32;i++) tweak_key[i]=i+101;
    uint8_t tweak[16] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    uint8_t pt[100]; for (int i=0;i<100;i++) pt[i]=(uint8_t)(i*7+3);
    
    AES_Context ctx;
    aes_init(&ctx, AES_256, main_key, 32, NULL, 0);
    printf("hw_flags=0x%08x Nr=%d\n", ctx.hw_flags, ctx.Nr);

    size_t out_size;
    uint8_t *ct = aes_xts_encrypt(&ctx, pt, 100, tweak_key, tweak, 16, &out_size);
    printf("enc out_size=%zu (expect 100)\n", out_size);
    if (!ct) { printf("XTS enc NULL FAIL\n"); return 1; }

    size_t dec_size;
    uint8_t *pt2 = aes_xts_decrypt(&ctx, ct, out_size, tweak_key, tweak, 16, &dec_size);
    printf("dec out_size=%zu match=%d\n", dec_size, memcmp(pt, pt2, 100)==0);
    if (memcmp(pt, pt2, 100)!=0) { printf("XTS ROUNDTRIP MISMATCH\n"); return 1; }

    /* short plaintext < 16 */
    uint8_t small_pt[3] = {0xAA,0xBB,0xCC};
    uint8_t small_tweak[16] = {2,0};
    uint8_t *ct2 = aes_xts_encrypt(&ctx, small_pt, 3, tweak_key, small_tweak, 16, &out_size);
    uint8_t *pt3 = aes_xts_decrypt(&ctx, ct2, out_size, tweak_key, small_tweak, 16, &dec_size);
    printf("xts short 3B dec match=%d\n", (dec_size==3 && memcmp(small_pt, pt3, 3)==0));

    /* single key (tweak_key=NULL) */
    uint8_t *ct3 = aes_xts_encrypt(&ctx, pt, 100, NULL, tweak, 16, &out_size);
    uint8_t *pt4 = aes_xts_decrypt(&ctx, ct3, out_size, NULL, tweak, 16, &dec_size);
    printf("xts single-key match=%d\n", (dec_size==100 && memcmp(pt, pt4, 100)==0));

    free(ct); free(pt2); free(ct2); free(pt3); free(ct3); free(pt4);
    aes_free(&ctx);
    printf("=== XTS ALL OK ===\n");
    return 0;
}
