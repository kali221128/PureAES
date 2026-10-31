#include "aes_c.h"
#include "hex_convert.h"
#include "base64_convert.h"
#include "aes_keygen.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* ============================================================
 * AES-NI / SSE 硬件加速段：
 *   - 首选: 全局编译标志 -maes -msse2 -mpclmul → 定义了 __AES__, __SSE2__, __PCLMUL__
 *     此时直接使用 intrinsics，ABI/寄存器保存由编译器全局保证，最稳定。
 *   - 回退: 无全局标志时，不启用 AES-NI 硬件路径（避免 per-function target
 *     属性在老 MinGW.org、32-bit PIC 等场景下的 ABI 保存崩溃）。
 *   - 运行时: 若编译期未启用 AES-NI 但 CPU 支持，则 hw_flags 仍会置位，
 *     但 aes_encrypt/aes_decrypt 中对应 AESNI 代码被 #if 裁掉，自动走纯 C。
 * ========================================================== */

/* 全局编译期是否可使用 AES-NI intrinsics？必须同时满足：
 *   1) 有 <wmmintrin.h> 头文件
 *   2) 全局定义 __AES__ (即 -maes 被传入)，避免 per-function target ABI 坑
 */
#if defined(__has_include)
#  if __has_include(<wmmintrin.h>) && defined(__AES__) && defined(__SSE2__)
#    define AES_HAS_WMMINTRIN  1
#    include <wmmintrin.h>
#    include <emmintrin.h>
#    include <xmmintrin.h>
#  else
#    define AES_HAS_WMMINTRIN  0
#  endif
#else
/* 老编译器：保守要求必须全局定义 __AES__ */
#  if defined(__AES__) && defined(__SSE2__)
#    define AES_HAS_WMMINTRIN  1
#    include <wmmintrin.h>
#    include <emmintrin.h>
#    include <xmmintrin.h>
#  else
#    define AES_HAS_WMMINTRIN  0
#  endif
#endif

#if AES_HAS_WMMINTRIN == 1
   /* 全局已启用 AES/SSE：不需要 per-function target 属性，保持 static inline 即可 */
#  define AESNI_FUNC  static inline
#else
   /* 编译期未启用 AES-NI：此宏不会被用到 (所有 AESNI_FUNC 定义都包裹在 AES_HAS_WMMINTRIN 下) */
#  define AESNI_FUNC  static inline
#endif

/* ARMv8 NEON AES Extension 编译期检测 */
#if defined(__aarch64__) && defined(__ARM_FEATURE_AES) && __ARM_FEATURE_AES == 1
#  define AES_HAS_ARM_AES  1
#else
#  define AES_HAS_ARM_AES  0
#endif
#if AES_HAS_ARM_AES == 1
#  include <arm_neon.h>
#endif

/* CPUID 硬件检测：返回 AES_HW_* 位组合 */
static uint32_t aes_detect_hw(void) {
    uint32_t flags = AES_HW_NONE;
#if defined(_MSC_VER)
    int info[4] = {0,0,0,0};
    __cpuidex(info, 1, 0);
    if (info[2] & (1 << 25)) flags |= AES_HW_NI;
    if (info[2] & (1 <<  1)) flags |= AES_HW_PCLMUL;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
#  if defined(__i386__) && defined(__PIC__)
    /* 32-bit x86 PIC: %ebx 是 GOT 指针，必须保存/恢复。用栈包一层 */
    __asm__ __volatile__ (
        "pushl %%ebx\n\t"
        "cpuid\n\t"
        "movl %%ebx, %1\n\t"
        "popl %%ebx\n\t"
        : "=a"(eax), "=r"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1), "c"(0)
    );
#  else
    __asm__ __volatile__ (
        "cpuid\n\t"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1), "c"(0)
    );
#  endif
    if (ecx & (1u << 25)) flags |= AES_HW_NI;
    if (ecx & (1u <<  1)) flags |= AES_HW_PCLMUL;
#endif
#if AES_HAS_ARM_AES == 1
    flags |= AES_HW_NEON;
#endif
#if defined(__linux__) && defined(__aarch64__)
    /* Linux ARM64 运行时: 读 /proc/self/auxv AT_HWCAP2 */
    {
        unsigned long hwcaps = 0;
        FILE *fp = fopen("/proc/self/auxv", "rb");
        if (fp) {
            struct { unsigned long a_type; unsigned long a_val; } e;
            while (fread(&e, sizeof(e), 1, fp) == 1) {
                if (e.a_type == 0x00000010 /* AT_HWCAP */) { hwcaps = e.a_val; break; }
            }
            fclose(fp);
        }
        /* HWCAP bit 1 = AES (ARMv8) */
        if (hwcaps & (1UL << 1)) flags |= AES_HW_NEON;
    }
#endif
    return flags;
}

#define Nb 4

static const uint8_t sbox[256] __attribute__((aligned(64))) = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] __attribute__((aligned(64))) = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit;
    int i;
    for (i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* ============================================================================
 * AES 查找表 T-box (Brian Gladman 风格纯C实现)
 *
 *   Te0..Te3 : 加密轮 T-Box, Sbox + ShiftRows + MixColumns 合并
 *   Td0..Td3 : 解密轮 T-Box, InvMixColumns + InvShiftRows + InvSbox 合并
 *
 * 每张表 256 × 32-bit = 1KB, 总共 8KB L1 常量表, 纯C可移植
 * ==========================================================================*/

#include <stdint.h>

typedef uint32_t u32;
typedef uint8_t  u8;

/* 注意：以下 SubBytes / InvSubBytes / ShiftRows / InvShiftRows 需要在前声明，
 * 用于 T-box 路径的最后一轮 */
static void SubBytes(uint8_t* state);
static void InvSubBytes(uint8_t* state);
static void ShiftRows(uint8_t* state);
static void InvShiftRows(uint8_t* state);
static void AddRoundKey(uint8_t* state, const uint8_t* w, int round);
static void MixColumns(uint8_t* state);
static void InvMixColumns(uint8_t* state);

static u32 Te0[256] __attribute__((aligned(64))), Te1[256] __attribute__((aligned(64))),
           Te2[256] __attribute__((aligned(64))), Te3[256] __attribute__((aligned(64)));
static u32 Td0[256] __attribute__((aligned(64))), Td1[256] __attribute__((aligned(64))),
           Td2[256] __attribute__((aligned(64))), Td3[256] __attribute__((aligned(64)));
static u32 Te4[256] __attribute__((aligned(64))), Td4[256] __attribute__((aligned(64)));
static u32 Imc0[256] __attribute__((aligned(64))), Imc1[256] __attribute__((aligned(64))),
           Imc2[256] __attribute__((aligned(64))), Imc3[256] __attribute__((aligned(64)));
static int  aes_tables_ready = 0;

/* 小端字节序工具: 把 4 字节打包成 uint32_t */
static inline u32 pack_u32_le(const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static inline void unpack_u32_le(u32 v, u8 *p) {
    p[0] = (u8)(v);
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

static void aes_init_tables(void) {
    int i;
    if (aes_tables_ready) return;
    for (i = 0; i < 256; ++i) {
        u8 s  = sbox[i];
        u8 s2 = gf_mult(s, 2);
        u8 s3 = gf_mult(s, 3);
        /* 加密 T 盒：列向量 [2,3,1,1] * s，按列方向分别对应 s0,s1,s2,s3 位置旋转 */
        Te0[i] = ((u32)s2)      | ((u32)s  << 8) | ((u32)s  << 16) | ((u32)s3 << 24);
        Te1[i] = ((u32)s3)      | ((u32)s2 << 8) | ((u32)s  << 16) | ((u32)s  << 24);
        Te2[i] = ((u32)s )      | ((u32)s3 << 8) | ((u32)s2 << 16) | ((u32)s  << 24);
        Te3[i] = ((u32)s )      | ((u32)s  << 8) | ((u32)s3 << 16) | ((u32)s2 << 24);
        /* Te4: 最后一轮专用, 只含 S-Box 值 (4 字节相同), 无 MixColumns 乘法 */
        Te4[i] = ((u32)s)       | ((u32)s  << 8) | ((u32)s  << 16) | ((u32)s  << 24);
    }
    for (i = 0; i < 256; ++i) {
        u8 t  = inv_sbox[i];
        u8 t9  = gf_mult(t, 9);
        u8 tb  = gf_mult(t, 11);
        u8 td  = gf_mult(t, 13);
        u8 te_ = gf_mult(t, 14);
        /* 解密 T 盒：InvMixColumns 矩阵 [14,11,13,9] * t */
        Td0[i] = ((u32)te_)     | ((u32)t9  << 8) | ((u32)td  << 16) | ((u32)tb  << 24);
        Td1[i] = ((u32)tb )     | ((u32)te_ << 8) | ((u32)t9  << 16) | ((u32)td  << 24);
        Td2[i] = ((u32)td )     | ((u32)tb  << 8) | ((u32)te_ << 16) | ((u32)t9  << 24);
        Td3[i] = ((u32)t9 )     | ((u32)td  << 8) | ((u32)tb  << 16) | ((u32)te_ << 24);
        /* Td4: 最后一轮专用, 只含 InvS-Box 值 (4 字节相同), 无 InvMixColumns 乘法 */
        Td4[i] = ((u32)t)       | ((u32)t  << 8) | ((u32)t  << 16) | ((u32)t  << 24);
    }
    /* InvMixColumns 专用查表格：每表对应一列的 4 个 inv_mix 系数字节 */
    for (i = 0; i < 256; ++i) {
        u8 x = (u8)i;
        u8 g9  = gf_mult(x, 9);
        u8 g11 = gf_mult(x, 11);
        u8 g13 = gf_mult(x, 13);
        u8 g14 = gf_mult(x, 14);
        /* 按小端顺序排列列向量 [g14, g9, g13, g11]，用于列第一个字节查表 */
        Imc0[i] = ((u32)g14)      | ((u32)g9  << 8) | ((u32)g13 << 16) | ((u32)g11 << 24);
        Imc1[i] = ((u32)g11)      | ((u32)g14 << 8) | ((u32)g9  << 16) | ((u32)g13 << 24);
        Imc2[i] = ((u32)g13)      | ((u32)g11 << 8) | ((u32)g14 << 16) | ((u32)g9  << 24);
        Imc3[i] = ((u32)g9 )      | ((u32)g13 << 8) | ((u32)g11 << 16) | ((u32)g14 << 24);
    }
    aes_tables_ready = 1;
}

/* =========================================================================
 * AES-NI 硬件加速单块 (16 字节) 加密/解密
 *   - Encrypt: 直接用 ctx->w (和软件 path 相同)
 *   - Decrypt: 必须用 ctx->dw (等效解密结构：中间轮密钥先 InvMixColumns)
 * ========================================================================= */
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1

AESNI_FUNC void
aesni_encrypt_block(const uint8_t *rk_bytes, int Nr,
                    const uint8_t in[16], uint8_t out[16])
{
    const __m128i *rk = (const __m128i *)(const void *)rk_bytes;
    __m128i s = _mm_loadu_si128((const __m128i *)in);
    int r;
    /* 所有 rk[i] 都显式 loadu → 保证 movdqu, 禁止编译器用 movdqa 假定 16 字节对齐 */
    s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
    for (r = 1; r < Nr; ++r) {
        s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
    }
    s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
    _mm_storeu_si128((__m128i *)out, s);
}

AESNI_FUNC void
aesni_decrypt_block(const uint8_t *drk_bytes, int Nr,
                    const uint8_t in[16], uint8_t out[16])
{
    /* drk_bytes = ctx->dw: 已按等效解密密钥准备 */
    const __m128i *drk = (const __m128i *)(const void *)drk_bytes;
    __m128i s = _mm_loadu_si128((const __m128i *)in);
    int r;
    s = _mm_xor_si128(s, _mm_loadu_si128(drk + Nr));
    for (r = Nr - 1; r >= 1; --r) {
        s = _mm_aesdec_si128(s, _mm_loadu_si128(drk + r));
    }
    s = _mm_aesdeclast_si128(s, _mm_loadu_si128(drk + 0));
    _mm_storeu_si128((__m128i *)out, s);
}

AESNI_FUNC void
aesni_ctr_block_x(const uint8_t *rk_bytes, int Nr,
                   uint8_t counter[16],
                   const uint8_t *__restrict src,
                   uint8_t *__restrict dst, size_t blocks)
{
    /* 通用 CTR: 对 counter++ 得到的多块 keystream 与 src XOR 写 dst.
       blocks 必须 <= 2^16 (安全起见用 unsigned). */
    const __m128i *rk = (const __m128i *)(const void *)rk_bytes;
    size_t i;
    for (i = 0; i < blocks; ++i) {
        __m128i ctr = _mm_loadu_si128((const __m128i *)counter);
        __m128i ks = _mm_xor_si128(ctr, _mm_loadu_si128(rk + 0));
        int r;
        for (r = 1; r < Nr; ++r) ks = _mm_aesenc_si128(ks, _mm_loadu_si128(rk + r));
        ks = _mm_aesenclast_si128(ks, _mm_loadu_si128(rk + Nr));
        if (src) {
            __m128i pl = _mm_loadu_si128((const __m128i *)src);
            __m128i cb = _mm_xor_si128(ks, pl);
            _mm_storeu_si128((__m128i *)dst, cb);
            src += 16;
        } else {
            _mm_storeu_si128((__m128i *)dst, ks);
        }
        dst += 16;
        /* counter += 1 (big endian 最后 16 字节计数器, 与软件 path 一致: 从尾到头自增) */
        {
            int j;
            for (j = 15; j >= 0; --j) {
                if (++counter[j] != 0) break;
            }
        }
    }
}

#endif /* AES_HAS_WMMINTRIN */

/* =========================================================================
 * 生成等效解密密钥 ctx->dw: 把 w[1..Nr-1] 每块做 InvMixColumns
 *   - w[0]  &  w[Nr] 原样拷贝 (首轮 & 末轮不需要 IMC)
 *   - 其余中间轮逐块 InvMixColumns
 * ========================================================================= */
static int aes_prepare_decrypt_keys(AES_Context *ctx) {
    int i;
    const uint8_t *w = ctx->w;
    uint8_t *dw;
    size_t w_bytes = (size_t)BLOCK_SIZE * (ctx->Nr + 1);

    if (ctx->dw) free(ctx->dw);
    ctx->dw = (uint8_t *)malloc(w_bytes);
    if (!ctx->dw) return -1;
    dw = ctx->dw;

    /* 首尾两块直接拷贝 */
    memcpy(dw, w, BLOCK_SIZE);
    memcpy(dw + (size_t)ctx->Nr * BLOCK_SIZE,
           w  + (size_t)ctx->Nr * BLOCK_SIZE,
           BLOCK_SIZE);

    if (!aes_tables_ready) aes_init_tables();

    for (i = 1; i < ctx->Nr; ++i) {
        const uint8_t *src = w + (size_t)i * BLOCK_SIZE;
        uint8_t       *dst = dw + (size_t)i * BLOCK_SIZE;
        /* 逐列做 InvMixColumns: 复用 Imc0..Imc3 查表 */
        int col;
        for (col = 0; col < 4; ++col) {
            int base = col * 4;
            u32 c =
                Imc0[src[base + 0]] ^
                Imc1[src[base + 1]] ^
                Imc2[src[base + 2]] ^
                Imc3[src[base + 3]];
            unpack_u32_le(c, dst + base);
        }
    }
    return 0;
}

/* 加密轮核心（T-Box 路径） */
static inline void
Cipher_fast(const u8 *w, int Nr, const u8 *in, u8 *out)
{
    u32 s0, s1, s2, s3;
    u32 t0, t1, t2, t3;
    int rnd;

    /* 从 key-schedule 取轮密钥按 4 个 u32 列访问 */
    const u32 *rk = (const u32 *)(const void *)w;

    /* 初始 AddRoundKey */
    s0 = pack_u32_le(in + 0)  ^ rk[0];
    s1 = pack_u32_le(in + 4)  ^ rk[1];
    s2 = pack_u32_le(in + 8)  ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];
    rk += 4;

    /* 中间 Nr-1 轮 */
    for (rnd = 1; rnd < Nr; ++rnd) {
        t0 =
            Te0[(s0 >>  0) & 0xFF] ^
            Te1[(s1 >>  8) & 0xFF] ^
            Te2[(s2 >> 16) & 0xFF] ^
            Te3[(s3 >> 24) & 0xFF] ^ rk[0];
        t1 =
            Te0[(s1 >>  0) & 0xFF] ^
            Te1[(s2 >>  8) & 0xFF] ^
            Te2[(s3 >> 16) & 0xFF] ^
            Te3[(s0 >> 24) & 0xFF] ^ rk[1];
        t2 =
            Te0[(s2 >>  0) & 0xFF] ^
            Te1[(s3 >>  8) & 0xFF] ^
            Te2[(s0 >> 16) & 0xFF] ^
            Te3[(s1 >> 24) & 0xFF] ^ rk[2];
        t3 =
            Te0[(s3 >>  0) & 0xFF] ^
            Te1[(s0 >>  8) & 0xFF] ^
            Te2[(s1 >> 16) & 0xFF] ^
            Te3[(s2 >> 24) & 0xFF] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk += 4;
    }

    /* 最后一轮：只有 SubBytes + ShiftRows + AddRoundKey（无 MixColumns） */
    {
        u8 sb[16];
        /* s0,s1,s2,s3 是列向量形式，按 ShiftRows 前的 state 展开：
         * col0: s0 byte 0..3 => state[0,1,2,3]
         * col1: s1 byte 0..3 => state[4,5,6,7]
         * col2: s2 byte 0..3 => state[8,9,10,11]
         * col3: s3 byte 0..3 => state[12,13,14,15]
         */
        u8 *st = sb;
        unpack_u32_le(s0, st + 0);
        unpack_u32_le(s1, st + 4);
        unpack_u32_le(s2, st + 8);
        unpack_u32_le(s3, st + 12);
        SubBytes(st);
        ShiftRows(st);
        /* AddRoundKey(rk[0..3]) 并输出 */
        {
            u8 rkbuf[16];
            unpack_u32_le(rk[0], rkbuf + 0);
            unpack_u32_le(rk[1], rkbuf + 4);
            unpack_u32_le(rk[2], rkbuf + 8);
            unpack_u32_le(rk[3], rkbuf + 12);
            for (rnd = 0; rnd < 16; ++rnd) out[rnd] = st[rnd] ^ rkbuf[rnd];
        }
    }
}

/* 解密轮核心（T-Box 路径） */
static inline void invmix_key(const u8 *in_rk, u8 *out_rk) {
    /* 对 16 字节轮密钥做 InvMixColumns (AES-256 解密等效结构需要) */
    int col;
    for (col = 0; col < 4; ++col) {
        int base = col * 4;
        u8 s0 = in_rk[base], s1 = in_rk[base+1], s2 = in_rk[base+2], s3 = in_rk[base+3];
        out_rk[base]   = gf_mult(0x0e, s0) ^ gf_mult(0x0b, s1) ^ gf_mult(0x0d, s2) ^ gf_mult(0x09, s3);
        out_rk[base+1] = gf_mult(0x09, s0) ^ gf_mult(0x0e, s1) ^ gf_mult(0x0b, s2) ^ gf_mult(0x0d, s3);
        out_rk[base+2] = gf_mult(0x0d, s0) ^ gf_mult(0x09, s1) ^ gf_mult(0x0e, s2) ^ gf_mult(0x0b, s3);
        out_rk[base+3] = gf_mult(0x0b, s0) ^ gf_mult(0x0d, s1) ^ gf_mult(0x09, s2) ^ gf_mult(0x0e, s3);
    }
}

static inline void
InvCipher_fast(const u8 *w, int Nr, const u8 *in, u8 *out)
{
    u32 s0, s1, s2, s3;
    u32 t0, t1, t2, t3;
    int rnd;

    const u32 *rk_orig = (const u32 *)(const void *)w;
    const u32 *rk = rk_orig + 4 * Nr;

    /* 初始 AddRoundKey(最后一轮的轮密钥) */
    s0 = pack_u32_le(in + 0)  ^ rk[0];
    s1 = pack_u32_le(in + 4)  ^ rk[1];
    s2 = pack_u32_le(in + 8)  ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];
    rk -= 4;

    for (rnd = Nr - 1; rnd > 0; --rnd) {
        /* OpenSSL 解密 Td 索引 (小端):
         * t0 = TD0[s0.0] ^ TD3[s1.1] ^ TD2[s2.2] ^ TD1[s3.3]
         * t1 = TD0[s1.0] ^ TD3[s2.1] ^ TD2[s3.2] ^ TD1[s0.3]
         * t2 = TD0[s2.0] ^ TD3[s3.1] ^ TD2[s0.2] ^ TD1[s1.3]
         * t3 = TD0[s3.0] ^ TD3[s0.1] ^ TD2[s1.2] ^ TD1[s2.3]
         * 轮密钥先经 InvMixColumns 变换（等效解密结构）
         */
        u8 rkbytes[16];
        u32 rk_mixed[4];
        unpack_u32_le(rk[0], rkbytes + 0);
        unpack_u32_le(rk[1], rkbytes + 4);
        unpack_u32_le(rk[2], rkbytes + 8);
        unpack_u32_le(rk[3], rkbytes + 12);
        invmix_key(rkbytes, rkbytes);
        rk_mixed[0] = pack_u32_le(rkbytes + 0);
        rk_mixed[1] = pack_u32_le(rkbytes + 4);
        rk_mixed[2] = pack_u32_le(rkbytes + 8);
        rk_mixed[3] = pack_u32_le(rkbytes + 12);

        t0 =
            Td0[(s0 >>  0) & 0xFF] ^
            Td3[(s1 >>  8) & 0xFF] ^
            Td2[(s2 >> 16) & 0xFF] ^
            Td1[(s3 >> 24) & 0xFF] ^
            rk_mixed[0];
        t1 =
            Td0[(s1 >>  0) & 0xFF] ^
            Td3[(s2 >>  8) & 0xFF] ^
            Td2[(s3 >> 16) & 0xFF] ^
            Td1[(s0 >> 24) & 0xFF] ^
            rk_mixed[1];
        t2 =
            Td0[(s2 >>  0) & 0xFF] ^
            Td3[(s3 >>  8) & 0xFF] ^
            Td2[(s0 >> 16) & 0xFF] ^
            Td1[(s1 >> 24) & 0xFF] ^
            rk_mixed[2];
        t3 =
            Td0[(s3 >>  0) & 0xFF] ^
            Td3[(s0 >>  8) & 0xFF] ^
            Td2[(s1 >> 16) & 0xFF] ^
            Td1[(s2 >> 24) & 0xFF] ^
            rk_mixed[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk -= 4;
    }

    /* 最后一轮：InvShiftRows + InvSubBytes + AddRoundKey(第一轮轮密钥 rk[0..3]) */
    {
        u8 sb[16];
        u8 *st = sb;
        unpack_u32_le(s0, st + 0);
        unpack_u32_le(s1, st + 4);
        unpack_u32_le(s2, st + 8);
        unpack_u32_le(s3, st + 12);
        InvShiftRows(st);
        InvSubBytes(st);
        {
            u8 rkbuf[16];
            unpack_u32_le(rk[0], rkbuf + 0);
            unpack_u32_le(rk[1], rkbuf + 4);
            unpack_u32_le(rk[2], rkbuf + 8);
            unpack_u32_le(rk[3], rkbuf + 12);
            for (rnd = 0; rnd < 16; ++rnd) out[rnd] = st[rnd] ^ rkbuf[rnd];
        }
    }
}

/* 对外保留原接口：T-box + 传统路径回退，可切 */
#define ENABLE_TBOX_ENC 1
#define ENABLE_TBOX_DEC 0

/* GF(2^8) xtime(x) = x<<1 或 x<<1 ^ 0x1b。宏比函数快 2-3 倍 */
#define AES_XTIME(x)  (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))
#define GF2(x)        AES_XTIME(x)
#define GF3(x)        (AES_XTIME(x) ^ (x))
#define GF4(x)        AES_XTIME(AES_XTIME(x))
#define GF8(x)        AES_XTIME(AES_XTIME(AES_XTIME(x)))
#define GF9(x)        (GF8(x) ^ (x))
#define GF11(x)       (GF8(x) ^ GF2(x) ^ (x))
#define GF13(x)       (GF8(x) ^ GF4(x) ^ (x))
#define GF14(x)       (GF8(x) ^ GF4(x) ^ GF2(x))

static void InvCipher_fast_native(uint8_t* state, const uint8_t* w, int Nr) {
    /* 等效解密 T-box 正确性未通过时，走纯 C 内联版：完全去掉 gf_mult 调用，
       InvSbox 直接查全局数组，InvMixColumns 全用 shift/xor 宏，每轮仅
       做 16 次 InvSbox 查表+ 4 列 × 4 字节 XOR，比原 gf_mult 版本快一个数量级。 */
    int round;
    const uint8_t *rk;

    /* 初始 AddRoundKey(最后一轮轮密钥) */
    rk = w + (size_t)BLOCK_SIZE * Nr;
    for (int i = 0; i < BLOCK_SIZE; ++i) state[i] ^= rk[i];

    for (round = Nr - 1; round > 0; --round) {
        InvShiftRows(state);
        /* InvSubBytes 内联查 inv_sbox */
        for (int i = 0; i < BLOCK_SIZE; ++i) state[i] = inv_sbox[state[i]];
        rk = w + (size_t)BLOCK_SIZE * round;
        /* AddRoundKey */
        for (int i = 0; i < BLOCK_SIZE; ++i) state[i] ^= rk[i];
        /* InvMixColumns：逐字节内联宏，避免 gf_mult 函数调用分支 */
        for (int col = 0; col < 4; ++col) {
            int base = col * 4;
            u8 s0 = state[base], s1 = state[base+1], s2 = state[base+2], s3 = state[base+3];
            state[base]   = GF14(s0) ^ GF11(s1) ^ GF13(s2) ^ GF9(s3);
            state[base+1] = GF9(s0)  ^ GF14(s1) ^ GF11(s2) ^ GF13(s3);
            state[base+2] = GF13(s0) ^ GF9(s1)  ^ GF14(s2) ^ GF11(s3);
            state[base+3] = GF11(s0) ^ GF13(s1) ^ GF9(s2)  ^ GF14(s3);
        }
    }
    /* 最后一轮：InvShiftRows + InvSubBytes + AddRoundKey(第一轮) */
    InvShiftRows(state);
    for (int i = 0; i < BLOCK_SIZE; ++i) state[i] = inv_sbox[state[i]];
    rk = w; /* rk0 */
    for (int i = 0; i < BLOCK_SIZE; ++i) state[i] ^= rk[i];
}

static void Cipher_old(uint8_t* state, const uint8_t* w, int Nr) {
    int round;
    AddRoundKey(state, w, 0);
    for (round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w, round);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w, Nr);
}

static void InvCipher_old(uint8_t* state, const uint8_t* w, int Nr) {
    int round;
    AddRoundKey(state, w, Nr);
    for (round = Nr - 1; round > 0; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w, round);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, w, 0);
}

/* ------- 内联无检查版 Cipher/InvCipher，用于批量循环调用 -------
   调用方必须保证 aes_init_tables() 已调用过。性能：省去每块 1 次条件判断，
   同时迫使编译器把整个轮循环内联进外层大循环，减少 call/ret。*/

static inline void
Cipher_inline(const u8 *__restrict w, int Nr, const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3;
    u32 t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in + 0)  ^ rk[0];
    s1 = pack_u32_le(in + 4)  ^ rk[1];
    s2 = pack_u32_le(in + 8)  ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];
    rk += 4;

    for (int rnd = 1; rnd < Nr; ++rnd) {
        t0 = Te0[s0&0xFF] ^ Te1[(s1>>8)&0xFF] ^ Te2[(s2>>16)&0xFF] ^ Te3[(s3>>24)&0xFF] ^ rk[0];
        t1 = Te0[s1&0xFF] ^ Te1[(s2>>8)&0xFF] ^ Te2[(s3>>16)&0xFF] ^ Te3[(s0>>24)&0xFF] ^ rk[1];
        t2 = Te0[s2&0xFF] ^ Te1[(s3>>8)&0xFF] ^ Te2[(s0>>16)&0xFF] ^ Te3[(s1>>24)&0xFF] ^ rk[2];
        t3 = Te0[s3&0xFF] ^ Te1[(s0>>8)&0xFF] ^ Te2[(s1>>16)&0xFF] ^ Te3[(s2>>24)&0xFF] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk += 4;
    }

    /* 最后一轮: SubBytes + ShiftRows + AddRoundKey (无 MixColumns)
     * 用 32 位打包写入, 减少 16 次字节内存写为 4 次 32 位写。 */
    {
        u32 r0 = (u32)sbox[s0 & 0xFF]
               | ((u32)sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)sbox[s1 & 0xFF]
               | ((u32)sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s0 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)sbox[s2 & 0xFF]
               | ((u32)sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)sbox[s3 & 0xFF]
               | ((u32)sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s2 >> 24) & 0xFF] << 24);
        r0 ^= rk[0]; r1 ^= rk[1]; r2 ^= rk[2]; r3 ^= rk[3];
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

static inline void
InvCipher_inline(const u8 *__restrict dw, int Nr, const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3;
    u32 t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw;

    /* 初始 AddRoundKey: 用 dw 的最后一轮 (等于 w[Nr], 未变) */
    drk += 4 * Nr;
    s0 = pack_u32_le(in + 0)  ^ drk[0];
    s1 = pack_u32_le(in + 4)  ^ drk[1];
    s2 = pack_u32_le(in + 8)  ^ drk[2];
    s3 = pack_u32_le(in + 12) ^ drk[3];
    drk -= 4;

    /* 中间轮: InvShiftRows + InvSubBytes + InvMixColumns + AddRoundKey
     * Td0-Td3 已合并 InvSubBytes+InvMixColumns, InvShiftRows 内嵌到字节索引中:
     * InvShiftRows 右移 → col0 的 byte1 来自 s3, byte2 来自 s2, byte3 来自 s1
     * Td 列序: Td0=col0(14), Td1=col1(11), Td2=col2(13), Td3=col3(9)
     * 所以 t0 = Td0[s0_b0] ^ Td1[s3_b1] ^ Td2[s2_b2] ^ Td3[s1_b3] */
    for (int rnd = Nr - 1; rnd > 0; --rnd) {
        t0 = Td0[s0&0xFF] ^ Td1[(s3>>8)&0xFF] ^ Td2[(s2>>16)&0xFF] ^ Td3[(s1>>24)&0xFF] ^ drk[0];
        t1 = Td0[s1&0xFF] ^ Td1[(s0>>8)&0xFF] ^ Td2[(s3>>16)&0xFF] ^ Td3[(s2>>24)&0xFF] ^ drk[1];
        t2 = Td0[s2&0xFF] ^ Td1[(s1>>8)&0xFF] ^ Td2[(s0>>16)&0xFF] ^ Td3[(s3>>24)&0xFF] ^ drk[2];
        t3 = Td0[s3&0xFF] ^ Td1[(s2>>8)&0xFF] ^ Td2[(s1>>16)&0xFF] ^ Td3[(s0>>24)&0xFF] ^ drk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        drk -= 4;
    }

    /* 最后一轮: InvShiftRows + InvSubBytes + AddRoundKey (无 InvMixColumns)
     * 直接用 inv_sbox 查表, InvShiftRows 紊乱内嵌到索引中 */
    {
        const u8 *drk8 = (const u8 *)drk;
        out[ 0] = inv_sbox[s0 & 0xFF]          ^ drk8[ 0];
        out[ 1] = inv_sbox[(s3 >>  8) & 0xFF]  ^ drk8[ 1];
        out[ 2] = inv_sbox[(s2 >> 16) & 0xFF]  ^ drk8[ 2];
        out[ 3] = inv_sbox[(s1 >> 24) & 0xFF]  ^ drk8[ 3];
        out[ 4] = inv_sbox[s1 & 0xFF]          ^ drk8[ 4];
        out[ 5] = inv_sbox[(s0 >>  8) & 0xFF]  ^ drk8[ 5];
        out[ 6] = inv_sbox[(s3 >> 16) & 0xFF]  ^ drk8[ 6];
        out[ 7] = inv_sbox[(s2 >> 24) & 0xFF]  ^ drk8[ 7];
        out[ 8] = inv_sbox[s2 & 0xFF]          ^ drk8[ 8];
        out[ 9] = inv_sbox[(s1 >>  8) & 0xFF]  ^ drk8[ 9];
        out[10] = inv_sbox[(s0 >> 16) & 0xFF]  ^ drk8[10];
        out[11] = inv_sbox[(s3 >> 24) & 0xFF]  ^ drk8[11];
        out[12] = inv_sbox[s3 & 0xFF]          ^ drk8[12];
        out[13] = inv_sbox[(s2 >>  8) & 0xFF]  ^ drk8[13];
        out[14] = inv_sbox[(s1 >> 16) & 0xFF]  ^ drk8[14];
        out[15] = inv_sbox[(s0 >> 24) & 0xFF]  ^ drk8[15];
    }
}

/* ---------------------------------------------------------------------------
 * CBC 专用加密: 把 plaintext ^ prev_block 合并到第一轮 AddRoundKey,
 * 省去 16 字节临时缓冲 + 4 次 pack_u32_le 读取。
 * 输出 out = E_K(P ^ prev), 同时把 out 拷回 prev 供下一块使用。
 * ------------------------------------------------------------------------- */
static __attribute__((always_inline)) inline void
Cipher_inline_cbc_enc(const u8 *__restrict w, int Nr,
                      const u8 *__restrict in,
                      const u8 *__restrict prev,
                      u8 *__restrict out,
                      u8 *__restrict prev_out)
{
    u32 s0, s1, s2, s3;
    u32 t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    /* 初始 AddRoundKey: pack(in) ^ pack(prev) ^ rk[0..3] 一次完成 */
    s0 = pack_u32_le(in +  0) ^ pack_u32_le(prev +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ pack_u32_le(prev +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ pack_u32_le(prev +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ pack_u32_le(prev + 12) ^ rk[3];
    rk += 4;

    /* 中间 Nr-1 轮 (与 Cipher_inline 完全一致) */
    for (int rnd = 1; rnd < Nr; ++rnd) {
        t0 = Te0[s0&0xFF] ^ Te1[(s1>>8)&0xFF] ^ Te2[(s2>>16)&0xFF] ^ Te3[(s3>>24)&0xFF] ^ rk[0];
        t1 = Te0[s1&0xFF] ^ Te1[(s2>>8)&0xFF] ^ Te2[(s3>>16)&0xFF] ^ Te3[(s0>>24)&0xFF] ^ rk[1];
        t2 = Te0[s2&0xFF] ^ Te1[(s3>>8)&0xFF] ^ Te2[(s0>>16)&0xFF] ^ Te3[(s1>>24)&0xFF] ^ rk[2];
        t3 = Te0[s3&0xFF] ^ Te1[(s0>>8)&0xFF] ^ Te2[(s1>>16)&0xFF] ^ Te3[(s2>>24)&0xFF] ^ rk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        rk += 4;
    }

    /* 最后一轮: SubBytes + ShiftRows + AddRoundKey, 直接写 out,
     * 同时把 out 拷到 prev_out 供下一块 XOR */
    {
        const u8 *rk8 = (const u8 *)rk;
        u8 v;
        v = sbox[s0 & 0xFF]         ^ rk8[ 0]; out[ 0] = v; prev_out[ 0] = v;
        v = sbox[(s1 >>  8) & 0xFF] ^ rk8[ 1]; out[ 1] = v; prev_out[ 1] = v;
        v = sbox[(s2 >> 16) & 0xFF] ^ rk8[ 2]; out[ 2] = v; prev_out[ 2] = v;
        v = sbox[(s3 >> 24) & 0xFF] ^ rk8[ 3]; out[ 3] = v; prev_out[ 3] = v;
        v = sbox[s1 & 0xFF]         ^ rk8[ 4]; out[ 4] = v; prev_out[ 4] = v;
        v = sbox[(s2 >>  8) & 0xFF] ^ rk8[ 5]; out[ 5] = v; prev_out[ 5] = v;
        v = sbox[(s3 >> 16) & 0xFF] ^ rk8[ 6]; out[ 6] = v; prev_out[ 6] = v;
        v = sbox[(s0 >> 24) & 0xFF] ^ rk8[ 7]; out[ 7] = v; prev_out[ 7] = v;
        v = sbox[s2 & 0xFF]         ^ rk8[ 8]; out[ 8] = v; prev_out[ 8] = v;
        v = sbox[(s3 >>  8) & 0xFF] ^ rk8[ 9]; out[ 9] = v; prev_out[ 9] = v;
        v = sbox[(s0 >> 16) & 0xFF] ^ rk8[10]; out[10] = v; prev_out[10] = v;
        v = sbox[(s1 >> 24) & 0xFF] ^ rk8[11]; out[11] = v; prev_out[11] = v;
        v = sbox[s3 & 0xFF]         ^ rk8[12]; out[12] = v; prev_out[12] = v;
        v = sbox[(s0 >>  8) & 0xFF] ^ rk8[13]; out[13] = v; prev_out[13] = v;
        v = sbox[(s1 >> 16) & 0xFF] ^ rk8[14]; out[14] = v; prev_out[14] = v;
        v = sbox[(s2 >> 24) & 0xFF] ^ rk8[15]; out[15] = v; prev_out[15] = v;
    }
}

/* ---------------------------------------------------------------------------
 * CBC 专用解密: out = D_K(in) ^ prev, 把 XOR prev 合并到最后一轮 AddRoundKey
 * 之后, 省去 16 字节临时缓冲 + 16 字节 XOR。
 * 调用方必须在调用前保存当前 in (作为下一块的 prev)。
 * ------------------------------------------------------------------------- */
static __attribute__((always_inline)) inline void
InvCipher_inline_cbc_dec(const u8 *__restrict dw, int Nr,
                         const u8 *__restrict in,
                         const u8 *__restrict prev,
                         u8 *__restrict out)
{
    u32 s0, s1, s2, s3;
    u32 t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw;

    /* 初始 AddRoundKey: 用 dw 的最后一轮 (等于 w[Nr], 未变) */
    drk += 4 * Nr;
    s0 = pack_u32_le(in +  0) ^ drk[0];
    s1 = pack_u32_le(in +  4) ^ drk[1];
    s2 = pack_u32_le(in +  8) ^ drk[2];
    s3 = pack_u32_le(in + 12) ^ drk[3];
    drk -= 4;

    /* 中间轮 (与 InvCipher_inline 完全一致) */
    for (int rnd = Nr - 1; rnd > 0; --rnd) {
        t0 = Td0[s0&0xFF] ^ Td1[(s3>>8)&0xFF] ^ Td2[(s2>>16)&0xFF] ^ Td3[(s1>>24)&0xFF] ^ drk[0];
        t1 = Td0[s1&0xFF] ^ Td1[(s0>>8)&0xFF] ^ Td2[(s3>>16)&0xFF] ^ Td3[(s2>>24)&0xFF] ^ drk[1];
        t2 = Td0[s2&0xFF] ^ Td1[(s1>>8)&0xFF] ^ Td2[(s0>>16)&0xFF] ^ Td3[(s3>>24)&0xFF] ^ drk[2];
        t3 = Td0[s3&0xFF] ^ Td1[(s2>>8)&0xFF] ^ Td2[(s1>>16)&0xFF] ^ Td3[(s0>>24)&0xFF] ^ drk[3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        drk -= 4;
    }

    /* 最后一轮: InvShiftRows + InvSubBytes + AddRoundKey, 然后 XOR prev 输出到 out。
     * 直接读 prev 的字节做 XOR, 无需独立 16 字节 XOR 循环。 */
    {
        const u8 *drk8 = (const u8 *)drk;
        out[ 0] = inv_sbox[s0 & 0xFF]         ^ drk8[ 0] ^ prev[ 0];
        out[ 1] = inv_sbox[(s3 >>  8) & 0xFF] ^ drk8[ 1] ^ prev[ 1];
        out[ 2] = inv_sbox[(s2 >> 16) & 0xFF] ^ drk8[ 2] ^ prev[ 2];
        out[ 3] = inv_sbox[(s1 >> 24) & 0xFF] ^ drk8[ 3] ^ prev[ 3];
        out[ 4] = inv_sbox[s1 & 0xFF]         ^ drk8[ 4] ^ prev[ 4];
        out[ 5] = inv_sbox[(s0 >>  8) & 0xFF] ^ drk8[ 5] ^ prev[ 5];
        out[ 6] = inv_sbox[(s3 >> 16) & 0xFF] ^ drk8[ 6] ^ prev[ 6];
        out[ 7] = inv_sbox[(s2 >> 24) & 0xFF] ^ drk8[ 7] ^ prev[ 7];
        out[ 8] = inv_sbox[s2 & 0xFF]         ^ drk8[ 8] ^ prev[ 8];
        out[ 9] = inv_sbox[(s1 >>  8) & 0xFF] ^ drk8[ 9] ^ prev[ 9];
        out[10] = inv_sbox[(s0 >> 16) & 0xFF] ^ drk8[10] ^ prev[10];
        out[11] = inv_sbox[(s3 >> 24) & 0xFF] ^ drk8[11] ^ prev[11];
        out[12] = inv_sbox[s3 & 0xFF]         ^ drk8[12] ^ prev[12];
        out[13] = inv_sbox[(s2 >>  8) & 0xFF] ^ drk8[13] ^ prev[13];
        out[14] = inv_sbox[(s1 >> 16) & 0xFF] ^ drk8[14] ^ prev[14];
        out[15] = inv_sbox[(s0 >> 24) & 0xFF] ^ drk8[15] ^ prev[15];
    }
}

static void Cipher(const uint8_t* w, int Nr, const uint8_t* in, uint8_t* out) {
    if (!aes_tables_ready) aes_init_tables();
    Cipher_inline(w, Nr, in, out);
}

/* ===========================================================================
 * 完全展开的 AES-256 专用加密 (Nr=14, 13 轮中间 + 1 轮末轮)
 *   - 手工展开所有轮次, 消除循环判断/跳转开销
 *   - 编译器看到线性代码, 可全局调度指令, 减少状态 spill
 *   - 32-bit x86 寄存器有限, 完全展开让编译器有更大优化空间
 * ========================================================================= */
#define AES_ENC_ROUND_FULL(rk4) \
    t0 = Te0[s0&0xFF] ^ Te1[(s1>>8)&0xFF] ^ Te2[(s2>>16)&0xFF] ^ Te3[(s3>>24)&0xFF] ^ (rk4)[0]; \
    t1 = Te0[s1&0xFF] ^ Te1[(s2>>8)&0xFF] ^ Te2[(s3>>16)&0xFF] ^ Te3[(s0>>24)&0xFF] ^ (rk4)[1]; \
    t2 = Te0[s2&0xFF] ^ Te1[(s3>>8)&0xFF] ^ Te2[(s0>>16)&0xFF] ^ Te3[(s1>>24)&0xFF] ^ (rk4)[2]; \
    t3 = Te0[s3&0xFF] ^ Te1[(s0>>8)&0xFF] ^ Te2[(s1>>16)&0xFF] ^ Te3[(s2>>24)&0xFF] ^ (rk4)[3]; \
    s0 = t0; s1 = t1; s2 = t2; s3 = t3

#define AES_DEC_ROUND_FULL(drk4) \
    t0 = Td0[s0&0xFF] ^ Td1[(s3>>8)&0xFF] ^ Td2[(s2>>16)&0xFF] ^ Td3[(s1>>24)&0xFF] ^ (drk4)[0]; \
    t1 = Td0[s1&0xFF] ^ Td1[(s0>>8)&0xFF] ^ Td2[(s3>>16)&0xFF] ^ Td3[(s2>>24)&0xFF] ^ (drk4)[1]; \
    t2 = Td0[s2&0xFF] ^ Td1[(s1>>8)&0xFF] ^ Td2[(s0>>16)&0xFF] ^ Td3[(s3>>24)&0xFF] ^ (drk4)[2]; \
    t3 = Td0[s3&0xFF] ^ Td1[(s2>>8)&0xFF] ^ Td2[(s1>>16)&0xFF] ^ Td3[(s0>>24)&0xFF] ^ (drk4)[3]; \
    s0 = t0; s1 = t1; s2 = t2; s3 = t3

static __attribute__((always_inline)) inline void
Cipher_inline_aes256(const u8 *__restrict w,
                     const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);
    AES_ENC_ROUND_FULL(rk + 40);
    AES_ENC_ROUND_FULL(rk + 44);
    AES_ENC_ROUND_FULL(rk + 48);
    AES_ENC_ROUND_FULL(rk + 52);

    {
        /* 最后一轮: SubBytes + ShiftRows + AddRoundKey, 用 32 位打包写入
         * 减少 16 次字节内存写为 4 次 32 位写。 */
        const u32 *__restrict rk_last = rk + 56;
        u32 r0 = (u32)sbox[s0 & 0xFF]
               | ((u32)sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)sbox[s1 & 0xFF]
               | ((u32)sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s0 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)sbox[s2 & 0xFF]
               | ((u32)sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)sbox[s3 & 0xFF]
               | ((u32)sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s2 >> 24) & 0xFF] << 24);
        r0 ^= rk_last[0]; r1 ^= rk_last[1]; r2 ^= rk_last[2]; r3 ^= rk_last[3];
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

/* ===========================================================================
 * AES-256 专用完全展开 2 块并行加密:
 *   2 块状态共 16 个 u32 + 8 个 temp = 24 个 u32, x86-64 寄存器可容纳。
 *   13 轮中间完全展开 (无循环), 编译器全局调度 ILP,
 *   把 T-box 查表延迟完美隐藏。用于 ECB / CTR / OFB / CFB128 等无依赖模式。
 * ========================================================================= */
static __attribute__((always_inline)) inline void
Cipher_inline_aes256_x2(const u8 *__restrict w,
                        const u8 *__restrict in0,
                        const u8 *__restrict in1,
                        u8 *__restrict out0,
                        u8 *__restrict out1)
{
    u32 a0, a1, a2, a3, at0, at1, at2, at3;
    u32 b0, b1, b2, b3, bt0, bt1, bt2, bt3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    a0 = pack_u32_le(in0 +  0) ^ rk[0];
    a1 = pack_u32_le(in0 +  4) ^ rk[1];
    a2 = pack_u32_le(in0 +  8) ^ rk[2];
    a3 = pack_u32_le(in0 + 12) ^ rk[3];
    b0 = pack_u32_le(in1 +  0) ^ rk[0];
    b1 = pack_u32_le(in1 +  4) ^ rk[1];
    b2 = pack_u32_le(in1 +  8) ^ rk[2];
    b3 = pack_u32_le(in1 + 12) ^ rk[3];

#define AES256_X2_ROUND(rk_off) \
    at0 = Te0[a0&0xFF]^Te1[(a1>>8)&0xFF]^Te2[(a2>>16)&0xFF]^Te3[(a3>>24)&0xFF]^rk[rk_off+0]; \
    at1 = Te0[a1&0xFF]^Te1[(a2>>8)&0xFF]^Te2[(a3>>16)&0xFF]^Te3[(a0>>24)&0xFF]^rk[rk_off+1]; \
    at2 = Te0[a2&0xFF]^Te1[(a3>>8)&0xFF]^Te2[(a0>>16)&0xFF]^Te3[(a1>>24)&0xFF]^rk[rk_off+2]; \
    at3 = Te0[a3&0xFF]^Te1[(a0>>8)&0xFF]^Te2[(a1>>16)&0xFF]^Te3[(a2>>24)&0xFF]^rk[rk_off+3]; \
    a0=at0; a1=at1; a2=at2; a3=at3; \
    bt0 = Te0[b0&0xFF]^Te1[(b1>>8)&0xFF]^Te2[(b2>>16)&0xFF]^Te3[(b3>>24)&0xFF]^rk[rk_off+0]; \
    bt1 = Te0[b1&0xFF]^Te1[(b2>>8)&0xFF]^Te2[(b3>>16)&0xFF]^Te3[(b0>>24)&0xFF]^rk[rk_off+1]; \
    bt2 = Te0[b2&0xFF]^Te1[(b3>>8)&0xFF]^Te2[(b0>>16)&0xFF]^Te3[(b1>>24)&0xFF]^rk[rk_off+2]; \
    bt3 = Te0[b3&0xFF]^Te1[(b0>>8)&0xFF]^Te2[(b1>>16)&0xFF]^Te3[(b2>>24)&0xFF]^rk[rk_off+3]; \
    b0=bt0; b1=bt1; b2=bt2; b3=bt3

    AES256_X2_ROUND( 4);  AES256_X2_ROUND( 8);  AES256_X2_ROUND(12);
    AES256_X2_ROUND(16);  AES256_X2_ROUND(20);  AES256_X2_ROUND(24);
    AES256_X2_ROUND(28);  AES256_X2_ROUND(32);  AES256_X2_ROUND(36);
    AES256_X2_ROUND(40);  AES256_X2_ROUND(44);  AES256_X2_ROUND(48);
    AES256_X2_ROUND(52);

#undef AES256_X2_ROUND

    {
        const u32 *__restrict rk_last = rk + 56;
        u32 ar0, ar1, ar2, ar3, br0, br1, br2, br3;
        ar0 = (u32)sbox[a0&0xFF] | ((u32)sbox[(a1>>8)&0xFF]<<8)
             | ((u32)sbox[(a2>>16)&0xFF]<<16) | ((u32)sbox[(a3>>24)&0xFF]<<24);
        ar1 = (u32)sbox[a1&0xFF] | ((u32)sbox[(a2>>8)&0xFF]<<8)
             | ((u32)sbox[(a3>>16)&0xFF]<<16) | ((u32)sbox[(a0>>24)&0xFF]<<24);
        ar2 = (u32)sbox[a2&0xFF] | ((u32)sbox[(a3>>8)&0xFF]<<8)
             | ((u32)sbox[(a0>>16)&0xFF]<<16) | ((u32)sbox[(a1>>24)&0xFF]<<24);
        ar3 = (u32)sbox[a3&0xFF] | ((u32)sbox[(a0>>8)&0xFF]<<8)
             | ((u32)sbox[(a1>>16)&0xFF]<<16) | ((u32)sbox[(a2>>24)&0xFF]<<24);
        br0 = (u32)sbox[b0&0xFF] | ((u32)sbox[(b1>>8)&0xFF]<<8)
             | ((u32)sbox[(b2>>16)&0xFF]<<16) | ((u32)sbox[(b3>>24)&0xFF]<<24);
        br1 = (u32)sbox[b1&0xFF] | ((u32)sbox[(b2>>8)&0xFF]<<8)
             | ((u32)sbox[(b3>>16)&0xFF]<<16) | ((u32)sbox[(b0>>24)&0xFF]<<24);
        br2 = (u32)sbox[b2&0xFF] | ((u32)sbox[(b3>>8)&0xFF]<<8)
             | ((u32)sbox[(b0>>16)&0xFF]<<16) | ((u32)sbox[(b1>>24)&0xFF]<<24);
        br3 = (u32)sbox[b3&0xFF] | ((u32)sbox[(b0>>8)&0xFF]<<8)
             | ((u32)sbox[(b1>>16)&0xFF]<<16) | ((u32)sbox[(b2>>24)&0xFF]<<24);
        ar0^=rk_last[0]; ar1^=rk_last[1]; ar2^=rk_last[2]; ar3^=rk_last[3];
        br0^=rk_last[0]; br1^=rk_last[1]; br2^=rk_last[2]; br3^=rk_last[3];
        unpack_u32_le(ar0, out0+0); unpack_u32_le(ar1, out0+4);
        unpack_u32_le(ar2, out0+8); unpack_u32_le(ar3, out0+12);
        unpack_u32_le(br0, out1+0); unpack_u32_le(br1, out1+4);
        unpack_u32_le(br2, out1+8); unpack_u32_le(br3, out1+12);
    }
}

/* ===========================================================================
 * AES-256 完全展开 2 块并行解密 (InvCipher):
 *   镜像 Cipher_inline_aes256_x2, 使用 Td0..Td3 + inv_sbox + dw 解密等效轮密钥。
 * ========================================================================= */
static __attribute__((always_inline)) inline void
InvCipher_inline_aes256_x2(const u8 *__restrict dw,
                           const u8 *__restrict in0,
                           const u8 *__restrict in1,
                           u8 *__restrict out0,
                           u8 *__restrict out1)
{
    u32 a0, a1, a2, a3, at0, at1, at2, at3;
    u32 b0, b1, b2, b3, bt0, bt1, bt2, bt3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw + 56; /* dw + 4*Nr (Nr=14) */

    a0 = pack_u32_le(in0 +  0) ^ drk[0];
    a1 = pack_u32_le(in0 +  4) ^ drk[1];
    a2 = pack_u32_le(in0 +  8) ^ drk[2];
    a3 = pack_u32_le(in0 + 12) ^ drk[3];
    b0 = pack_u32_le(in1 +  0) ^ drk[0];
    b1 = pack_u32_le(in1 +  4) ^ drk[1];
    b2 = pack_u32_le(in1 +  8) ^ drk[2];
    b3 = pack_u32_le(in1 + 12) ^ drk[3];

#define AES256_X2_DEC_ROUND(drk_off) \
    at0 = Td0[a0&0xFF]^Td1[(a3>>8)&0xFF]^Td2[(a2>>16)&0xFF]^Td3[(a1>>24)&0xFF]^drk[drk_off+0]; \
    at1 = Td0[a1&0xFF]^Td1[(a0>>8)&0xFF]^Td2[(a3>>16)&0xFF]^Td3[(a2>>24)&0xFF]^drk[drk_off+1]; \
    at2 = Td0[a2&0xFF]^Td1[(a1>>8)&0xFF]^Td2[(a0>>16)&0xFF]^Td3[(a3>>24)&0xFF]^drk[drk_off+2]; \
    at3 = Td0[a3&0xFF]^Td1[(a2>>8)&0xFF]^Td2[(a1>>16)&0xFF]^Td3[(a0>>24)&0xFF]^drk[drk_off+3]; \
    a0=at0; a1=at1; a2=at2; a3=at3; \
    bt0 = Td0[b0&0xFF]^Td1[(b3>>8)&0xFF]^Td2[(b2>>16)&0xFF]^Td3[(b1>>24)&0xFF]^drk[drk_off+0]; \
    bt1 = Td0[b1&0xFF]^Td1[(b0>>8)&0xFF]^Td2[(b3>>16)&0xFF]^Td3[(b2>>24)&0xFF]^drk[drk_off+1]; \
    bt2 = Td0[b2&0xFF]^Td1[(b1>>8)&0xFF]^Td2[(b0>>16)&0xFF]^Td3[(b3>>24)&0xFF]^drk[drk_off+2]; \
    bt3 = Td0[b3&0xFF]^Td1[(b2>>8)&0xFF]^Td2[(b1>>16)&0xFF]^Td3[(b0>>24)&0xFF]^drk[drk_off+3]; \
    b0=bt0; b1=bt1; b2=bt2; b3=bt3

    AES256_X2_DEC_ROUND(- 4);  AES256_X2_DEC_ROUND(- 8);  AES256_X2_DEC_ROUND(-12);
    AES256_X2_DEC_ROUND(-16);  AES256_X2_DEC_ROUND(-20);  AES256_X2_DEC_ROUND(-24);
    AES256_X2_DEC_ROUND(-28);  AES256_X2_DEC_ROUND(-32);  AES256_X2_DEC_ROUND(-36);
    AES256_X2_DEC_ROUND(-40);  AES256_X2_DEC_ROUND(-44);  AES256_X2_DEC_ROUND(-48);
    AES256_X2_DEC_ROUND(-52);

#undef AES256_X2_DEC_ROUND

    {
        /* 末轮: InvSubBytes + InvShiftRows + AddRoundKey(dw[0..3]) */
        const u32 *__restrict drk_first = (const u32 *)(const void *)dw;
        u32 ar0 = (u32)inv_sbox[a0&0xFF] | ((u32)inv_sbox[(a3>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(a2>>16)&0xFF]<<16) | ((u32)inv_sbox[(a1>>24)&0xFF]<<24);
        u32 ar1 = (u32)inv_sbox[a1&0xFF] | ((u32)inv_sbox[(a0>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(a3>>16)&0xFF]<<16) | ((u32)inv_sbox[(a2>>24)&0xFF]<<24);
        u32 ar2 = (u32)inv_sbox[a2&0xFF] | ((u32)inv_sbox[(a1>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(a0>>16)&0xFF]<<16) | ((u32)inv_sbox[(a3>>24)&0xFF]<<24);
        u32 ar3 = (u32)inv_sbox[a3&0xFF] | ((u32)inv_sbox[(a2>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(a1>>16)&0xFF]<<16) | ((u32)inv_sbox[(a0>>24)&0xFF]<<24);
        u32 br0 = (u32)inv_sbox[b0&0xFF] | ((u32)inv_sbox[(b3>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(b2>>16)&0xFF]<<16) | ((u32)inv_sbox[(b1>>24)&0xFF]<<24);
        u32 br1 = (u32)inv_sbox[b1&0xFF] | ((u32)inv_sbox[(b0>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(b3>>16)&0xFF]<<16) | ((u32)inv_sbox[(b2>>24)&0xFF]<<24);
        u32 br2 = (u32)inv_sbox[b2&0xFF] | ((u32)inv_sbox[(b1>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(b0>>16)&0xFF]<<16) | ((u32)inv_sbox[(b3>>24)&0xFF]<<24);
        u32 br3 = (u32)inv_sbox[b3&0xFF] | ((u32)inv_sbox[(b2>>8)&0xFF]<<8)
             | ((u32)inv_sbox[(b1>>16)&0xFF]<<16) | ((u32)inv_sbox[(b0>>24)&0xFF]<<24);
        ar0^=drk_first[0]; ar1^=drk_first[1]; ar2^=drk_first[2]; ar3^=drk_first[3];
        br0^=drk_first[0]; br1^=drk_first[1]; br2^=drk_first[2]; br3^=drk_first[3];
        unpack_u32_le(ar0, out0+0); unpack_u32_le(ar1, out0+4);
        unpack_u32_le(ar2, out0+8); unpack_u32_le(ar3, out0+12);
        unpack_u32_le(br0, out1+0); unpack_u32_le(br1, out1+4);
        unpack_u32_le(br2, out1+8); unpack_u32_le(br3, out1+12);
    }
}

/* CFB8 专用 AES-256: 只取 encrypted[0], 省 15 字节写 + unpack 开销 */
static __attribute__((always_inline)) inline u8
Cipher_inline_aes256_cfb8_msb0(const u8 *__restrict w, const u8 *__restrict in)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);
    AES_ENC_ROUND_FULL(rk + 40);
    AES_ENC_ROUND_FULL(rk + 44);
    AES_ENC_ROUND_FULL(rk + 48);
    AES_ENC_ROUND_FULL(rk + 52);

    {
        const u8 *rk8 = (const u8 *)(rk + 56);
        return sbox[s0 & 0xFF] ^ rk8[0];  /* 仅 output byte0 */
    }
}

static __attribute__((always_inline)) inline void
InvCipher_inline_aes256(const u8 *__restrict dw,
                        const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw + 56; /* dw + 4*Nr */

    s0 = pack_u32_le(in +  0) ^ drk[0];
    s1 = pack_u32_le(in +  4) ^ drk[1];
    s2 = pack_u32_le(in +  8) ^ drk[2];
    s3 = pack_u32_le(in + 12) ^ drk[3];

    AES_DEC_ROUND_FULL(drk -  4);
    AES_DEC_ROUND_FULL(drk -  8);
    AES_DEC_ROUND_FULL(drk - 12);
    AES_DEC_ROUND_FULL(drk - 16);
    AES_DEC_ROUND_FULL(drk - 20);
    AES_DEC_ROUND_FULL(drk - 24);
    AES_DEC_ROUND_FULL(drk - 28);
    AES_DEC_ROUND_FULL(drk - 32);
    AES_DEC_ROUND_FULL(drk - 36);
    AES_DEC_ROUND_FULL(drk - 40);
    AES_DEC_ROUND_FULL(drk - 44);
    AES_DEC_ROUND_FULL(drk - 48);
    AES_DEC_ROUND_FULL(drk - 52);

    {
        /* 最后一轮: InvSubBytes + InvShiftRows + AddRoundKey, 32 位打包写入 */
        const u32 *__restrict drk_first = (const u32 *)(const void *)dw;
        u32 r0 = (u32)inv_sbox[s0 & 0xFF]
               | ((u32)inv_sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)inv_sbox[s1 & 0xFF]
               | ((u32)inv_sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s2 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)inv_sbox[s2 & 0xFF]
               | ((u32)inv_sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)inv_sbox[s3 & 0xFF]
               | ((u32)inv_sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s0 >> 24) & 0xFF] << 24);
        r0 ^= drk_first[0]; r1 ^= drk_first[1]; r2 ^= drk_first[2]; r3 ^= drk_first[3];
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

/* 根据 ctx->Nr 自动选择 AES-256/128 完全展开路径或通用路径的加密封装。
 * 用于 CCM/GCM 等 CBC-ECB-CTR 之外的复合模式, 消除 Cipher() 内的
 * tables_ready 检查 (调用者须确保已初始化) 和 Nr 循环判断开销。
 * 注意: 此函数定义在所有 Cipher_inline_aesNNN 之后, 以保证前向引用正确。 */

/* =========================================================================
 * AES-128 完全展开实现 (Nr=10, 9 轮完整 + 1 轮最终)
 * 消除 for 循环开销, 改善指令调度, 提升 AES-128 软件路径速度。
 * ======================================================================= */
static __attribute__((always_inline)) inline void
Cipher_inline_aes128(const u8 *__restrict w,
                     const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);

    {
        const u32 *__restrict rk_last = rk + 40;
        u32 r0 = (u32)sbox[s0 & 0xFF]
               | ((u32)sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)sbox[s1 & 0xFF]
               | ((u32)sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s0 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)sbox[s2 & 0xFF]
               | ((u32)sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)sbox[s3 & 0xFF]
               | ((u32)sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s2 >> 24) & 0xFF] << 24);
        r0 ^= rk_last[0]; r1 ^= rk_last[1]; r2 ^= rk_last[2]; r3 ^= rk_last[3];
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

/* CFB8 专用 AES-128 加密: 只返回 MSB(encrypted[0]), 省去 unpack/写 16 字节的开销
 * CFB8 每字节都需要 E_k(feedback)[0]，其他 15 字节完全没用。 */
static __attribute__((always_inline)) inline u8
Cipher_inline_aes128_cfb8_msb0(const u8 *__restrict w, const u8 *__restrict in)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);

    /* 只需要 output byte 0 = sbox[s0 & 0xFF] ^ rk_last[0] (ShiftRows row0 在 byte0) */
    {
        const u8 *rk8 = (const u8 *)(rk + 40);
        return sbox[s0 & 0xFF] ^ rk8[0];
    }
}

/* AES-192 专用 CFB8 msb0: Nr=12, 11 轮完整轮 + 末轮查表 */
static __attribute__((always_inline)) inline u8
Cipher_inline_aes192_cfb8_msb0(const u8 *__restrict w, const u8 *__restrict in)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);
    AES_ENC_ROUND_FULL(rk + 40);
    AES_ENC_ROUND_FULL(rk + 44);

    {
        const u8 *rk8 = (const u8 *)(rk + 48);
        return sbox[s0 & 0xFF] ^ rk8[0];
    }
}

static __attribute__((always_inline)) inline void
InvCipher_inline_aes128(const u8 *__restrict dw,
                        const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw + 40; /* dw + 4*Nr */

    s0 = pack_u32_le(in +  0) ^ drk[0];
    s1 = pack_u32_le(in +  4) ^ drk[1];
    s2 = pack_u32_le(in +  8) ^ drk[2];
    s3 = pack_u32_le(in + 12) ^ drk[3];

    AES_DEC_ROUND_FULL(drk -  4);
    AES_DEC_ROUND_FULL(drk -  8);
    AES_DEC_ROUND_FULL(drk - 12);
    AES_DEC_ROUND_FULL(drk - 16);
    AES_DEC_ROUND_FULL(drk - 20);
    AES_DEC_ROUND_FULL(drk - 24);
    AES_DEC_ROUND_FULL(drk - 28);
    AES_DEC_ROUND_FULL(drk - 32);
    AES_DEC_ROUND_FULL(drk - 36);

    {
        const u32 *__restrict drk_first = (const u32 *)(const void *)dw;
        u32 r0 = (u32)inv_sbox[s0 & 0xFF]
               | ((u32)inv_sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)inv_sbox[s1 & 0xFF]
               | ((u32)inv_sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s2 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)inv_sbox[s2 & 0xFF]
               | ((u32)inv_sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)inv_sbox[s3 & 0xFF]
               | ((u32)inv_sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s0 >> 24) & 0xFF] << 24);
        r0 ^= drk_first[0]; r1 ^= drk_first[1]; r2 ^= drk_first[2]; r3 ^= drk_first[3];
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

/* AES-192 专用加密: Nr=12, 11 轮完整轮 + 末轮 (完全展开) */
static __attribute__((always_inline)) inline void
Cipher_inline_aes192(const u8 *__restrict w,
                     const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);
    AES_ENC_ROUND_FULL(rk + 40);
    AES_ENC_ROUND_FULL(rk + 44);

    {
        const u32 *__restrict rk_last = rk + 48;
        u32 r0 = (u32)sbox[s0 & 0xFF]
               | ((u32)sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)sbox[s1 & 0xFF]
               | ((u32)sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s0 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)sbox[s2 & 0xFF]
               | ((u32)sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)sbox[s3 & 0xFF]
               | ((u32)sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)sbox[(s2 >> 24) & 0xFF] << 24);
        r0 ^= rk_last[0]; r1 ^= rk_last[1]; r2 ^= rk_last[2]; r3 ^= rk_last[3];
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

/* AES-192 专用解密: Nr=12, 11 轮完整轮 + 末轮 (完全展开) */
static __attribute__((always_inline)) inline void
InvCipher_inline_aes192(const u8 *__restrict dw,
                        const u8 *__restrict in, u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw + 48; /* dw + 4*Nr */

    s0 = pack_u32_le(in +  0) ^ drk[0];
    s1 = pack_u32_le(in +  4) ^ drk[1];
    s2 = pack_u32_le(in +  8) ^ drk[2];
    s3 = pack_u32_le(in + 12) ^ drk[3];

    AES_DEC_ROUND_FULL(drk -  4);
    AES_DEC_ROUND_FULL(drk -  8);
    AES_DEC_ROUND_FULL(drk - 12);
    AES_DEC_ROUND_FULL(drk - 16);
    AES_DEC_ROUND_FULL(drk - 20);
    AES_DEC_ROUND_FULL(drk - 24);
    AES_DEC_ROUND_FULL(drk - 28);
    AES_DEC_ROUND_FULL(drk - 32);
    AES_DEC_ROUND_FULL(drk - 36);
    AES_DEC_ROUND_FULL(drk - 40);
    AES_DEC_ROUND_FULL(drk - 44);

    {
        const u32 *__restrict drk_first = (const u32 *)(const void *)dw;
        u32 r0 = (u32)inv_sbox[s0 & 0xFF]
               | ((u32)inv_sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)inv_sbox[s1 & 0xFF]
               | ((u32)inv_sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s2 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)inv_sbox[s2 & 0xFF]
               | ((u32)inv_sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)inv_sbox[s3 & 0xFF]
               | ((u32)inv_sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s0 >> 24) & 0xFF] << 24);
        r0 ^= drk_first[0]; r1 ^= drk_first[1]; r2 ^= drk_first[2]; r3 ^= drk_first[3];
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

/* AES-128 专用 CBC 加密: 完全展开 + prev XOR 合并进第一轮 */
static __attribute__((always_inline)) inline void
Cipher_inline_cbc_enc_aes128(const u8 *__restrict w,
                             const u8 *__restrict in,
                             const u8 *__restrict prev,
                             u8 *__restrict out,
                             u8 *__restrict prev_out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ pack_u32_le(prev +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ pack_u32_le(prev +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ pack_u32_le(prev +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ pack_u32_le(prev + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);

    {
        const u8 *rk8 = (const u8 *)(rk + 40);
        u8 v;
        v = sbox[s0 & 0xFF]         ^ rk8[ 0]; out[ 0] = v; prev_out[ 0] = v;
        v = sbox[(s1 >>  8) & 0xFF] ^ rk8[ 1]; out[ 1] = v; prev_out[ 1] = v;
        v = sbox[(s2 >> 16) & 0xFF] ^ rk8[ 2]; out[ 2] = v; prev_out[ 2] = v;
        v = sbox[(s3 >> 24) & 0xFF] ^ rk8[ 3]; out[ 3] = v; prev_out[ 3] = v;
        v = sbox[s1 & 0xFF]         ^ rk8[ 4]; out[ 4] = v; prev_out[ 4] = v;
        v = sbox[(s2 >>  8) & 0xFF] ^ rk8[ 5]; out[ 5] = v; prev_out[ 5] = v;
        v = sbox[(s3 >> 16) & 0xFF] ^ rk8[ 6]; out[ 6] = v; prev_out[ 6] = v;
        v = sbox[(s0 >> 24) & 0xFF] ^ rk8[ 7]; out[ 7] = v; prev_out[ 7] = v;
        v = sbox[s2 & 0xFF]         ^ rk8[ 8]; out[ 8] = v; prev_out[ 8] = v;
        v = sbox[(s3 >>  8) & 0xFF] ^ rk8[ 9]; out[ 9] = v; prev_out[ 9] = v;
        v = sbox[(s0 >> 16) & 0xFF] ^ rk8[10]; out[10] = v; prev_out[10] = v;
        v = sbox[(s1 >> 24) & 0xFF] ^ rk8[11]; out[11] = v; prev_out[11] = v;
        v = sbox[s3 & 0xFF]         ^ rk8[12]; out[12] = v; prev_out[12] = v;
        v = sbox[(s0 >>  8) & 0xFF] ^ rk8[13]; out[13] = v; prev_out[13] = v;
        v = sbox[(s1 >> 16) & 0xFF] ^ rk8[14]; out[14] = v; prev_out[14] = v;
        v = sbox[(s2 >> 24) & 0xFF] ^ rk8[15]; out[15] = v; prev_out[15] = v;
    }
}

/* AES-128 专用 CBC 解密: 完全展开 + 下一密文块 XOR 合并进最终轮 */
static __attribute__((always_inline)) inline void
InvCipher_inline_cbc_dec_aes128(const u8 *__restrict dw,
                                const u8 *__restrict in,
                                const u8 *__restrict next_cipher,
                                u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw + 40;

    s0 = pack_u32_le(in +  0) ^ drk[0];
    s1 = pack_u32_le(in +  4) ^ drk[1];
    s2 = pack_u32_le(in +  8) ^ drk[2];
    s3 = pack_u32_le(in + 12) ^ drk[3];

    AES_DEC_ROUND_FULL(drk -  4);
    AES_DEC_ROUND_FULL(drk -  8);
    AES_DEC_ROUND_FULL(drk - 12);
    AES_DEC_ROUND_FULL(drk - 16);
    AES_DEC_ROUND_FULL(drk - 20);
    AES_DEC_ROUND_FULL(drk - 24);
    AES_DEC_ROUND_FULL(drk - 28);
    AES_DEC_ROUND_FULL(drk - 32);
    AES_DEC_ROUND_FULL(drk - 36);

    {
        const u8 *drk8 = (const u8 *)dw;
        u32 c0 = pack_u32_le(next_cipher +  0);
        u32 c1 = pack_u32_le(next_cipher +  4);
        u32 c2 = pack_u32_le(next_cipher +  8);
        u32 c3 = pack_u32_le(next_cipher + 12);
        u32 r0 = (u32)inv_sbox[s0 & 0xFF]
               | ((u32)inv_sbox[(s3 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s2 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s1 >> 24) & 0xFF] << 24);
        u32 r1 = (u32)inv_sbox[s1 & 0xFF]
               | ((u32)inv_sbox[(s0 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s3 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s2 >> 24) & 0xFF] << 24);
        u32 r2 = (u32)inv_sbox[s2 & 0xFF]
               | ((u32)inv_sbox[(s1 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s0 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s3 >> 24) & 0xFF] << 24);
        u32 r3 = (u32)inv_sbox[s3 & 0xFF]
               | ((u32)inv_sbox[(s2 >>  8) & 0xFF] <<  8)
               | ((u32)inv_sbox[(s1 >> 16) & 0xFF] << 16)
               | ((u32)inv_sbox[(s0 >> 24) & 0xFF] << 24);
        r0 ^= ((const u32 *)(const void *)drk8)[0] ^ c0;
        r1 ^= ((const u32 *)(const void *)drk8)[1] ^ c1;
        r2 ^= ((const u32 *)(const void *)drk8)[2] ^ c2;
        r3 ^= ((const u32 *)(const void *)drk8)[3] ^ c3;
        unpack_u32_le(r0, out +  0);
        unpack_u32_le(r1, out +  4);
        unpack_u32_le(r2, out +  8);
        unpack_u32_le(r3, out + 12);
    }
}

/* 根据 ctx->Nr 自动选择 AES-256/128 完全展开路径或通用路径的加密封装。
 * 用于 CCM/GCM 等 CBC-ECB-CTR 之外的复合模式, 消除 Cipher() 内的
 * tables_ready 检查 (调用者须确保已初始化) 和 Nr 循环判断开销。 */
static __attribute__((always_inline)) inline void
Cipher_auto(const AES_Context *ctx, const u8 *in, u8 *out)
{
    if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, in, out);
    else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, in, out);
    else                    Cipher_inline(ctx->w, ctx->Nr, in, out);
}

/* AES-256 专用 CBC 加密: 完全展开 + prev XOR 合并进第一轮 */
static __attribute__((always_inline)) inline void
Cipher_inline_cbc_enc_aes256(const u8 *__restrict w,
                             const u8 *__restrict in,
                             const u8 *__restrict prev,
                             u8 *__restrict out,
                             u8 *__restrict prev_out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;

    s0 = pack_u32_le(in +  0) ^ pack_u32_le(prev +  0) ^ rk[0];
    s1 = pack_u32_le(in +  4) ^ pack_u32_le(prev +  4) ^ rk[1];
    s2 = pack_u32_le(in +  8) ^ pack_u32_le(prev +  8) ^ rk[2];
    s3 = pack_u32_le(in + 12) ^ pack_u32_le(prev + 12) ^ rk[3];

    AES_ENC_ROUND_FULL(rk +  4);
    AES_ENC_ROUND_FULL(rk +  8);
    AES_ENC_ROUND_FULL(rk + 12);
    AES_ENC_ROUND_FULL(rk + 16);
    AES_ENC_ROUND_FULL(rk + 20);
    AES_ENC_ROUND_FULL(rk + 24);
    AES_ENC_ROUND_FULL(rk + 28);
    AES_ENC_ROUND_FULL(rk + 32);
    AES_ENC_ROUND_FULL(rk + 36);
    AES_ENC_ROUND_FULL(rk + 40);
    AES_ENC_ROUND_FULL(rk + 44);
    AES_ENC_ROUND_FULL(rk + 48);
    AES_ENC_ROUND_FULL(rk + 52);

    {
        const u8 *rk8 = (const u8 *)(rk + 56);
        u8 v;
        v = sbox[s0 & 0xFF]         ^ rk8[ 0]; out[ 0] = v; prev_out[ 0] = v;
        v = sbox[(s1 >>  8) & 0xFF] ^ rk8[ 1]; out[ 1] = v; prev_out[ 1] = v;
        v = sbox[(s2 >> 16) & 0xFF] ^ rk8[ 2]; out[ 2] = v; prev_out[ 2] = v;
        v = sbox[(s3 >> 24) & 0xFF] ^ rk8[ 3]; out[ 3] = v; prev_out[ 3] = v;
        v = sbox[s1 & 0xFF]         ^ rk8[ 4]; out[ 4] = v; prev_out[ 4] = v;
        v = sbox[(s2 >>  8) & 0xFF] ^ rk8[ 5]; out[ 5] = v; prev_out[ 5] = v;
        v = sbox[(s3 >> 16) & 0xFF] ^ rk8[ 6]; out[ 6] = v; prev_out[ 6] = v;
        v = sbox[(s0 >> 24) & 0xFF] ^ rk8[ 7]; out[ 7] = v; prev_out[ 7] = v;
        v = sbox[s2 & 0xFF]         ^ rk8[ 8]; out[ 8] = v; prev_out[ 8] = v;
        v = sbox[(s3 >>  8) & 0xFF] ^ rk8[ 9]; out[ 9] = v; prev_out[ 9] = v;
        v = sbox[(s0 >> 16) & 0xFF] ^ rk8[10]; out[10] = v; prev_out[10] = v;
        v = sbox[(s1 >> 24) & 0xFF] ^ rk8[11]; out[11] = v; prev_out[11] = v;
        v = sbox[s3 & 0xFF]         ^ rk8[12]; out[12] = v; prev_out[12] = v;
        v = sbox[(s0 >>  8) & 0xFF] ^ rk8[13]; out[13] = v; prev_out[13] = v;
        v = sbox[(s1 >> 16) & 0xFF] ^ rk8[14]; out[14] = v; prev_out[14] = v;
        v = sbox[(s2 >> 24) & 0xFF] ^ rk8[15]; out[15] = v; prev_out[15] = v;
    }
}

/* AES-256 专用 CBC 解密: 完全展开 + XOR prev 合并进最后一轮 */
static __attribute__((always_inline)) inline void
InvCipher_inline_cbc_dec_aes256(const u8 *__restrict dw,
                                const u8 *__restrict in,
                                const u8 *__restrict prev,
                                u8 *__restrict out)
{
    u32 s0, s1, s2, s3, t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw + 56;

    s0 = pack_u32_le(in +  0) ^ drk[0];
    s1 = pack_u32_le(in +  4) ^ drk[1];
    s2 = pack_u32_le(in +  8) ^ drk[2];
    s3 = pack_u32_le(in + 12) ^ drk[3];

    AES_DEC_ROUND_FULL(drk -  4);
    AES_DEC_ROUND_FULL(drk -  8);
    AES_DEC_ROUND_FULL(drk - 12);
    AES_DEC_ROUND_FULL(drk - 16);
    AES_DEC_ROUND_FULL(drk - 20);
    AES_DEC_ROUND_FULL(drk - 24);
    AES_DEC_ROUND_FULL(drk - 28);
    AES_DEC_ROUND_FULL(drk - 32);
    AES_DEC_ROUND_FULL(drk - 36);
    AES_DEC_ROUND_FULL(drk - 40);
    AES_DEC_ROUND_FULL(drk - 44);
    AES_DEC_ROUND_FULL(drk - 48);
    AES_DEC_ROUND_FULL(drk - 52);

    {
        const u8 *drk8 = (const u8 *)dw;
        out[ 0] = inv_sbox[s0 & 0xFF]         ^ drk8[ 0] ^ prev[ 0];
        out[ 1] = inv_sbox[(s3 >>  8) & 0xFF] ^ drk8[ 1] ^ prev[ 1];
        out[ 2] = inv_sbox[(s2 >> 16) & 0xFF] ^ drk8[ 2] ^ prev[ 2];
        out[ 3] = inv_sbox[(s1 >> 24) & 0xFF] ^ drk8[ 3] ^ prev[ 3];
        out[ 4] = inv_sbox[s1 & 0xFF]         ^ drk8[ 4] ^ prev[ 4];
        out[ 5] = inv_sbox[(s0 >>  8) & 0xFF] ^ drk8[ 5] ^ prev[ 5];
        out[ 6] = inv_sbox[(s3 >> 16) & 0xFF] ^ drk8[ 6] ^ prev[ 6];
        out[ 7] = inv_sbox[(s2 >> 24) & 0xFF] ^ drk8[ 7] ^ prev[ 7];
        out[ 8] = inv_sbox[s2 & 0xFF]         ^ drk8[ 8] ^ prev[ 8];
        out[ 9] = inv_sbox[(s1 >>  8) & 0xFF] ^ drk8[ 9] ^ prev[ 9];
        out[10] = inv_sbox[(s0 >> 16) & 0xFF] ^ drk8[10] ^ prev[10];
        out[11] = inv_sbox[(s3 >> 24) & 0xFF] ^ drk8[11] ^ prev[11];
        out[12] = inv_sbox[s3 & 0xFF]         ^ drk8[12] ^ prev[12];
        out[13] = inv_sbox[(s2 >>  8) & 0xFF] ^ drk8[13] ^ prev[13];
        out[14] = inv_sbox[(s1 >> 16) & 0xFF] ^ drk8[14] ^ prev[14];
        out[15] = inv_sbox[(s0 >> 24) & 0xFF] ^ drk8[15] ^ prev[15];
    }
}

static void InvCipher(const uint8_t* dw, int Nr, const uint8_t* in, uint8_t* out) {
    if (!aes_tables_ready) aes_init_tables();
    InvCipher_inline(dw, Nr, in, out);
}

/* ===========================================================================
 * 2 块并行 ECB 加密 (Cipher_inline_x2):
 *   2 块状态共需 8 个 u32 (state) + 4 个 u32 (temp) = 12 个 u32,
 *   适配 32-bit x86 的 8 个通用寄存器 (会少量 spill 但比 x4 好)。
 * ========================================================================= */
static __attribute__((always_inline)) inline void
Cipher_inline_x2(const u8 *__restrict w, int Nr,
                 const u8 *__restrict in0,
                 const u8 *__restrict in1,
                 u8 *__restrict out0,
                 u8 *__restrict out1)
{
    u32 a0, a1, a2, a3;
    u32 b0, b1, b2, b3;
    u32 t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;
    int rnd;

    a0 = pack_u32_le(in0 +  0) ^ rk[0];
    a1 = pack_u32_le(in0 +  4) ^ rk[1];
    a2 = pack_u32_le(in0 +  8) ^ rk[2];
    a3 = pack_u32_le(in0 + 12) ^ rk[3];
    b0 = pack_u32_le(in1 +  0) ^ rk[0];
    b1 = pack_u32_le(in1 +  4) ^ rk[1];
    b2 = pack_u32_le(in1 +  8) ^ rk[2];
    b3 = pack_u32_le(in1 + 12) ^ rk[3];
    rk += 4;

    for (rnd = 1; rnd < Nr; ++rnd) {
        /* block 0 */
        t0 = Te0[a0&0xFF] ^ Te1[(a1>>8)&0xFF] ^ Te2[(a2>>16)&0xFF] ^ Te3[(a3>>24)&0xFF] ^ rk[0];
        t1 = Te0[a1&0xFF] ^ Te1[(a2>>8)&0xFF] ^ Te2[(a3>>16)&0xFF] ^ Te3[(a0>>24)&0xFF] ^ rk[1];
        t2 = Te0[a2&0xFF] ^ Te1[(a3>>8)&0xFF] ^ Te2[(a0>>16)&0xFF] ^ Te3[(a1>>24)&0xFF] ^ rk[2];
        t3 = Te0[a3&0xFF] ^ Te1[(a0>>8)&0xFF] ^ Te2[(a1>>16)&0xFF] ^ Te3[(a2>>24)&0xFF] ^ rk[3];
        a0 = t0; a1 = t1; a2 = t2; a3 = t3;
        /* block 1 */
        t0 = Te0[b0&0xFF] ^ Te1[(b1>>8)&0xFF] ^ Te2[(b2>>16)&0xFF] ^ Te3[(b3>>24)&0xFF] ^ rk[0];
        t1 = Te0[b1&0xFF] ^ Te1[(b2>>8)&0xFF] ^ Te2[(b3>>16)&0xFF] ^ Te3[(b0>>24)&0xFF] ^ rk[1];
        t2 = Te0[b2&0xFF] ^ Te1[(b3>>8)&0xFF] ^ Te2[(b0>>16)&0xFF] ^ Te3[(b1>>24)&0xFF] ^ rk[2];
        t3 = Te0[b3&0xFF] ^ Te1[(b0>>8)&0xFF] ^ Te2[(b1>>16)&0xFF] ^ Te3[(b2>>24)&0xFF] ^ rk[3];
        b0 = t0; b1 = t1; b2 = t2; b3 = t3;
        rk += 4;
    }

    {
        const u8 *rk8 = (const u8 *)rk;
        out0[ 0] = sbox[a0 & 0xFF]         ^ rk8[ 0];
        out0[ 1] = sbox[(a1 >>  8) & 0xFF] ^ rk8[ 1];
        out0[ 2] = sbox[(a2 >> 16) & 0xFF] ^ rk8[ 2];
        out0[ 3] = sbox[(a3 >> 24) & 0xFF] ^ rk8[ 3];
        out0[ 4] = sbox[a1 & 0xFF]         ^ rk8[ 4];
        out0[ 5] = sbox[(a2 >>  8) & 0xFF] ^ rk8[ 5];
        out0[ 6] = sbox[(a3 >> 16) & 0xFF] ^ rk8[ 6];
        out0[ 7] = sbox[(a0 >> 24) & 0xFF] ^ rk8[ 7];
        out0[ 8] = sbox[a2 & 0xFF]         ^ rk8[ 8];
        out0[ 9] = sbox[(a3 >>  8) & 0xFF] ^ rk8[ 9];
        out0[10] = sbox[(a0 >> 16) & 0xFF] ^ rk8[10];
        out0[11] = sbox[(a1 >> 24) & 0xFF] ^ rk8[11];
        out0[12] = sbox[a3 & 0xFF]         ^ rk8[12];
        out0[13] = sbox[(a0 >>  8) & 0xFF] ^ rk8[13];
        out0[14] = sbox[(a1 >> 16) & 0xFF] ^ rk8[14];
        out0[15] = sbox[(a2 >> 24) & 0xFF] ^ rk8[15];
        out1[ 0] = sbox[b0 & 0xFF]         ^ rk8[ 0];
        out1[ 1] = sbox[(b1 >>  8) & 0xFF] ^ rk8[ 1];
        out1[ 2] = sbox[(b2 >> 16) & 0xFF] ^ rk8[ 2];
        out1[ 3] = sbox[(b3 >> 24) & 0xFF] ^ rk8[ 3];
        out1[ 4] = sbox[b1 & 0xFF]         ^ rk8[ 4];
        out1[ 5] = sbox[(b2 >>  8) & 0xFF] ^ rk8[ 5];
        out1[ 6] = sbox[(b3 >> 16) & 0xFF] ^ rk8[ 6];
        out1[ 7] = sbox[(b0 >> 24) & 0xFF] ^ rk8[ 7];
        out1[ 8] = sbox[b2 & 0xFF]         ^ rk8[ 8];
        out1[ 9] = sbox[(b3 >>  8) & 0xFF] ^ rk8[ 9];
        out1[10] = sbox[(b0 >> 16) & 0xFF] ^ rk8[10];
        out1[11] = sbox[(b1 >> 24) & 0xFF] ^ rk8[11];
        out1[12] = sbox[b3 & 0xFF]         ^ rk8[12];
        out1[13] = sbox[(b0 >>  8) & 0xFF] ^ rk8[13];
        out1[14] = sbox[(b1 >> 16) & 0xFF] ^ rk8[14];
        out1[15] = sbox[(b2 >> 24) & 0xFF] ^ rk8[15];
    }
}

/* 2 块并行解密 */
static __attribute__((always_inline)) inline void
InvCipher_inline_x2(const u8 *__restrict dw, int Nr,
                    const u8 *__restrict in0,
                    const u8 *__restrict in1,
                    u8 *__restrict out0,
                    u8 *__restrict out1)
{
    u32 a0, a1, a2, a3;
    u32 b0, b1, b2, b3;
    u32 t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw;
    int rnd;

    drk += 4 * Nr;
    a0 = pack_u32_le(in0 +  0) ^ drk[0];
    a1 = pack_u32_le(in0 +  4) ^ drk[1];
    a2 = pack_u32_le(in0 +  8) ^ drk[2];
    a3 = pack_u32_le(in0 + 12) ^ drk[3];
    b0 = pack_u32_le(in1 +  0) ^ drk[0];
    b1 = pack_u32_le(in1 +  4) ^ drk[1];
    b2 = pack_u32_le(in1 +  8) ^ drk[2];
    b3 = pack_u32_le(in1 + 12) ^ drk[3];
    drk -= 4;

    for (rnd = Nr - 1; rnd > 0; --rnd) {
        t0 = Td0[a0&0xFF] ^ Td1[(a3>>8)&0xFF] ^ Td2[(a2>>16)&0xFF] ^ Td3[(a1>>24)&0xFF] ^ drk[0];
        t1 = Td0[a1&0xFF] ^ Td1[(a0>>8)&0xFF] ^ Td2[(a3>>16)&0xFF] ^ Td3[(a2>>24)&0xFF] ^ drk[1];
        t2 = Td0[a2&0xFF] ^ Td1[(a1>>8)&0xFF] ^ Td2[(a0>>16)&0xFF] ^ Td3[(a3>>24)&0xFF] ^ drk[2];
        t3 = Td0[a3&0xFF] ^ Td1[(a2>>8)&0xFF] ^ Td2[(a1>>16)&0xFF] ^ Td3[(a0>>24)&0xFF] ^ drk[3];
        a0 = t0; a1 = t1; a2 = t2; a3 = t3;
        t0 = Td0[b0&0xFF] ^ Td1[(b3>>8)&0xFF] ^ Td2[(b2>>16)&0xFF] ^ Td3[(b1>>24)&0xFF] ^ drk[0];
        t1 = Td0[b1&0xFF] ^ Td1[(b0>>8)&0xFF] ^ Td2[(b3>>16)&0xFF] ^ Td3[(b2>>24)&0xFF] ^ drk[1];
        t2 = Td0[b2&0xFF] ^ Td1[(b1>>8)&0xFF] ^ Td2[(b0>>16)&0xFF] ^ Td3[(b3>>24)&0xFF] ^ drk[2];
        t3 = Td0[b3&0xFF] ^ Td1[(b2>>8)&0xFF] ^ Td2[(b1>>16)&0xFF] ^ Td3[(b0>>24)&0xFF] ^ drk[3];
        b0 = t0; b1 = t1; b2 = t2; b3 = t3;
        drk -= 4;
    }

    {
        const u8 *drk8 = (const u8 *)drk;
        out0[ 0] = inv_sbox[a0 & 0xFF]         ^ drk8[ 0];
        out0[ 1] = inv_sbox[(a3 >>  8) & 0xFF] ^ drk8[ 1];
        out0[ 2] = inv_sbox[(a2 >> 16) & 0xFF] ^ drk8[ 2];
        out0[ 3] = inv_sbox[(a1 >> 24) & 0xFF] ^ drk8[ 3];
        out0[ 4] = inv_sbox[a1 & 0xFF]         ^ drk8[ 4];
        out0[ 5] = inv_sbox[(a0 >>  8) & 0xFF] ^ drk8[ 5];
        out0[ 6] = inv_sbox[(a3 >> 16) & 0xFF] ^ drk8[ 6];
        out0[ 7] = inv_sbox[(a2 >> 24) & 0xFF] ^ drk8[ 7];
        out0[ 8] = inv_sbox[a2 & 0xFF]         ^ drk8[ 8];
        out0[ 9] = inv_sbox[(a1 >>  8) & 0xFF] ^ drk8[ 9];
        out0[10] = inv_sbox[(a0 >> 16) & 0xFF] ^ drk8[10];
        out0[11] = inv_sbox[(a3 >> 24) & 0xFF] ^ drk8[11];
        out0[12] = inv_sbox[a3 & 0xFF]         ^ drk8[12];
        out0[13] = inv_sbox[(a2 >>  8) & 0xFF] ^ drk8[13];
        out0[14] = inv_sbox[(a1 >> 16) & 0xFF] ^ drk8[14];
        out0[15] = inv_sbox[(a0 >> 24) & 0xFF] ^ drk8[15];
        out1[ 0] = inv_sbox[b0 & 0xFF]         ^ drk8[ 0];
        out1[ 1] = inv_sbox[(b3 >>  8) & 0xFF] ^ drk8[ 1];
        out1[ 2] = inv_sbox[(b2 >> 16) & 0xFF] ^ drk8[ 2];
        out1[ 3] = inv_sbox[(b1 >> 24) & 0xFF] ^ drk8[ 3];
        out1[ 4] = inv_sbox[b1 & 0xFF]         ^ drk8[ 4];
        out1[ 5] = inv_sbox[(b0 >>  8) & 0xFF] ^ drk8[ 5];
        out1[ 6] = inv_sbox[(b3 >> 16) & 0xFF] ^ drk8[ 6];
        out1[ 7] = inv_sbox[(b2 >> 24) & 0xFF] ^ drk8[ 7];
        out1[ 8] = inv_sbox[b2 & 0xFF]         ^ drk8[ 8];
        out1[ 9] = inv_sbox[(b1 >>  8) & 0xFF] ^ drk8[ 9];
        out1[10] = inv_sbox[(b0 >> 16) & 0xFF] ^ drk8[10];
        out1[11] = inv_sbox[(b3 >> 24) & 0xFF] ^ drk8[11];
        out1[12] = inv_sbox[b3 & 0xFF]         ^ drk8[12];
        out1[13] = inv_sbox[(b2 >>  8) & 0xFF] ^ drk8[13];
        out1[14] = inv_sbox[(b1 >> 16) & 0xFF] ^ drk8[14];
        out1[15] = inv_sbox[(b0 >> 24) & 0xFF] ^ drk8[15];
    }
}

/* ===========================================================================
 * 4 块并行 ECB 加密 (Cipher_inline_x4):
 *   4 个块的状态同时保留在寄存器中, CPU 流水线自动提取 ILP,
 *   充分利用双 load 端口, 把每轮 4 次查表的延迟隐藏到 4 块之间。
 *   仅用于 ECB / CTR / OFB / CFB128 等块间无依赖的模式。
 *   CBC 加密本质串行, 不能用此函数。
 * ========================================================================= */
static __attribute__((always_inline)) inline void
Cipher_inline_x4(const u8 *__restrict w, int Nr,
                 const u8 *__restrict in0,
                 const u8 *__restrict in1,
                 const u8 *__restrict in2,
                 const u8 *__restrict in3,
                 u8 *__restrict out0,
                 u8 *__restrict out1,
                 u8 *__restrict out2,
                 u8 *__restrict out3)
{
    u32 a0, a1, a2, a3;  /* block 0 state */
    u32 b0, b1, b2, b3;  /* block 1 state */
    u32 c0, c1, c2, c3;  /* block 2 state */
    u32 d0, d1, d2, d3;  /* block 3 state */
    u32 t0, t1, t2, t3;
    const u32 *__restrict rk = (const u32 *)(const void *)w;
    int rnd;

    a0 = pack_u32_le(in0 +  0) ^ rk[0];
    a1 = pack_u32_le(in0 +  4) ^ rk[1];
    a2 = pack_u32_le(in0 +  8) ^ rk[2];
    a3 = pack_u32_le(in0 + 12) ^ rk[3];
    b0 = pack_u32_le(in1 +  0) ^ rk[0];
    b1 = pack_u32_le(in1 +  4) ^ rk[1];
    b2 = pack_u32_le(in1 +  8) ^ rk[2];
    b3 = pack_u32_le(in1 + 12) ^ rk[3];
    c0 = pack_u32_le(in2 +  0) ^ rk[0];
    c1 = pack_u32_le(in2 +  4) ^ rk[1];
    c2 = pack_u32_le(in2 +  8) ^ rk[2];
    c3 = pack_u32_le(in2 + 12) ^ rk[3];
    d0 = pack_u32_le(in3 +  0) ^ rk[0];
    d1 = pack_u32_le(in3 +  4) ^ rk[1];
    d2 = pack_u32_le(in3 +  8) ^ rk[2];
    d3 = pack_u32_le(in3 + 12) ^ rk[3];
    rk += 4;

    for (rnd = 1; rnd < Nr; ++rnd) {
        /* block 0 */
        t0 = Te0[a0&0xFF] ^ Te1[(a1>>8)&0xFF] ^ Te2[(a2>>16)&0xFF] ^ Te3[(a3>>24)&0xFF] ^ rk[0];
        t1 = Te0[a1&0xFF] ^ Te1[(a2>>8)&0xFF] ^ Te2[(a3>>16)&0xFF] ^ Te3[(a0>>24)&0xFF] ^ rk[1];
        t2 = Te0[a2&0xFF] ^ Te1[(a3>>8)&0xFF] ^ Te2[(a0>>16)&0xFF] ^ Te3[(a1>>24)&0xFF] ^ rk[2];
        t3 = Te0[a3&0xFF] ^ Te1[(a0>>8)&0xFF] ^ Te2[(a1>>16)&0xFF] ^ Te3[(a2>>24)&0xFF] ^ rk[3];
        a0 = t0; a1 = t1; a2 = t2; a3 = t3;
        /* block 1 */
        t0 = Te0[b0&0xFF] ^ Te1[(b1>>8)&0xFF] ^ Te2[(b2>>16)&0xFF] ^ Te3[(b3>>24)&0xFF] ^ rk[0];
        t1 = Te0[b1&0xFF] ^ Te1[(b2>>8)&0xFF] ^ Te2[(b3>>16)&0xFF] ^ Te3[(b0>>24)&0xFF] ^ rk[1];
        t2 = Te0[b2&0xFF] ^ Te1[(b3>>8)&0xFF] ^ Te2[(b0>>16)&0xFF] ^ Te3[(b1>>24)&0xFF] ^ rk[2];
        t3 = Te0[b3&0xFF] ^ Te1[(b0>>8)&0xFF] ^ Te2[(b1>>16)&0xFF] ^ Te3[(b2>>24)&0xFF] ^ rk[3];
        b0 = t0; b1 = t1; b2 = t2; b3 = t3;
        /* block 2 */
        t0 = Te0[c0&0xFF] ^ Te1[(c1>>8)&0xFF] ^ Te2[(c2>>16)&0xFF] ^ Te3[(c3>>24)&0xFF] ^ rk[0];
        t1 = Te0[c1&0xFF] ^ Te1[(c2>>8)&0xFF] ^ Te2[(c3>>16)&0xFF] ^ Te3[(c0>>24)&0xFF] ^ rk[1];
        t2 = Te0[c2&0xFF] ^ Te1[(c3>>8)&0xFF] ^ Te2[(c0>>16)&0xFF] ^ Te3[(c1>>24)&0xFF] ^ rk[2];
        t3 = Te0[c3&0xFF] ^ Te1[(c0>>8)&0xFF] ^ Te2[(c1>>16)&0xFF] ^ Te3[(c2>>24)&0xFF] ^ rk[3];
        c0 = t0; c1 = t1; c2 = t2; c3 = t3;
        /* block 3 */
        t0 = Te0[d0&0xFF] ^ Te1[(d1>>8)&0xFF] ^ Te2[(d2>>16)&0xFF] ^ Te3[(d3>>24)&0xFF] ^ rk[0];
        t1 = Te0[d1&0xFF] ^ Te1[(d2>>8)&0xFF] ^ Te2[(d3>>16)&0xFF] ^ Te3[(d0>>24)&0xFF] ^ rk[1];
        t2 = Te0[d2&0xFF] ^ Te1[(d3>>8)&0xFF] ^ Te2[(d0>>16)&0xFF] ^ Te3[(d1>>24)&0xFF] ^ rk[2];
        t3 = Te0[d3&0xFF] ^ Te1[(d0>>8)&0xFF] ^ Te2[(d1>>16)&0xFF] ^ Te3[(d2>>24)&0xFF] ^ rk[3];
        d0 = t0; d1 = t1; d2 = t2; d3 = t3;
        rk += 4;
    }

    /* 最后一轮: SubBytes + ShiftRows + AddRoundKey (无 MixColumns) */
    {
        const u8 *rk8 = (const u8 *)rk;
        /* block 0 */
        out0[ 0] = sbox[a0 & 0xFF]         ^ rk8[ 0];
        out0[ 1] = sbox[(a1 >>  8) & 0xFF] ^ rk8[ 1];
        out0[ 2] = sbox[(a2 >> 16) & 0xFF] ^ rk8[ 2];
        out0[ 3] = sbox[(a3 >> 24) & 0xFF] ^ rk8[ 3];
        out0[ 4] = sbox[a1 & 0xFF]         ^ rk8[ 4];
        out0[ 5] = sbox[(a2 >>  8) & 0xFF] ^ rk8[ 5];
        out0[ 6] = sbox[(a3 >> 16) & 0xFF] ^ rk8[ 6];
        out0[ 7] = sbox[(a0 >> 24) & 0xFF] ^ rk8[ 7];
        out0[ 8] = sbox[a2 & 0xFF]         ^ rk8[ 8];
        out0[ 9] = sbox[(a3 >>  8) & 0xFF] ^ rk8[ 9];
        out0[10] = sbox[(a0 >> 16) & 0xFF] ^ rk8[10];
        out0[11] = sbox[(a1 >> 24) & 0xFF] ^ rk8[11];
        out0[12] = sbox[a3 & 0xFF]         ^ rk8[12];
        out0[13] = sbox[(a0 >>  8) & 0xFF] ^ rk8[13];
        out0[14] = sbox[(a1 >> 16) & 0xFF] ^ rk8[14];
        out0[15] = sbox[(a2 >> 24) & 0xFF] ^ rk8[15];
        /* block 1 */
        out1[ 0] = sbox[b0 & 0xFF]         ^ rk8[ 0];
        out1[ 1] = sbox[(b1 >>  8) & 0xFF] ^ rk8[ 1];
        out1[ 2] = sbox[(b2 >> 16) & 0xFF] ^ rk8[ 2];
        out1[ 3] = sbox[(b3 >> 24) & 0xFF] ^ rk8[ 3];
        out1[ 4] = sbox[b1 & 0xFF]         ^ rk8[ 4];
        out1[ 5] = sbox[(b2 >>  8) & 0xFF] ^ rk8[ 5];
        out1[ 6] = sbox[(b3 >> 16) & 0xFF] ^ rk8[ 6];
        out1[ 7] = sbox[(b0 >> 24) & 0xFF] ^ rk8[ 7];
        out1[ 8] = sbox[b2 & 0xFF]         ^ rk8[ 8];
        out1[ 9] = sbox[(b3 >>  8) & 0xFF] ^ rk8[ 9];
        out1[10] = sbox[(b0 >> 16) & 0xFF] ^ rk8[10];
        out1[11] = sbox[(b1 >> 24) & 0xFF] ^ rk8[11];
        out1[12] = sbox[b3 & 0xFF]         ^ rk8[12];
        out1[13] = sbox[(b0 >>  8) & 0xFF] ^ rk8[13];
        out1[14] = sbox[(b1 >> 16) & 0xFF] ^ rk8[14];
        out1[15] = sbox[(b2 >> 24) & 0xFF] ^ rk8[15];
        /* block 2 */
        out2[ 0] = sbox[c0 & 0xFF]         ^ rk8[ 0];
        out2[ 1] = sbox[(c1 >>  8) & 0xFF] ^ rk8[ 1];
        out2[ 2] = sbox[(c2 >> 16) & 0xFF] ^ rk8[ 2];
        out2[ 3] = sbox[(c3 >> 24) & 0xFF] ^ rk8[ 3];
        out2[ 4] = sbox[c1 & 0xFF]         ^ rk8[ 4];
        out2[ 5] = sbox[(c2 >>  8) & 0xFF] ^ rk8[ 5];
        out2[ 6] = sbox[(c3 >> 16) & 0xFF] ^ rk8[ 6];
        out2[ 7] = sbox[(c0 >> 24) & 0xFF] ^ rk8[ 7];
        out2[ 8] = sbox[c2 & 0xFF]         ^ rk8[ 8];
        out2[ 9] = sbox[(c3 >>  8) & 0xFF] ^ rk8[ 9];
        out2[10] = sbox[(c0 >> 16) & 0xFF] ^ rk8[10];
        out2[11] = sbox[(c1 >> 24) & 0xFF] ^ rk8[11];
        out2[12] = sbox[c3 & 0xFF]         ^ rk8[12];
        out2[13] = sbox[(c0 >>  8) & 0xFF] ^ rk8[13];
        out2[14] = sbox[(c1 >> 16) & 0xFF] ^ rk8[14];
        out2[15] = sbox[(c2 >> 24) & 0xFF] ^ rk8[15];
        /* block 3 */
        out3[ 0] = sbox[d0 & 0xFF]         ^ rk8[ 0];
        out3[ 1] = sbox[(d1 >>  8) & 0xFF] ^ rk8[ 1];
        out3[ 2] = sbox[(d2 >> 16) & 0xFF] ^ rk8[ 2];
        out3[ 3] = sbox[(d3 >> 24) & 0xFF] ^ rk8[ 3];
        out3[ 4] = sbox[d1 & 0xFF]         ^ rk8[ 4];
        out3[ 5] = sbox[(d2 >>  8) & 0xFF] ^ rk8[ 5];
        out3[ 6] = sbox[(d3 >> 16) & 0xFF] ^ rk8[ 6];
        out3[ 7] = sbox[(d0 >> 24) & 0xFF] ^ rk8[ 7];
        out3[ 8] = sbox[d2 & 0xFF]         ^ rk8[ 8];
        out3[ 9] = sbox[(d3 >>  8) & 0xFF] ^ rk8[ 9];
        out3[10] = sbox[(d0 >> 16) & 0xFF] ^ rk8[10];
        out3[11] = sbox[(d1 >> 24) & 0xFF] ^ rk8[11];
        out3[12] = sbox[d3 & 0xFF]         ^ rk8[12];
        out3[13] = sbox[(d0 >>  8) & 0xFF] ^ rk8[13];
        out3[14] = sbox[(d1 >> 16) & 0xFF] ^ rk8[14];
        out3[15] = sbox[(d2 >> 24) & 0xFF] ^ rk8[15];
    }
}

/* ===========================================================================
 * 4 块并行 ECB 解密 (InvCipher_inline_x4):
 *   解密时 D_K(C_i) 互相独立, 可并行处理。
 *   也用于 CBC 解密的核心步骤, 之后串行 XOR prev 即可。
 * ========================================================================= */
static __attribute__((always_inline)) inline void
InvCipher_inline_x4(const u8 *__restrict dw, int Nr,
                    const u8 *__restrict in0,
                    const u8 *__restrict in1,
                    const u8 *__restrict in2,
                    const u8 *__restrict in3,
                    u8 *__restrict out0,
                    u8 *__restrict out1,
                    u8 *__restrict out2,
                    u8 *__restrict out3)
{
    u32 a0, a1, a2, a3;
    u32 b0, b1, b2, b3;
    u32 c0, c1, c2, c3;
    u32 d0, d1, d2, d3;
    u32 t0, t1, t2, t3;
    const u32 *__restrict drk = (const u32 *)(const void *)dw;
    int rnd;

    drk += 4 * Nr;
    a0 = pack_u32_le(in0 +  0) ^ drk[0];
    a1 = pack_u32_le(in0 +  4) ^ drk[1];
    a2 = pack_u32_le(in0 +  8) ^ drk[2];
    a3 = pack_u32_le(in0 + 12) ^ drk[3];
    b0 = pack_u32_le(in1 +  0) ^ drk[0];
    b1 = pack_u32_le(in1 +  4) ^ drk[1];
    b2 = pack_u32_le(in1 +  8) ^ drk[2];
    b3 = pack_u32_le(in1 + 12) ^ drk[3];
    c0 = pack_u32_le(in2 +  0) ^ drk[0];
    c1 = pack_u32_le(in2 +  4) ^ drk[1];
    c2 = pack_u32_le(in2 +  8) ^ drk[2];
    c3 = pack_u32_le(in2 + 12) ^ drk[3];
    d0 = pack_u32_le(in3 +  0) ^ drk[0];
    d1 = pack_u32_le(in3 +  4) ^ drk[1];
    d2 = pack_u32_le(in3 +  8) ^ drk[2];
    d3 = pack_u32_le(in3 + 12) ^ drk[3];
    drk -= 4;

    for (rnd = Nr - 1; rnd > 0; --rnd) {
        /* block 0 */
        t0 = Td0[a0&0xFF] ^ Td1[(a3>>8)&0xFF] ^ Td2[(a2>>16)&0xFF] ^ Td3[(a1>>24)&0xFF] ^ drk[0];
        t1 = Td0[a1&0xFF] ^ Td1[(a0>>8)&0xFF] ^ Td2[(a3>>16)&0xFF] ^ Td3[(a2>>24)&0xFF] ^ drk[1];
        t2 = Td0[a2&0xFF] ^ Td1[(a1>>8)&0xFF] ^ Td2[(a0>>16)&0xFF] ^ Td3[(a3>>24)&0xFF] ^ drk[2];
        t3 = Td0[a3&0xFF] ^ Td1[(a2>>8)&0xFF] ^ Td2[(a1>>16)&0xFF] ^ Td3[(a0>>24)&0xFF] ^ drk[3];
        a0 = t0; a1 = t1; a2 = t2; a3 = t3;
        /* block 1 */
        t0 = Td0[b0&0xFF] ^ Td1[(b3>>8)&0xFF] ^ Td2[(b2>>16)&0xFF] ^ Td3[(b1>>24)&0xFF] ^ drk[0];
        t1 = Td0[b1&0xFF] ^ Td1[(b0>>8)&0xFF] ^ Td2[(b3>>16)&0xFF] ^ Td3[(b2>>24)&0xFF] ^ drk[1];
        t2 = Td0[b2&0xFF] ^ Td1[(b1>>8)&0xFF] ^ Td2[(b0>>16)&0xFF] ^ Td3[(b3>>24)&0xFF] ^ drk[2];
        t3 = Td0[b3&0xFF] ^ Td1[(b2>>8)&0xFF] ^ Td2[(b1>>16)&0xFF] ^ Td3[(b0>>24)&0xFF] ^ drk[3];
        b0 = t0; b1 = t1; b2 = t2; b3 = t3;
        /* block 2 */
        t0 = Td0[c0&0xFF] ^ Td1[(c3>>8)&0xFF] ^ Td2[(c2>>16)&0xFF] ^ Td3[(c1>>24)&0xFF] ^ drk[0];
        t1 = Td0[c1&0xFF] ^ Td1[(c0>>8)&0xFF] ^ Td2[(c3>>16)&0xFF] ^ Td3[(c2>>24)&0xFF] ^ drk[1];
        t2 = Td0[c2&0xFF] ^ Td1[(c1>>8)&0xFF] ^ Td2[(c0>>16)&0xFF] ^ Td3[(c3>>24)&0xFF] ^ drk[2];
        t3 = Td0[c3&0xFF] ^ Td1[(c2>>8)&0xFF] ^ Td2[(c1>>16)&0xFF] ^ Td3[(c0>>24)&0xFF] ^ drk[3];
        c0 = t0; c1 = t1; c2 = t2; c3 = t3;
        /* block 3 */
        t0 = Td0[d0&0xFF] ^ Td1[(d3>>8)&0xFF] ^ Td2[(d2>>16)&0xFF] ^ Td3[(d1>>24)&0xFF] ^ drk[0];
        t1 = Td0[d1&0xFF] ^ Td1[(d0>>8)&0xFF] ^ Td2[(d3>>16)&0xFF] ^ Td3[(d2>>24)&0xFF] ^ drk[1];
        t2 = Td0[d2&0xFF] ^ Td1[(d1>>8)&0xFF] ^ Td2[(d0>>16)&0xFF] ^ Td3[(d3>>24)&0xFF] ^ drk[2];
        t3 = Td0[d3&0xFF] ^ Td1[(d2>>8)&0xFF] ^ Td2[(d1>>16)&0xFF] ^ Td3[(d0>>24)&0xFF] ^ drk[3];
        d0 = t0; d1 = t1; d2 = t2; d3 = t3;
        drk -= 4;
    }

    /* 最后一轮: InvShiftRows + InvSubBytes + AddRoundKey */
    {
        const u8 *drk8 = (const u8 *)drk;
        /* block 0 */
        out0[ 0] = inv_sbox[a0 & 0xFF]         ^ drk8[ 0];
        out0[ 1] = inv_sbox[(a3 >>  8) & 0xFF] ^ drk8[ 1];
        out0[ 2] = inv_sbox[(a2 >> 16) & 0xFF] ^ drk8[ 2];
        out0[ 3] = inv_sbox[(a1 >> 24) & 0xFF] ^ drk8[ 3];
        out0[ 4] = inv_sbox[a1 & 0xFF]         ^ drk8[ 4];
        out0[ 5] = inv_sbox[(a0 >>  8) & 0xFF] ^ drk8[ 5];
        out0[ 6] = inv_sbox[(a3 >> 16) & 0xFF] ^ drk8[ 6];
        out0[ 7] = inv_sbox[(a2 >> 24) & 0xFF] ^ drk8[ 7];
        out0[ 8] = inv_sbox[a2 & 0xFF]         ^ drk8[ 8];
        out0[ 9] = inv_sbox[(a1 >>  8) & 0xFF] ^ drk8[ 9];
        out0[10] = inv_sbox[(a0 >> 16) & 0xFF] ^ drk8[10];
        out0[11] = inv_sbox[(a3 >> 24) & 0xFF] ^ drk8[11];
        out0[12] = inv_sbox[a3 & 0xFF]         ^ drk8[12];
        out0[13] = inv_sbox[(a2 >>  8) & 0xFF] ^ drk8[13];
        out0[14] = inv_sbox[(a1 >> 16) & 0xFF] ^ drk8[14];
        out0[15] = inv_sbox[(a0 >> 24) & 0xFF] ^ drk8[15];
        /* block 1 */
        out1[ 0] = inv_sbox[b0 & 0xFF]         ^ drk8[ 0];
        out1[ 1] = inv_sbox[(b3 >>  8) & 0xFF] ^ drk8[ 1];
        out1[ 2] = inv_sbox[(b2 >> 16) & 0xFF] ^ drk8[ 2];
        out1[ 3] = inv_sbox[(b1 >> 24) & 0xFF] ^ drk8[ 3];
        out1[ 4] = inv_sbox[b1 & 0xFF]         ^ drk8[ 4];
        out1[ 5] = inv_sbox[(b0 >>  8) & 0xFF] ^ drk8[ 5];
        out1[ 6] = inv_sbox[(b3 >> 16) & 0xFF] ^ drk8[ 6];
        out1[ 7] = inv_sbox[(b2 >> 24) & 0xFF] ^ drk8[ 7];
        out1[ 8] = inv_sbox[b2 & 0xFF]         ^ drk8[ 8];
        out1[ 9] = inv_sbox[(b1 >>  8) & 0xFF] ^ drk8[ 9];
        out1[10] = inv_sbox[(b0 >> 16) & 0xFF] ^ drk8[10];
        out1[11] = inv_sbox[(b3 >> 24) & 0xFF] ^ drk8[11];
        out1[12] = inv_sbox[b3 & 0xFF]         ^ drk8[12];
        out1[13] = inv_sbox[(b2 >>  8) & 0xFF] ^ drk8[13];
        out1[14] = inv_sbox[(b1 >> 16) & 0xFF] ^ drk8[14];
        out1[15] = inv_sbox[(b0 >> 24) & 0xFF] ^ drk8[15];
        /* block 2 */
        out2[ 0] = inv_sbox[c0 & 0xFF]         ^ drk8[ 0];
        out2[ 1] = inv_sbox[(c3 >>  8) & 0xFF] ^ drk8[ 1];
        out2[ 2] = inv_sbox[(c2 >> 16) & 0xFF] ^ drk8[ 2];
        out2[ 3] = inv_sbox[(c1 >> 24) & 0xFF] ^ drk8[ 3];
        out2[ 4] = inv_sbox[c1 & 0xFF]         ^ drk8[ 4];
        out2[ 5] = inv_sbox[(c0 >>  8) & 0xFF] ^ drk8[ 5];
        out2[ 6] = inv_sbox[(c3 >> 16) & 0xFF] ^ drk8[ 6];
        out2[ 7] = inv_sbox[(c2 >> 24) & 0xFF] ^ drk8[ 7];
        out2[ 8] = inv_sbox[c2 & 0xFF]         ^ drk8[ 8];
        out2[ 9] = inv_sbox[(c1 >>  8) & 0xFF] ^ drk8[ 9];
        out2[10] = inv_sbox[(c0 >> 16) & 0xFF] ^ drk8[10];
        out2[11] = inv_sbox[(c3 >> 24) & 0xFF] ^ drk8[11];
        out2[12] = inv_sbox[c3 & 0xFF]         ^ drk8[12];
        out2[13] = inv_sbox[(c2 >>  8) & 0xFF] ^ drk8[13];
        out2[14] = inv_sbox[(c1 >> 16) & 0xFF] ^ drk8[14];
        out2[15] = inv_sbox[(c0 >> 24) & 0xFF] ^ drk8[15];
        /* block 3 */
        out3[ 0] = inv_sbox[d0 & 0xFF]         ^ drk8[ 0];
        out3[ 1] = inv_sbox[(d3 >>  8) & 0xFF] ^ drk8[ 1];
        out3[ 2] = inv_sbox[(d2 >> 16) & 0xFF] ^ drk8[ 2];
        out3[ 3] = inv_sbox[(d1 >> 24) & 0xFF] ^ drk8[ 3];
        out3[ 4] = inv_sbox[d1 & 0xFF]         ^ drk8[ 4];
        out3[ 5] = inv_sbox[(d0 >>  8) & 0xFF] ^ drk8[ 5];
        out3[ 6] = inv_sbox[(d3 >> 16) & 0xFF] ^ drk8[ 6];
        out3[ 7] = inv_sbox[(d2 >> 24) & 0xFF] ^ drk8[ 7];
        out3[ 8] = inv_sbox[d2 & 0xFF]         ^ drk8[ 8];
        out3[ 9] = inv_sbox[(d1 >>  8) & 0xFF] ^ drk8[ 9];
        out3[10] = inv_sbox[(d0 >> 16) & 0xFF] ^ drk8[10];
        out3[11] = inv_sbox[(d3 >> 24) & 0xFF] ^ drk8[11];
        out3[12] = inv_sbox[d3 & 0xFF]         ^ drk8[12];
        out3[13] = inv_sbox[(d2 >>  8) & 0xFF] ^ drk8[13];
        out3[14] = inv_sbox[(d1 >> 16) & 0xFF] ^ drk8[14];
        out3[15] = inv_sbox[(d0 >> 24) & 0xFF] ^ drk8[15];
    }
}

/* 兼容旧函数 (未调用但保持符号安全) */
static void AddRoundKey_unused(uint8_t* state, const uint8_t* w, int round) {
    int i;
    (void)state; (void)w; (void)round; (void)i;
}

static int KeyExpansion(AES_Context* ctx, const uint8_t* key) {
    int key_len, w_size, i;
    uint8_t temp[4];
    uint8_t t;
    
    if (ctx->w) free(ctx->w);
    ctx->w = NULL;
    
    key_len = (int)ctx->key_len;
    ctx->Nk = key_len / 4;
    ctx->Nr = ctx->Nk + 6;
    
    w_size = Nb * (ctx->Nr + 1) * 4;
    ctx->w = (uint8_t*)malloc(w_size);
    if (!ctx->w) {
        return -1;
    }
    
    i = 0;
    while (i < ctx->Nk) {
        ctx->w[4 * i] = key[4 * i];
        ctx->w[4 * i + 1] = key[4 * i + 1];
        ctx->w[4 * i + 2] = key[4 * i + 2];
        ctx->w[4 * i + 3] = key[4 * i + 3];
        ++i;
    }
    
    i = ctx->Nk;
    while (i < Nb * (ctx->Nr + 1)) {
        temp[0] = ctx->w[4 * (i - 1) + 0];
        temp[1] = ctx->w[4 * (i - 1) + 1];
        temp[2] = ctx->w[4 * (i - 1) + 2];
        temp[3] = ctx->w[4 * (i - 1) + 3];
        
        if (i % ctx->Nk == 0) {
            t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            
            temp[0] ^= Rcon[i / ctx->Nk];
        } else if (ctx->Nk > 6 && i % ctx->Nk == 4) {
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }
        
        ctx->w[4 * i + 0] = ctx->w[4 * (i - ctx->Nk) + 0] ^ temp[0];
        ctx->w[4 * i + 1] = ctx->w[4 * (i - ctx->Nk) + 1] ^ temp[1];
        ctx->w[4 * i + 2] = ctx->w[4 * (i - ctx->Nk) + 2] ^ temp[2];
        ctx->w[4 * i + 3] = ctx->w[4 * (i - ctx->Nk) + 3] ^ temp[3];
        ++i;
    }

    /* T-box & 表初始化一次 (确保后续 InvMixColumns 能查 Imc 表) */
    if (!aes_tables_ready) aes_init_tables();

    /* 无条件预计算等效解密密钥 dw (w[1..Nr-1] 经 InvMixColumns 变换)。
     * 纯软件 Td-table 解密路径和 AES-NI 路径都需要 dw。
     * 失败时降级（清除 AES_HW_NI 位，软件路径仍可用原始 w 做逐字节解密回退）。 */
    if (aes_prepare_decrypt_keys(ctx) != 0) {
        ctx->hw_flags &= ~(uint32_t)AES_HW_NI;
    }

    /* CPU 硬件能力检测：编译期已启用 AES-NI intrinsics 且 CPU 支持时置位 */
    {
        uint32_t hw = aes_detect_hw();
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
        ctx->hw_flags |= (hw & AES_HW_NI);  /* dw 已准备好, 可直接用 */
#else
        /* 编译期未启用 AES-NI intrinsics：清除 AES-NI 位, 走纯 C */
        ctx->hw_flags &= ~(uint32_t)AES_HW_NI;
#endif
        ctx->hw_flags |= (hw & AES_HW_PCLMUL);
#if AES_HAS_ARM_AES == 1
        ctx->hw_flags |= (hw & AES_HW_NEON);
#else
        ctx->hw_flags &= ~(uint32_t)AES_HW_NEON;
#endif
    }

    return 0;
}

static void AddRoundKey(uint8_t* state, const uint8_t* w, int round) {
    int i;
    for (i = 0; i < 16; ++i) {
        state[i] ^= w[round * 16 + i];
    }
}

static void SubBytes(uint8_t* state) {
    int i;
    for (i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

static void InvSubBytes(uint8_t* state) {
    int i;
    for (i = 0; i < 16; ++i) {
        state[i] = inv_sbox[state[i]];
    }
}

static void ShiftRows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

static void InvShiftRows(uint8_t* state) {
    uint8_t temp;
    
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    temp = state[10];
    state[10] = state[2];
    state[2] = temp;
    temp = state[14];
    state[14] = state[6];
    state[6] = temp;
    
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

/* 仅 GCM/CCM MAC 等内部非性能关键路径使用; Cipher 走 T-box */
static void MixColumns(uint8_t* state) {
    uint8_t temp[16];
    int col, base;
    for (col = 0; col < 4; ++col) {
        base = col * 4;
        temp[base] = gf_mult(0x02, state[base]) ^ gf_mult(0x03, state[base + 1]) ^ state[base + 2] ^ state[base + 3];
        temp[base + 1] = state[base] ^ gf_mult(0x02, state[base + 1]) ^ gf_mult(0x03, state[base + 2]) ^ state[base + 3];
        temp[base + 2] = state[base] ^ state[base + 1] ^ gf_mult(0x02, state[base + 2]) ^ gf_mult(0x03, state[base + 3]);
        temp[base + 3] = gf_mult(0x03, state[base]) ^ state[base + 1] ^ state[base + 2] ^ gf_mult(0x02, state[base + 3]);
    }
    memcpy(state, temp, 16);
}

static void InvMixColumns(uint8_t* state) {
    uint8_t temp[16];
    int col, base;
    for (col = 0; col < 4; ++col) {
        base = col * 4;
        temp[base] = gf_mult(0x0e, state[base]) ^ gf_mult(0x0b, state[base + 1]) ^ gf_mult(0x0d, state[base + 2]) ^ gf_mult(0x09, state[base + 3]);
        temp[base + 1] = gf_mult(0x09, state[base]) ^ gf_mult(0x0e, state[base + 1]) ^ gf_mult(0x0b, state[base + 2]) ^ gf_mult(0x0d, state[base + 3]);
        temp[base + 2] = gf_mult(0x0d, state[base]) ^ gf_mult(0x09, state[base + 1]) ^ gf_mult(0x0e, state[base + 2]) ^ gf_mult(0x0b, state[base + 3]);
        temp[base + 3] = gf_mult(0x0b, state[base]) ^ gf_mult(0x0d, state[base + 1]) ^ gf_mult(0x09, state[base + 2]) ^ gf_mult(0x0e, state[base + 3]);
    }
    memcpy(state, temp, 16);
}

static uint8_t* pad(const uint8_t* data, size_t size, AES_Padding padding, size_t* out_size) {
    size_t block_size, padding_len;
    uint8_t* padded;
    size_t i;
    
    block_size = BLOCK_SIZE;
    
    if (padding == AES_PADDING_NONE) {
        *out_size = size;
        padded = (uint8_t*)malloc(*out_size);
        if (!padded) {
            *out_size = 0;
            return NULL;
        }
        memcpy(padded, data, size);
        return padded;
    }
    
    padding_len = block_size - (size % block_size);
    
    if (padding_len == 0) {
        padding_len = block_size;
    }
    
    *out_size = size + padding_len;
    padded = (uint8_t*)malloc(*out_size);
    if (!padded) {
        *out_size = 0;
        return NULL;
    }
    memcpy(padded, data, size);
    
    switch (padding) {
        case AES_PADDING_NONE:
            break;
        case AES_PADDING_ZERO:
            memset(padded + size, 0, padding_len);
            break;
        case AES_PADDING_PKCS5:
        case AES_PADDING_PKCS7:
            for (i = 0; i < padding_len; ++i) {
                padded[size + i] = (uint8_t)padding_len;
            }
            break;
        case AES_PADDING_ANSIX923:
            memset(padded + size, 0, padding_len - 1);
            padded[size + padding_len - 1] = (uint8_t)padding_len;
            break;
        case AES_PADDING_ISO10126:
            if (padding_len > 1) {
                aes_random_bytes(padded + size, padding_len - 1);
            }
            padded[size + padding_len - 1] = (uint8_t)padding_len;
            break;
        case AES_PADDING_ISO7816:
            padded[size] = 0x80;
            memset(padded + size + 1, 0, padding_len - 1);
            break;
    }
    
    return padded;
}

static uint8_t* unpad(const uint8_t* data, size_t size, AES_Padding padding, size_t* out_size) {
    size_t padding_len;
    uint8_t last_byte;
    uint8_t* result;
    int i, j;
    
    if (size == 0 || size % BLOCK_SIZE != 0) {
        *out_size = 0;
        return NULL;
    }
    
    padding_len = 0;
    
    switch (padding) {
        case AES_PADDING_NONE:
            *out_size = size;
            break;
        case AES_PADDING_ZERO:
            /* 常时实现: 正向扫描全块, 用 mask 记录最后一个非零字节位置,
             * 避免 `if (data[i] != 0) break;` 的早退分支泄漏尾零数量。
             * 循环恒定执行 size 次, 无数据依赖分支。 */
            {
                size_t last_nz = 0;  /* 最后一个非零字节位置 (0-based) */
                int found = 0;
                for (i = 0; i < (int)size; ++i) {
                    /* mask = -(data[i] != 0): 非零时 mask=全1, 零时 mask=0 */
                    size_t mask = -(size_t)(data[i] != 0);
                    /* 非零字节: 更新 last_nz = i; 零字节: 保持 last_nz 不变 */
                    last_nz = (size_t)((size_t)i & mask) | (size_t)(last_nz & ~mask);
                    found |= (data[i] != 0);
                }
                /* 找到非零字节: padding_len = size - (last_nz + 1)
                 * 全零: padding_len = size */
                padding_len = found ? (size - last_nz - 1) : size;
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_PKCS5:
        case AES_PADDING_PKCS7:
            /* 常时验证: 不在循环中早退, 避免 padding oracle 通过耗时差异
             * 推断 padding 字节是否正确。先验证范围 (padding_len 来自密文,
             * 非秘密), 再用累积差异标志验证所有 padding 字节。 */
            last_byte = data[size - 1];
            padding_len = (size_t)last_byte;
            if (padding_len == 0 || padding_len > size || padding_len > BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            {
                uint8_t bad = 0;
                for (j = (int)(size - padding_len); j < (int)size; ++j) {
                    bad |= (uint8_t)(data[j] ^ last_byte);
                }
                if (bad) {
                    *out_size = 0;
                    return NULL;
                }
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_ANSIX923:
            last_byte = data[size - 1];
            padding_len = (size_t)last_byte;
            if (padding_len == 0 || padding_len > size || padding_len > BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            {
                uint8_t bad = 0;
                for (j = (int)(size - padding_len); j < (int)(size - 1); ++j) {
                    bad |= data[j];   /* 中间字节必须为 0 */
                }
                /* 最后一字节必须等于 padding_len (已在 last_byte) */
                bad |= (uint8_t)(last_byte ^ (uint8_t)padding_len);
                if (bad) {
                    *out_size = 0;
                    return NULL;
                }
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_ISO10126:
            last_byte = data[size - 1];
            padding_len = (size_t)last_byte;
            if (padding_len == 0 || padding_len > size || padding_len > BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            *out_size = size - padding_len;
            break;
        case AES_PADDING_ISO7816:
            /* 常时验证: 从块尾向前扫描, 0x80 标记之后(更高地址)必须全 0x00,
             * 0x80 标记之前(更低地址)属明文。用累积 bad 标志避免早退分支。 */
            {
                uint8_t found_marker = 0;
                uint8_t bad = 0;
                padding_len = 0;
                for (i = (int)size - 1; i >= 0; --i) {
                    uint8_t b = data[i];
                    uint8_t is_marker = (uint8_t)(!(b ^ 0x80));
                    uint8_t is_zero   = (uint8_t)(!b);
                    /* 未找到 marker 时, 字节必须是 0x00 或 0x80, 否则 bad。
                     * found_marker=0 → mask=1; =1 → mask=0 (后续字节属明文, 不验证) */
                    uint8_t mask = (uint8_t)(found_marker ^ 1u);
                    bad |= (uint8_t)(mask & (uint8_t)(!(is_zero | is_marker)));
                    /* 记录第一个 marker 位置 (padding_len 非秘密, 可分支) */
                    if (!found_marker && is_marker) {
                        padding_len = size - (size_t)i;
                        found_marker = 1;
                    }
                }
                if (!found_marker || bad) {
                    *out_size = 0;
                    return NULL;
                }
                *out_size = size - padding_len;
            }
            break;
    }
    
    result = (uint8_t*)malloc(*out_size);
    if (!result) {
        *out_size = 0;
        return NULL;
    }
    memcpy(result, data, *out_size);
    return result;
}

int aes_init(AES_Context* ctx, AES_KeyLength key_len, const uint8_t* key, size_t key_size,
             const uint8_t* iv, size_t iv_size) {
    if (!ctx || !key || key_size != (size_t)key_len) {
        return -1;
    }
    
    ctx->key_len = key_len;
    ctx->iv_set = 0;
    ctx->w = NULL;
    ctx->dw = NULL;
    ctx->hw_flags = AES_HW_NONE;
    
    if (KeyExpansion(ctx, key) != 0) {
        return -1;
    }
    
    if (iv && iv_size == BLOCK_SIZE) {
        memcpy(ctx->iv, iv, BLOCK_SIZE);
        ctx->iv_set = 1;
    }
    
    return 0;
}

int aes_init_with_key_string(AES_Context* ctx, AES_KeyLength key_len, const char* key_str,
                             AES_KeyType key_type, const char* iv_str, AES_KeyType iv_type) {
    uint8_t* key = NULL;
    uint8_t* iv = NULL;
    size_t key_size = 0;
    size_t iv_size = 0;
    int result;
    
    if (!ctx || !key_str) {
        return -1;
    }
    
    switch (key_type) {
        case AES_KEY_RAW:
            key_size = (size_t)key_len;
            key = (uint8_t*)malloc(key_size);
            if (!key) return -1;
            memcpy(key, key_str, key_size);
            break;
        case AES_KEY_HEX:
            key = string_to_hex(key_str, &key_size);
            if (!key) return -1;
            if (key_size != (size_t)key_len) {
                free(key);
                return -1;
            }
            break;
        case AES_KEY_BASE64:
            key = base64_decode(key_str, &key_size);
            if (!key) return -1;
            if (key_size != (size_t)key_len) {
                free(key);
                return -1;
            }
            break;
        default:
            return -1;
    }
    
    if (iv_str) {
        switch (iv_type) {
            case AES_KEY_RAW:
                iv_size = BLOCK_SIZE;
                iv = (uint8_t*)malloc(iv_size);
                if (!iv) { free(key); return -1; }
                memcpy(iv, iv_str, iv_size);
                break;
            case AES_KEY_HEX:
                iv = string_to_hex(iv_str, &iv_size);
                if (!iv) { free(key); return -1; }
                if (iv_size != BLOCK_SIZE) {
                    free(key); free(iv);
                    return -1;
                }
                break;
            case AES_KEY_BASE64:
                iv = base64_decode(iv_str, &iv_size);
                if (!iv) { free(key); return -1; }
                if (iv_size != BLOCK_SIZE) {
                    free(key); free(iv);
                    return -1;
                }
                break;
            default:
                free(key);
                return -1;
        }
    }
    
    result = aes_init(ctx, key_len, key, key_size, iv, iv_size);
    
    memset(key, 0, key_size);
    free(key);
    if (iv) {
        memset(iv, 0, iv_size);
        free(iv);
    }
    
    return result;
}

void aes_free(AES_Context* ctx) {
    int i;
    if (ctx) {
        if (ctx->dw) {
            int w_bytes = Nb * (ctx->Nr + 1) * 4;
            for (i = 0; i < w_bytes; ++i) {
                ctx->dw[i] = 0;
            }
            free(ctx->dw);
            ctx->dw = NULL;
        }
        if (ctx->w) {
            int w_bytes = Nb * (ctx->Nr + 1) * 4;
            for (i = 0; i < w_bytes; ++i) {
                ctx->w[i] = 0;
            }
            free(ctx->w);
            ctx->w = NULL;
        }
        ctx->hw_flags = AES_HW_NONE;
        memset(ctx->iv, 0, BLOCK_SIZE);
    }
}

/* ----------------------------------------------------------------------
 *  64KB 精确批量 (4096 blocks × 16 B) 公共批处理辅助
 *  - AES-NI 路径: 内联 _mm_aesenc_si128 / _mm_aesdec_si128
 *  - 软件  路径: 内联 Cipher_inline / InvCipher_inline (T-box + Imc 表)
 * -------------------------------------------------------------------- */
#define AES_BATCH_BLOCKS  4096   /* 65536 B 精确 64KB = 4096 × 16 */

/* =========================================================================
 * ARMv8 NEON AES Extension 批量处理函数
 *
 * 编译期依赖: __aarch64__ && __ARM_FEATURE_AES == 1
 * 头文件:     <arm_neon.h> (已在文件顶部 AES_HAS_ARM_AES 下包含)
 *
 * ARM NEON AES 指令语义 (与 Intel AES-NI 对照):
 *
 *   ┌──────────────────────────────────────────────────────────────────┐
 *   │ 加密路径 (使用原始轮密钥 ctx->w):                                │
 *   │   vaesdq_u8(state, rk)  ← SubBytes + ShiftRows + AddRoundKey    │
 *   │   vaesmcq_u8(state)     ← MixColumns (独立指令, 不含 AddRoundKey) │
 *   │                                                                 │
 *   │   AddRoundKey 0:   veorq_u8(state, rk[0])       ← 手动 XOR     │
 *   │   中间轮 1..Nr-1:  vaesmcq_u8(vaesdq_u8(s, rk[r]))             │
 *   │   最后一轮 Nr:     vaesdq_u8(s, rk[Nr])          ← 跳过 MixCols │
 *   │                                                                 │
 *   │ 解密路径 (使用等效解密密钥 ctx->dw):                              │
 *   │   vaeseq_u8(state, rk)  ← InvSubBytes + InvShiftRows + AddRoundKey│
 *   │   vaesimcq_u8(state)    ← InvMixColumns (独立指令)               │
 *   │                                                                 │
 *   │   AddRoundKey Nr:  veorq_u8(state, dw[Nr])       ← 先加末轮密钥 │
 *   │   中间轮 Nr-1..1:  vaesimcq_u8(vaeseq_u8(s, dw[r]))            │
 *   │   最后一轮 0:      vaeseq_u8(s, dw[0])           ← 跳过 InvMix  │
 *   └──────────────────────────────────────────────────────────────────┘
 *
 * 轮密钥布局 (ctx->w / ctx->dw 均为 uint8_t*):
 *   w[0..15]                      初始 AddRoundKey (原始密钥)
 *   w[16..31]                     第 1 轮轮密钥
 *   ...
 *   w[Nr*16 .. (Nr+1)*16 - 1]     第 Nr 轮轮密钥
 *   dw 布局同 w, 但中间轮已预做 InvMixColumns, 首尾轮与 w 相同
 *
 * AES 轮数: AES-128 Nr=10, AES-192 Nr=12, AES-256 Nr=14
 *   加密: (Nr-1) 轮完整 + 最后一轮无 MixColumns
 *   解密: (Nr-1) 轮完整 + 最后一轮无 InvMixColumns
 *
 * 加载/存储: vld1q_u8 / vst1q_u8 (NEON 支持非对齐访问, 无需对齐)
 * ========================================================================= */
#if AES_HAS_ARM_AES == 1

/* -----------------------------------------------------------------------
 * neon_batch_ecb_enc - ARM NEON 批量 ECB 模式加密
 *
 * 原理:
 *   ECB 模式每 16 字节块独立加密, 无反馈链.
 *   对于输入的 num_blocks 个明文块, 逐块完成 AES-Encrypt:
 *     state = vld1q_u8(in + i*16)
 *     state = veorq_u8(state,   rk[0])       -- 初始 AddRoundKey
 *     for r = 1..Nr-1:
 *         state = vaesdq_u8(state, rk[r])    -- Sub+Shift+AddKey
 *         state = vaesmcq_u8(state)           -- MixColumns
 *     state = vaesdq_u8(state, rk[Nr])        -- 最后一轮, 无 Mix
 *     vst1q_u8(out + i*16, state)
 *
 * 与 AES-NI 版 aesni_batch_ecb_enc 结构一一对应:
 *   _mm_xor_si128    → veorq_u8
 *   _mm_aesenc_si128 → vaesmcq_u8(vaesdq_u8(...))
 *   _mm_aesenclast   → vaesdq_u8 (直接, 无 vaesmcq_u8)
 * --------------------------------------------------------------------- */
static __attribute__((always_inline)) void
neon_batch_ecb_enc(const AES_Context *ctx,
                   const uint8_t *__restrict in,
                   uint8_t       *__restrict out,
                   size_t num_blocks)
{
    const uint8_t *rk = ctx->w;
    const int Nr = ctx->Nr;
    size_t i;
    for (i = 0; i < num_blocks; ++i) {
        uint8x16_t state = vld1q_u8(in);
        int r;
        state = veorq_u8(state, vld1q_u8(rk + 0 * 16));
        for (r = 1; r < Nr; ++r) {
            state = vaesmcq_u8(vaesdq_u8(state, vld1q_u8(rk + r * 16)));
        }
        state = vaesdq_u8(state, vld1q_u8(rk + Nr * 16));
        vst1q_u8(out, state);
        in += 16; out += 16;
    }
}

/* -----------------------------------------------------------------------
 * neon_batch_ecb_dec - ARM NEON 批量 ECB 模式解密
 *
 * 原理:
 *   使用等效解密密钥 ctx->dw (中间轮已做 InvMixColumns, 与 AES-NI 共用).
 *   AES 解密 = InvCipher(加密输出). NEON 解密路径:
 *     state = vld1q_u8(in + i*16)
 *     state = veorq_u8(state, dw[Nr])         -- 先加末轮密钥 (AES 解密起点)
 *     for r = Nr-1 .. 1:
 *         state = vaeseq_u8(state, dw[r])     -- InvSub+InvShift+AddKey
 *         state = vaesimcq_u8(state)           -- InvMixColumns
 *     state = vaeseq_u8(state, dw[0])          -- 最后一轮, 无 InvMix
 *     vst1q_u8(out + i*16, state)
 *
 * 与 AES-NI 版 aesni_batch_ecb_dec 结构一一对应:
 *   _mm_xor_si128    → veorq_u8
 *   _mm_aesdec_si128 → vaesimcq_u8(vaeseq_u8(...))
 *   _mm_aesdeclast   → vaeseq_u8 (直接, 无 vaesimcq_u8)
 * --------------------------------------------------------------------- */
static __attribute__((always_inline)) void
neon_batch_ecb_dec(const AES_Context *ctx,
                   const uint8_t *__restrict in,
                   uint8_t       *__restrict out,
                   size_t num_blocks)
{
    const uint8_t *drk = ctx->dw;
    const int Nr = ctx->Nr;
    size_t i;
    for (i = 0; i < num_blocks; ++i) {
        uint8x16_t state = vld1q_u8(in);
        int r;
        state = veorq_u8(state, vld1q_u8(drk + Nr * 16));
        for (r = Nr - 1; r >= 1; --r) {
            state = vaesimcq_u8(vaeseq_u8(state, vld1q_u8(drk + r * 16)));
        }
        state = vaeseq_u8(state, vld1q_u8(drk + 0 * 16));
        vst1q_u8(out, state);
        in += 16; out += 16;
    }
}

/* -----------------------------------------------------------------------
 * neon_batch_ctr - ARM NEON 批量 CTR 模式加密/解密 (对称, 加密解密同函数)
 *
 * 原理:
 *   CTR 是流密码模式: keystream = AES_Enc(counter_i)
 *   out = in XOR keystream
 *   因为 XOR 对称, 加密解密是同一个函数.
 *
 *   核心步骤:
 *     1. 每 16 字节块取 counter16 作为输入, 调用 NEON AES 加密得 keystream
 *     2. vld1q_u8 加载明文/密文块, veorq_u8 与 keystream XOR
 *     3. vst1q_u8 存储结果, counter16 大端递增
 *     4. 尾部不足 16 字节时, 仍生成完整 keystream, 按实际长度逐字节 XOR
 *
 *   counter 递增: 从尾字节 (index 15) 到头字节 (index 0) 逐字节 +1,
 *   遇到溢出 (0xFF→0x00) 继续进位, 与 AES-NI 版保持一致.
 * --------------------------------------------------------------------- */
static __attribute__((always_inline)) void
neon_batch_ctr(const AES_Context *ctx,
               const uint8_t *__restrict in,
               uint8_t       *__restrict out,
               size_t         len,
               uint8_t        counter16[16])
{
    const uint8_t *rk = ctx->w;
    const int Nr = ctx->Nr;
    size_t done = 0;
    while (done + 16 <= len) {
        int r;
        uint8x16_t state = vld1q_u8(counter16);
        state = veorq_u8(state, vld1q_u8(rk + 0 * 16));
        for (r = 1; r < Nr; ++r) {
            state = vaesmcq_u8(vaesdq_u8(state, vld1q_u8(rk + r * 16)));
        }
        state = vaesdq_u8(state, vld1q_u8(rk + Nr * 16));
        {
            int jj;
            for (jj = 15; jj >= 0; --jj) {
                if (++counter16[jj] != 0) break;
            }
        }
        {
            uint8x16_t pl = vld1q_u8(in + done);
            vst1q_u8(out + done, veorq_u8(pl, state));
        }
        done += 16;
    }
    if (done < len) {
        int r;
        uint8_t kbuf[16];
        uint8x16_t state = vld1q_u8(counter16);
        state = veorq_u8(state, vld1q_u8(rk + 0 * 16));
        for (r = 1; r < Nr; ++r) {
            state = vaesmcq_u8(vaesdq_u8(state, vld1q_u8(rk + r * 16)));
        }
        state = vaesdq_u8(state, vld1q_u8(rk + Nr * 16));
        {
            int jj;
            for (jj = 15; jj >= 0; --jj) {
                if (++counter16[jj] != 0) break;
            }
        }
        vst1q_u8(kbuf, state);
        for (size_t b = 0; b < len - done; ++b) {
            out[done + b] = in[done + b] ^ kbuf[b];
        }
    }
}

/* -----------------------------------------------------------------------
 * neon_batch_ofb - ARM NEON 批量 OFB 模式加密/解密 (对称, 加密解密同函数)
 *
 * 原理:
 *   OFB 也是流密码模式, 与 CTR 的区别在于 keystream 来源:
 *     O_0 = IV (初始化向量)
 *     O_i = AES_Enc(O_{i-1})          ← feedback 链
 *     C_i = P_i XOR O_i
 *
 *   所以 feedback16 在每次加密后被覆盖为当次加密的输出.
 *   核心步骤:
 *     1. 加密 feedback16 得到 keystream
 *     2. 保存 keystream 到 feedback16 (供下一块使用)
 *     3. 明文/密文块与 keystream XOR 得输出
 *     4. 尾部不足 16 字节时, 仍生成完整 keystream, 按实际长度逐字节 XOR
 *
 *   与 AES-NI 版 aesni_batch_ofb 结构完全一致.
 * --------------------------------------------------------------------- */
static __attribute__((always_inline)) void
neon_batch_ofb(const AES_Context *ctx,
               const uint8_t *__restrict in,
               uint8_t       *__restrict out,
               size_t         len,
               uint8_t        feedback16[16])
{
    const uint8_t *rk = ctx->w;
    const int Nr = ctx->Nr;
    size_t done = 0;
    while (done + 16 <= len) {
        int r;
        uint8x16_t state = vld1q_u8(feedback16);
        state = veorq_u8(state, vld1q_u8(rk + 0 * 16));
        for (r = 1; r < Nr; ++r) {
            state = vaesmcq_u8(vaesdq_u8(state, vld1q_u8(rk + r * 16)));
        }
        state = vaesdq_u8(state, vld1q_u8(rk + Nr * 16));
        vst1q_u8(feedback16, state);
        {
            uint8x16_t pl = vld1q_u8(in + done);
            vst1q_u8(out + done, veorq_u8(pl, state));
        }
        done += 16;
    }
    if (done < len) {
        int r;
        uint8_t kbuf[16];
        uint8x16_t state = vld1q_u8(feedback16);
        state = veorq_u8(state, vld1q_u8(rk + 0 * 16));
        for (r = 1; r < Nr; ++r) {
            state = vaesmcq_u8(vaesdq_u8(state, vld1q_u8(rk + r * 16)));
        }
        state = vaesdq_u8(state, vld1q_u8(rk + Nr * 16));
        vst1q_u8(feedback16, state);
        vst1q_u8(kbuf, state);
        for (size_t b = 0; b < len - done; ++b) {
            out[done + b] = in[done + b] ^ kbuf[b];
        }
    }
}

#endif /* AES_HAS_ARM_AES */

#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
/* ECB 批量加密 */
AESNI_FUNC void
aesni_batch_ecb_enc(const AES_Context *ctx,
                    const uint8_t *__restrict in,
                    uint8_t       *__restrict out,
                    size_t blocks)
{
    const __m128i *rk = (const __m128i *)(const void *)ctx->w;
    const int Nr = ctx->Nr;
    size_t i;
    for (i = 0; i < blocks; ++i) {
        __m128i s = _mm_loadu_si128((const __m128i *)in);
        int r;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        _mm_storeu_si128((__m128i *)out, s);
        in += 16; out += 16;
    }
}

/* ECB 批量解密 */
AESNI_FUNC void
aesni_batch_ecb_dec(const AES_Context *ctx,
                    const uint8_t *__restrict in,
                    uint8_t       *__restrict out,
                    size_t blocks)
{
    const __m128i *drk = (const __m128i *)(const void *)ctx->dw;
    const int Nr = ctx->Nr;
    size_t i;
    for (i = 0; i < blocks; ++i) {
        __m128i s = _mm_loadu_si128((const __m128i *)in);
        int r;
        s = _mm_xor_si128(s, _mm_loadu_si128(drk + Nr));
        for (r = Nr - 1; r >= 1; --r) s = _mm_aesdec_si128(s, _mm_loadu_si128(drk + r));
        s = _mm_aesdeclast_si128(s, _mm_loadu_si128(drk + 0));
        _mm_storeu_si128((__m128i *)out, s);
        in += 16; out += 16;
    }
}

/* CBC 批量加密: C_i = E_K(P_i ^ C_{i-1}), C_{-1} = IV */
AESNI_FUNC void
aesni_batch_cbc_enc(const AES_Context *ctx,
                    const uint8_t *__restrict in,
                    uint8_t       *__restrict out,
                    size_t blocks, uint8_t iv[16])
{
    const __m128i *rk = (const __m128i *)(const void *)ctx->w;
    const int Nr = ctx->Nr;
    __m128i prev = _mm_loadu_si128((const __m128i *)iv);
    size_t i;
    for (i = 0; i < blocks; ++i) {
        __m128i pl = _mm_loadu_si128((const __m128i *)in);
        __m128i s  = _mm_xor_si128(pl, prev);
        int r;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        _mm_storeu_si128((__m128i *)out, s);
        prev = s;
        in += 16; out += 16;
    }
    _mm_storeu_si128((__m128i *)iv, prev);
}

/* CBC 批量解密: P_i = D_K(C_i) ^ C_{i-1}, C_{-1} = IV */
AESNI_FUNC void
aesni_batch_cbc_dec(const AES_Context *ctx,
                    const uint8_t *__restrict in,
                    uint8_t       *__restrict out,
                    size_t blocks, uint8_t iv[16])
{
    const __m128i *drk = (const __m128i *)(const void *)ctx->dw;
    const int Nr = ctx->Nr;
    __m128i prev = _mm_loadu_si128((const __m128i *)iv);
    size_t i;
    for (i = 0; i < blocks; ++i) {
        __m128i cb = _mm_loadu_si128((const __m128i *)in);
        __m128i s  = cb;
        int r;
        s = _mm_xor_si128(s, _mm_loadu_si128(drk + Nr));
        for (r = Nr - 1; r >= 1; --r) s = _mm_aesdec_si128(s, _mm_loadu_si128(drk + r));
        s = _mm_aesdeclast_si128(s, _mm_loadu_si128(drk + 0));
        __m128i pl = _mm_xor_si128(s, prev);
        _mm_storeu_si128((__m128i *)out, pl);
        prev = cb;
        in += 16; out += 16;
    }
    _mm_storeu_si128((__m128i *)iv, prev);
}

/* OFB 批量: O_i = E_K(O_{i-1}), O_0 = IV; C_i = P_i ^ O_i (加解密同构) */
AESNI_FUNC void
aesni_batch_ofb(const AES_Context *ctx,
                const uint8_t *__restrict in,
                uint8_t       *__restrict out,
                size_t bytes, uint8_t feedback[16])
{
    const __m128i *rk = (const __m128i *)(const void *)ctx->w;
    const int Nr = ctx->Nr;
    __m128i fb = _mm_loadu_si128((const __m128i *)feedback);
    size_t done = 0;
    /* 整 16 字节块 */
    while (done + 16 <= bytes) {
        int r;
        __m128i s = fb;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        fb = s;
        {
            __m128i pl = _mm_loadu_si128((const __m128i *)(in + done));
            __m128i cb = _mm_xor_si128(pl, s);
            _mm_storeu_si128((__m128i *)(out + done), cb);
        }
        done += 16;
    }
    /* 尾部不足 16 字节 */
    if (done < bytes) {
        int r;
        __m128i s = fb;
        uint8_t kbuf[16];
        size_t step = bytes - done;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        fb = s;
        _mm_storeu_si128((__m128i *)kbuf, s);
        for (size_t b = 0; b < step; ++b) out[done + b] = in[done + b] ^ kbuf[b];
    }
    _mm_storeu_si128((__m128i *)feedback, fb);
}

/* CFB128 批量加密: O_i = E_K(I_{i-1}), I_0 = IV; C_i = P_i ^ O_i; I_i = C_i */
AESNI_FUNC void
aesni_batch_cfb128_enc(const AES_Context *ctx,
                       const uint8_t *__restrict in,
                       uint8_t       *__restrict out,
                       size_t bytes, uint8_t feedback[16])
{
    const __m128i *rk = (const __m128i *)(const void *)ctx->w;
    const int Nr = ctx->Nr;
    __m128i fb = _mm_loadu_si128((const __m128i *)feedback);
    size_t done = 0;
    while (done + 16 <= bytes) {
        int r;
        __m128i s = fb;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        {
            __m128i pl = _mm_loadu_si128((const __m128i *)(in + done));
            __m128i cb = _mm_xor_si128(pl, s);
            _mm_storeu_si128((__m128i *)(out + done), cb);
            fb = cb;  /* CFB128 加密 feedback = 密文块 */
        }
        done += 16;
    }
    if (done < bytes) {
        int r;
        __m128i s = fb;
        uint8_t kbuf[16];
        uint8_t cbuf[16];
        size_t step = bytes - done;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        _mm_storeu_si128((__m128i *)kbuf, s);
        /* 先 XOR 写出密文 */
        for (size_t b = 0; b < step; ++b) cbuf[b] = in[done + b] ^ kbuf[b];
        for (size_t b = 0; b < step; ++b) out[done + b] = cbuf[b];
        /* feedback 左移 step 字节，尾部填 step 字节密文 */
        memmove(feedback, feedback + step, 16 - step);
        memcpy(feedback + (16 - step), cbuf, step);
    } else {
        _mm_storeu_si128((__m128i *)feedback, fb);
    }
}

/* CFB128 批量解密: O_i = E_K(I_{i-1}), I_0 = IV; P_i = C_i ^ O_i; I_i = C_i */
AESNI_FUNC void
aesni_batch_cfb128_dec(const AES_Context *ctx,
                       const uint8_t *__restrict in,
                       uint8_t       *__restrict out,
                       size_t bytes, uint8_t feedback[16])
{
    const __m128i *rk = (const __m128i *)(const void *)ctx->w;
    const int Nr = ctx->Nr;
    __m128i fb = _mm_loadu_si128((const __m128i *)feedback);
    size_t done = 0;
    while (done + 16 <= bytes) {
        int r;
        __m128i s = fb;
        __m128i cb = _mm_loadu_si128((const __m128i *)(in + done));
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        {
            __m128i pl = _mm_xor_si128(cb, s);
            _mm_storeu_si128((__m128i *)(out + done), pl);
            fb = cb;  /* CFB128 解密 feedback = 密文块 (注意: 是原密文, 非明文) */
        }
        done += 16;
    }
    if (done < bytes) {
        int r;
        __m128i s = fb;
        uint8_t kbuf[16];
        uint8_t cbuf[16];
        size_t step = bytes - done;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        _mm_storeu_si128((__m128i *)kbuf, s);
        /* 保存尾部密文用于 feedback */
        for (size_t b = 0; b < step; ++b) cbuf[b] = in[done + b];
        for (size_t b = 0; b < step; ++b) out[done + b] = cbuf[b] ^ kbuf[b];
        /* feedback 左移 step 字节，尾部填 step 字节密文 */
        memmove(feedback, feedback + step, 16 - step);
        memcpy(feedback + (16 - step), cbuf, step);
    } else {
        _mm_storeu_si128((__m128i *)feedback, fb);
    }
}

/* CTR 批量: KS_i = E_K(IV + i); C_i = P_i ^ KS_i (加解密同构); counter 按大端尾字节自增 */
AESNI_FUNC void
aesni_batch_ctr(const AES_Context *ctx,
                const uint8_t *__restrict in,
                uint8_t       *__restrict out,
                size_t bytes, uint8_t counter[16])
{
    const __m128i *rk = (const __m128i *)(const void *)ctx->w;
    const int Nr = ctx->Nr;
    size_t done = 0;
    while (done + 16 <= bytes) {
        int r;
        __m128i ctr = _mm_loadu_si128((const __m128i *)counter);
        __m128i s = ctr;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        /* counter++ (从尾字节到首字节，与软件路径一致) */
        {
            int jj;
            for (jj = 15; jj >= 0; --jj) {
                if (++counter[jj] != 0) break;
            }
        }
        {
            __m128i pl = _mm_loadu_si128((const __m128i *)(in + done));
            __m128i cb = _mm_xor_si128(pl, s);
            _mm_storeu_si128((__m128i *)(out + done), cb);
        }
        done += 16;
    }
    if (done < bytes) {
        int r;
        __m128i ctr = _mm_loadu_si128((const __m128i *)counter);
        __m128i s = ctr;
        uint8_t kbuf[16];
        size_t step = bytes - done;
        s = _mm_xor_si128(s, _mm_loadu_si128(rk + 0));
        for (r = 1; r < Nr; ++r) s = _mm_aesenc_si128(s, _mm_loadu_si128(rk + r));
        s = _mm_aesenclast_si128(s, _mm_loadu_si128(rk + Nr));
        /* counter++ */
        {
            int jj;
            for (jj = 15; jj >= 0; --jj) {
                if (++counter[jj] != 0) break;
            }
        }
        _mm_storeu_si128((__m128i *)kbuf, s);
        for (size_t b = 0; b < step; ++b) out[done + b] = in[done + b] ^ kbuf[b];
    }
}
#endif /* AES_HAS_WMMINTRIN */

/* 公共循环: 按 64KB 切分，每次 AES_BATCH_BLOCKS 块 */
#define FOREACH_BATCH_BLOCKS(total, var, chunk)  \
    for ((var) = (total); (var) > 0; (var) -= (chunk)) {  \
        size_t cur = ((var) >= (chunk)) ? (chunk) : (var);  \
        /* use `cur` here as batch size */

static uint8_t* ecb_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            AES_Padding padding, size_t* out_size) {
    size_t padded_size;
    uint8_t* padded;
    size_t num_blocks;
    uint8_t* ciphertext;
    
    padded = pad(plaintext, plaintext_size, padding, &padded_size);
    if (!padded) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = padded_size / BLOCK_SIZE;
    ciphertext = (uint8_t*)malloc(padded_size);
    if (!ciphertext) {
        free(padded);
        *out_size = 0;
        return NULL;
    }

    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = padded;
        uint8_t       *op = ciphertext;
        size_t remaining = num_blocks;
        while (remaining > 0) {
            size_t cur = (remaining > AES_BATCH_BLOCKS) ? AES_BATCH_BLOCKS : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                aesni_batch_ecb_enc(ctx, ip, op, cur);
            } else
#endif
#if AES_HAS_ARM_AES == 1
            if (ctx->hw_flags & AES_HW_NEON) {
                neon_batch_ecb_enc(ctx, ip, op, cur);
            } else
#endif
            {
                size_t k = 0;
                if (ctx->Nr == 14) {
                    /* AES-256: 完全展开 2 块并行 + 单块展开尾 */
                    while (k + 2 <= cur) {
                        Cipher_inline_aes256_x2(ctx->w,
                                         ip + (k+0)*16, ip + (k+1)*16,
                                         op + (k+0)*16, op + (k+1)*16);
                        if (k + 4 <= cur) {
                            __builtin_prefetch(ip + (k+4)*16, 0, 1);
                        }
                        k += 2;
                    }
                    for (; k < cur; ++k) {
                        Cipher_inline_aes256(ctx->w, ip + k*16, op + k*16);
                    }
                } else if (ctx->Nr == 10) {
                    /* AES-128: 4 块并行 + 2 块 + 单块展开尾 */
                    while (k + 4 <= cur) {
                        Cipher_inline_x4(ctx->w, ctx->Nr,
                                         ip + (k+0)*16, ip + (k+1)*16,
                                         ip + (k+2)*16, ip + (k+3)*16,
                                         op + (k+0)*16, op + (k+1)*16,
                                         op + (k+2)*16, op + (k+3)*16);
                        if (k + 8 <= cur) {
                            __builtin_prefetch(ip + (k+8)*16, 0, 1);
                        }
                        k += 4;
                    }
                    while (k + 2 <= cur) {
                        Cipher_inline_x2(ctx->w, ctx->Nr,
                                         ip + (k+0)*16, ip + (k+1)*16,
                                         op + (k+0)*16, op + (k+1)*16);
                        k += 2;
                    }
                    for (; k < cur; ++k) {
                        Cipher_inline_aes128(ctx->w, ip + k*16, op + k*16);
                    }
                } else {
                    /* AES-192: 4 块 + 2 块 + 单块 */
                    while (k + 4 <= cur) {
                        Cipher_inline_x4(ctx->w, ctx->Nr,
                                         ip + (k+0)*16, ip + (k+1)*16,
                                         ip + (k+2)*16, ip + (k+3)*16,
                                         op + (k+0)*16, op + (k+1)*16,
                                         op + (k+2)*16, op + (k+3)*16);
                        if (k + 8 <= cur) {
                            __builtin_prefetch(ip + (k+8)*16, 0, 1);
                        }
                        k += 4;
                    }
                    while (k + 2 <= cur) {
                        Cipher_inline_x2(ctx->w, ctx->Nr,
                                         ip + (k+0)*16, ip + (k+1)*16,
                                         op + (k+0)*16, op + (k+1)*16);
                        k += 2;
                    }
                    for (; k < cur; ++k) {
                        Cipher_inline(ctx->w, ctx->Nr, ip + k*16, op + k*16);
                    }
                }
            }
            ip += cur * 16; op += cur * 16; remaining -= cur;
        }
    }
    
    free(padded);
    *out_size = padded_size;
    return ciphertext;
}

static uint8_t* ecb_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                            AES_Padding padding, size_t* out_size) {
    size_t num_blocks;
    uint8_t* plaintext;
    uint8_t* result;
    
    if (ciphertext_size % BLOCK_SIZE != 0) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = ciphertext_size / BLOCK_SIZE;
    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        *out_size = 0;
        return NULL;
    }

    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = ciphertext;
        uint8_t       *op = plaintext;
        size_t remaining = num_blocks;
        while (remaining > 0) {
            size_t cur = (remaining > AES_BATCH_BLOCKS) ? AES_BATCH_BLOCKS : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                aesni_batch_ecb_dec(ctx, ip, op, cur);
            } else
#endif
#if AES_HAS_ARM_AES == 1
            if (ctx->hw_flags & AES_HW_NEON) {
                neon_batch_ecb_dec(ctx, ip, op, cur);
            } else
#endif
            {
                size_t k = 0;
                if (ctx->Nr == 14) {
                    /* AES-256: 完全展开 2 块并行 InvCipher + 单块展开尾 */
                    while (k + 2 <= cur) {
                        InvCipher_inline_aes256_x2(ctx->dw,
                                            ip + (k+0)*16, ip + (k+1)*16,
                                            op + (k+0)*16, op + (k+1)*16);
                        if (k + 4 <= cur) {
                            __builtin_prefetch(ip + (k+4)*16, 0, 1);
                        }
                        k += 2;
                    }
                    for (; k < cur; ++k) {
                        InvCipher_inline_aes256(ctx->dw, ip + k*16, op + k*16);
                    }
                } else if (ctx->Nr == 10) {
                    /* AES-128: 4 块 + 2 块 + 单块 */
                    while (k + 4 <= cur) {
                        InvCipher_inline_x4(ctx->dw, ctx->Nr,
                                            ip + (k+0)*16, ip + (k+1)*16,
                                            ip + (k+2)*16, ip + (k+3)*16,
                                            op + (k+0)*16, op + (k+1)*16,
                                            op + (k+2)*16, op + (k+3)*16);
                        if (k + 8 <= cur) {
                            __builtin_prefetch(ip + (k+8)*16, 0, 1);
                        }
                        k += 4;
                    }
                    while (k + 2 <= cur) {
                        InvCipher_inline_x2(ctx->dw, ctx->Nr,
                                            ip + (k+0)*16, ip + (k+1)*16,
                                            op + (k+0)*16, op + (k+1)*16);
                        k += 2;
                    }
                    for (; k < cur; ++k) {
                        InvCipher_inline_aes128(ctx->dw, ip + k*16, op + k*16);
                    }
                } else {
                    /* AES-192: 4 块 + 2 块 + 单块 */
                    while (k + 4 <= cur) {
                        InvCipher_inline_x4(ctx->dw, ctx->Nr,
                                            ip + (k+0)*16, ip + (k+1)*16,
                                            ip + (k+2)*16, ip + (k+3)*16,
                                            op + (k+0)*16, op + (k+1)*16,
                                            op + (k+2)*16, op + (k+3)*16);
                        if (k + 8 <= cur) {
                            __builtin_prefetch(ip + (k+8)*16, 0, 1);
                        }
                        k += 4;
                    }
                    while (k + 2 <= cur) {
                        InvCipher_inline_x2(ctx->dw, ctx->Nr,
                                            ip + (k+0)*16, ip + (k+1)*16,
                                            op + (k+0)*16, op + (k+1)*16);
                        k += 2;
                    }
                    for (; k < cur; ++k) {
                        InvCipher_inline(ctx->dw, ctx->Nr, ip + k*16, op + k*16);
                    }
                }
            }
            ip += cur * 16; op += cur * 16; remaining -= cur;
        }
    }
    
    result = unpad(plaintext, ciphertext_size, padding, out_size);
    free(plaintext);
    return result;
}

static uint8_t* cbc_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            const uint8_t* iv, AES_Padding padding, size_t* out_size) {
    size_t padded_size;
    uint8_t* padded;
    size_t num_blocks;
    uint8_t* ciphertext;
    uint8_t prev_block[BLOCK_SIZE];
    
    padded = pad(plaintext, plaintext_size, padding, &padded_size);
    if (!padded) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = padded_size / BLOCK_SIZE;
    ciphertext = (uint8_t*)malloc(padded_size);
    if (!ciphertext) {
        free(padded);
        *out_size = 0;
        return NULL;
    }
    memcpy(prev_block, iv, BLOCK_SIZE);

    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = padded;
        uint8_t       *op = ciphertext;
        size_t remaining = num_blocks;
        while (remaining > 0) {
            size_t cur = (remaining > AES_BATCH_BLOCKS) ? AES_BATCH_BLOCKS : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                aesni_batch_cbc_enc(ctx, ip, op, cur, prev_block);
            } else
#endif
            {
                size_t k;
                if (ctx->Nr == 14) {
                    /* AES-256 完全展开 CBC 加密 */
                    for (k = 0; k < cur; ++k) {
                        const u8 *in_blk = ip + k*16;
                        u8       *ou_blk = op + k*16;
                        Cipher_inline_cbc_enc_aes256(ctx->w,
                                                     in_blk, prev_block,
                                                     ou_blk, prev_block);
                        if (k + 1 < cur) {
                            __builtin_prefetch(ip + (k+1)*16, 0, 1);
                        }
                    }
                } else if (ctx->Nr == 10) {
                    /* AES-128 完全展开 CBC 加密 */
                    for (k = 0; k < cur; ++k) {
                        const u8 *in_blk = ip + k*16;
                        u8       *ou_blk = op + k*16;
                        Cipher_inline_cbc_enc_aes128(ctx->w,
                                                     in_blk, prev_block,
                                                     ou_blk, prev_block);
                        if (k + 1 < cur) {
                            __builtin_prefetch(ip + (k+1)*16, 0, 1);
                        }
                    }
                } else {
                    for (k = 0; k < cur; ++k) {
                        const u8 *in_blk = ip + k*16;
                        u8       *ou_blk = op + k*16;
                        Cipher_inline_cbc_enc(ctx->w, ctx->Nr,
                                              in_blk, prev_block,
                                              ou_blk, prev_block);
                        if (k + 1 < cur) {
                            __builtin_prefetch(ip + (k+1)*16, 0, 1);
                        }
                    }
                }
            }
            ip += cur * 16; op += cur * 16; remaining -= cur;
        }
    }
    
    free(padded);
    *out_size = padded_size;
    return ciphertext;
}

static uint8_t* cbc_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                            const uint8_t* iv, AES_Padding padding, size_t* out_size) {
    size_t num_blocks;
    uint8_t* plaintext;
    uint8_t prev_block[BLOCK_SIZE];
    uint8_t* result;
    
    if (ciphertext_size % BLOCK_SIZE != 0) {
        *out_size = 0;
        return NULL;
    }
    
    num_blocks = ciphertext_size / BLOCK_SIZE;
    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(prev_block, iv, BLOCK_SIZE);

    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = ciphertext;
        uint8_t       *op = plaintext;
        const u8 *sw_prev = iv;   /* 软件路径: 直接用指针跟踪 prev, 无 memcpy */
        size_t remaining = num_blocks;
        while (remaining > 0) {
            size_t cur = (remaining > AES_BATCH_BLOCKS) ? AES_BATCH_BLOCKS : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                /* AES-NI 路径需要可写缓冲: 同步 prev_block 与 sw_prev */
                if (sw_prev != prev_block) {
                    memcpy(prev_block, sw_prev, 16);
                    sw_prev = prev_block;
                }
                aesni_batch_cbc_dec(ctx, ip, op, cur, prev_block);
                sw_prev = ip + (cur - 1) * 16;
            } else
#endif
            {
                size_t k;
                if (ctx->Nr == 14) {
                    /* AES-256 完全展开 CBC 解密 + 指针跟踪 prev (零 memcpy) */
                    for (k = 0; k < cur; ++k) {
                        const u8 *cb = ip + k*16;
                        u8       *ob = op + k*16;
                        InvCipher_inline_cbc_dec_aes256(ctx->dw,
                                                         cb, sw_prev, ob);
                        sw_prev = cb;
                        if (k + 1 < cur) {
                            __builtin_prefetch(ip + (k+1)*16, 0, 1);
                        }
                    }
                } else if (ctx->Nr == 10) {
                    /* AES-128 完全展开 CBC 解密 */
                    for (k = 0; k < cur; ++k) {
                        const u8 *cb = ip + k*16;
                        u8       *ob = op + k*16;
                        InvCipher_inline_cbc_dec_aes128(ctx->dw,
                                                         cb, sw_prev, ob);
                        sw_prev = cb;
                        if (k + 1 < cur) {
                            __builtin_prefetch(ip + (k+1)*16, 0, 1);
                        }
                    }
                } else {
                    for (k = 0; k < cur; ++k) {
                        const u8 *cb = ip + k*16;
                        u8       *ob = op + k*16;
                        InvCipher_inline_cbc_dec(ctx->dw, ctx->Nr,
                                                  cb, sw_prev, ob);
                        sw_prev = cb;
                        if (k + 1 < cur) {
                            __builtin_prefetch(ip + (k+1)*16, 0, 1);
                        }
                    }
                }
            }
            ip += cur * 16; op += cur * 16; remaining -= cur;
        }
    }
    
    result = unpad(plaintext, ciphertext_size, padding, out_size);
    free(plaintext);
    return result;
}

static uint8_t* cfb8_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                             const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t  fb[16];
    size_t i;

    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) { *out_size = 0; return NULL; }
    if (!aes_tables_ready) aes_init_tables();
    memcpy(fb, iv, 16);

#define FB_SHIFT_1(new_last) do { \
        fb[ 0] = fb[ 1]; fb[ 1] = fb[ 2]; fb[ 2] = fb[ 3]; fb[ 3] = fb[ 4]; \
        fb[ 4] = fb[ 5]; fb[ 5] = fb[ 6]; fb[ 6] = fb[ 7]; fb[ 7] = fb[ 8]; \
        fb[ 8] = fb[ 9]; fb[ 9] = fb[10]; fb[10] = fb[11]; fb[11] = fb[12]; \
        fb[12] = fb[13]; fb[13] = fb[14]; fb[14] = fb[15]; fb[15] = (new_last); \
    } while(0)

    for (i = 0; i + 3 < plaintext_size; i += 4) {
        uint8_t enc[16];
        /* byte 0 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        uint8_t c0 = plaintext[i+0] ^ enc[0];
        ciphertext[i+0] = c0;
        FB_SHIFT_1(c0);
        /* byte 1 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        uint8_t c1 = plaintext[i+1] ^ enc[0];
        ciphertext[i+1] = c1;
        FB_SHIFT_1(c1);
        /* byte 2 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        uint8_t c2 = plaintext[i+2] ^ enc[0];
        ciphertext[i+2] = c2;
        FB_SHIFT_1(c2);
        /* byte 3 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        uint8_t c3 = plaintext[i+3] ^ enc[0];
        ciphertext[i+3] = c3;
        FB_SHIFT_1(c3);
    }
    while (i < plaintext_size) {
        uint8_t enc[16];
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        uint8_t c = plaintext[i] ^ enc[0];
        ciphertext[i] = c;
        FB_SHIFT_1(c);
        ++i;
    }
#undef FB_SHIFT_1
    *out_size = plaintext_size;
    return ciphertext;
}

static uint8_t* cfb8_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                             const uint8_t* iv, size_t* out_size) {
    uint8_t* plaintext;
    uint8_t  fb[16];
    size_t i;

    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) { *out_size = 0; return NULL; }
    if (!aes_tables_ready) aes_init_tables();
    memcpy(fb, iv, 16);

#define FB_SHIFT_1(new_last) do { \
        fb[ 0] = fb[ 1]; fb[ 1] = fb[ 2]; fb[ 2] = fb[ 3]; fb[ 3] = fb[ 4]; \
        fb[ 4] = fb[ 5]; fb[ 5] = fb[ 6]; fb[ 6] = fb[ 7]; fb[ 7] = fb[ 8]; \
        fb[ 8] = fb[ 9]; fb[ 9] = fb[10]; fb[10] = fb[11]; fb[11] = fb[12]; \
        fb[12] = fb[13]; fb[13] = fb[14]; fb[14] = fb[15]; fb[15] = (new_last); \
    } while(0)

    for (i = 0; i + 3 < ciphertext_size; i += 4) {
        uint8_t enc[16];
        uint8_t c;
        /* byte 0 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        c = ciphertext[i+0];
        plaintext[i+0] = c ^ enc[0];
        FB_SHIFT_1(c);
        /* byte 1 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        c = ciphertext[i+1];
        plaintext[i+1] = c ^ enc[0];
        FB_SHIFT_1(c);
        /* byte 2 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        c = ciphertext[i+2];
        plaintext[i+2] = c ^ enc[0];
        FB_SHIFT_1(c);
        /* byte 3 */
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        c = ciphertext[i+3];
        plaintext[i+3] = c ^ enc[0];
        FB_SHIFT_1(c);
    }
    while (i < ciphertext_size) {
        uint8_t enc[16];
        Cipher_inline(ctx->w, ctx->Nr, fb, enc);
        uint8_t c = ciphertext[i];
        plaintext[i] = c ^ enc[0];
        FB_SHIFT_1(c);
        ++i;
    }
#undef FB_SHIFT_1
    *out_size = ciphertext_size;
    return plaintext;
}

static uint8_t* cfb128_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                               const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t feedback[BLOCK_SIZE];
    
    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = plaintext;
        uint8_t       *op = ciphertext;
        size_t remaining = plaintext_size;
        while (remaining > 0) {
            size_t chunk_bytes = (remaining > (size_t)AES_BATCH_BLOCKS * 16)
                                        ? (size_t)AES_BATCH_BLOCKS * 16 : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                aesni_batch_cfb128_enc(ctx, ip, op, chunk_bytes, feedback);
            } else
#endif
            {
                size_t done = 0;
                while (done < chunk_bytes) {
                    uint8_t encrypted[BLOCK_SIZE];
                    Cipher_auto(ctx, feedback, encrypted);
                    if (done + BLOCK_SIZE <= chunk_bytes) {
                        /* 32 位 XOR 加速 */
                        u32 *o4 = (u32*)(op + done);
                        const u32 *i4 = (const u32*)(ip + done);
                        const u32 *e4 = (const u32*)encrypted;
                        o4[0] = i4[0] ^ e4[0];
                        o4[1] = i4[1] ^ e4[1];
                        o4[2] = i4[2] ^ e4[2];
                        o4[3] = i4[3] ^ e4[3];
                        memcpy(feedback, op + done, BLOCK_SIZE);
                        done += BLOCK_SIZE;
                    } else {
                        size_t j;
                        size_t step = chunk_bytes - done;
                        for (j = 0; j < step; ++j) {
                            op[done + j] = ip[done + j] ^ encrypted[j];
                        }
                        memmove(feedback, feedback + step, BLOCK_SIZE - step);
                        memcpy(feedback + (BLOCK_SIZE - step), op + done, step);
                        done += step;
                    }
                }
            }
            ip += chunk_bytes; op += chunk_bytes; remaining -= chunk_bytes;
        }
    }
    
    *out_size = plaintext_size;
    return ciphertext;
}

static uint8_t* cfb128_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                               const uint8_t* iv, size_t* out_size) {
    uint8_t* plaintext;
    uint8_t feedback[BLOCK_SIZE];
    
    plaintext = (uint8_t*)malloc(ciphertext_size);
    if (!plaintext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = ciphertext;
        uint8_t       *op = plaintext;
        size_t remaining = ciphertext_size;
        while (remaining > 0) {
            size_t chunk_bytes = (remaining > (size_t)AES_BATCH_BLOCKS * 16)
                                        ? (size_t)AES_BATCH_BLOCKS * 16 : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                aesni_batch_cfb128_dec(ctx, ip, op, chunk_bytes, feedback);
            } else
#endif
            {
                size_t done = 0;
                while (done < chunk_bytes) {
                    uint8_t encrypted[BLOCK_SIZE];
                    Cipher_auto(ctx, feedback, encrypted);
                    if (done + BLOCK_SIZE <= chunk_bytes) {
                        /* CFB128 解密: feedback = 密文块 (ip), 输出 = 密文 XOR AES(feedback) */
                        u32 *o4 = (u32*)(op + done);
                        const u32 *c4 = (const u32*)(ip + done);
                        const u32 *e4 = (const u32*)encrypted;
                        o4[0] = c4[0] ^ e4[0];
                        o4[1] = c4[1] ^ e4[1];
                        o4[2] = c4[2] ^ e4[2];
                        o4[3] = c4[3] ^ e4[3];
                        /* feedback 更新为当前密文块 (注意: 须在 XOR 后, 但 XOR 不改 ip) */
                        memcpy(feedback, ip + done, BLOCK_SIZE);
                        done += BLOCK_SIZE;
                    } else {
                        size_t j;
                        size_t step = chunk_bytes - done;
                        uint8_t temp[BLOCK_SIZE];
                        memcpy(temp, ip + done, step);
                        for (j = 0; j < step; ++j) {
                            op[done + j] = temp[j] ^ encrypted[j];
                        }
                        memmove(feedback, feedback + step, BLOCK_SIZE - step);
                        memcpy(feedback + (BLOCK_SIZE - step), temp, step);
                        done += step;
                    }
                }
            }
            ip += chunk_bytes; op += chunk_bytes; remaining -= chunk_bytes;
        }
    }
    
    *out_size = ciphertext_size;
    return plaintext;
}

static uint8_t* ofb_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t feedback[BLOCK_SIZE];

    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(feedback, iv, BLOCK_SIZE);
    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = plaintext;
        uint8_t       *op = ciphertext;
        size_t remaining = plaintext_size;
        while (remaining > 0) {
            /* 每批最多处理 64KB (AES_BATCH_BLOCKS * 16 字节) */
            size_t chunk_bytes = (remaining > (size_t)AES_BATCH_BLOCKS * 16)
                                        ? (size_t)AES_BATCH_BLOCKS * 16 : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                aesni_batch_ofb(ctx, ip, op, chunk_bytes, feedback);
            } else
#endif
#if AES_HAS_ARM_AES == 1
            if (ctx->hw_flags & AES_HW_NEON) {
                neon_batch_ofb(ctx, ip, op, chunk_bytes, feedback);
            } else
#endif
            {
                /* 16 字节块处理: 每块加密 feedback 得到 keystream, XOR 明文。
                 * 消除逐字节循环与 % 16 取模的开销。 */
                size_t done = 0;
                uint8_t stream[BLOCK_SIZE];
                while (done + BLOCK_SIZE <= chunk_bytes) {
                    Cipher_auto(ctx, feedback, stream);
                    /* feedback = stream (OFB 反馈) */
                    memcpy(feedback, stream, BLOCK_SIZE);
                    /* XOR 16 字节 */
                    u32 *o4 = (u32*)(op + done);
                    const u32 *i4 = (const u32*)(ip + done);
                    const u32 *s4 = (const u32*)stream;
                    o4[0] = i4[0] ^ s4[0];
                    o4[1] = i4[1] ^ s4[1];
                    o4[2] = i4[2] ^ s4[2];
                    o4[3] = i4[3] ^ s4[3];
                    done += BLOCK_SIZE;
                }
                /* 尾部不足 16 字节 */
                if (done < chunk_bytes) {
                    Cipher_auto(ctx, feedback, stream);
                    size_t rem = chunk_bytes - done;
                    size_t j;
                    for (j = 0; j < rem; ++j) {
                        op[done + j] = ip[done + j] ^ stream[j];
                    }
                }
            }
            ip += chunk_bytes; op += chunk_bytes; remaining -= chunk_bytes;
        }
    }

    *out_size = plaintext_size;
    return ciphertext;
}

static uint8_t* ctr_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                            const uint8_t* iv, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t counter[BLOCK_SIZE];

    ciphertext = (uint8_t*)malloc(plaintext_size);
    if (!ciphertext) {
        *out_size = 0;
        return NULL;
    }
    memcpy(counter, iv, BLOCK_SIZE);
    if (!aes_tables_ready) aes_init_tables();

    {
        const uint8_t *ip = plaintext;
        uint8_t       *op = ciphertext;
        size_t remaining = plaintext_size;
        while (remaining > 0) {
            size_t chunk_bytes = (remaining > (size_t)AES_BATCH_BLOCKS * 16)
                                        ? (size_t)AES_BATCH_BLOCKS * 16 : remaining;
#if defined(AES_HAS_WMMINTRIN) && AES_HAS_WMMINTRIN == 1
            if ((ctx->hw_flags & AES_HW_NI) && ctx->dw) {
                aesni_batch_ctr(ctx, ip, op, chunk_bytes, counter);
            } else
#endif
#if AES_HAS_ARM_AES == 1
            if (ctx->hw_flags & AES_HW_NEON) {
                neon_batch_ctr(ctx, ip, op, chunk_bytes, counter);
            } else
#endif
            {
                /* CTR: 批量生成 4 个 keystream block + 批量 XOR + 32 位快速 counter 递增 */
                size_t done = 0;
                uint8_t stream0[16], stream1[16], stream2[16], stream3[16];

                while (done + 64 <= chunk_bytes) {
                    /* 4 个连续 counter 值的 keystream (小端 x86, counter 存大端) */
                    Cipher_auto(ctx, counter, stream0);
                    /* counter += 1, 用 32 位递增 */
                    {
                        u32 *c32 = (u32*)(void*)counter;
                        c32[3]++;
                        if (c32[3] == 0) {
                            c32[2]++;
                            if (c32[2] == 0) { c32[1]++; if (c32[1] == 0) c32[0]++; }
                        }
                    }
                    Cipher_auto(ctx, counter, stream1);
                    {
                        u32 *c32 = (u32*)(void*)counter;
                        c32[3]++;
                        if (c32[3] == 0) {
                            c32[2]++;
                            if (c32[2] == 0) { c32[1]++; if (c32[1] == 0) c32[0]++; }
                        }
                    }
                    Cipher_auto(ctx, counter, stream2);
                    {
                        u32 *c32 = (u32*)(void*)counter;
                        c32[3]++;
                        if (c32[3] == 0) {
                            c32[2]++;
                            if (c32[2] == 0) { c32[1]++; if (c32[1] == 0) c32[0]++; }
                        }
                    }
                    Cipher_auto(ctx, counter, stream3);
                    {
                        u32 *c32 = (u32*)(void*)counter;
                        c32[3]++;
                        if (c32[3] == 0) {
                            c32[2]++;
                            if (c32[2] == 0) { c32[1]++; if (c32[1] == 0) c32[0]++; }
                        }
                    }
                    /* 批量 XOR 4 块 = 64 字节 */
                    u32 *o0 = (u32*)(op + done);
                    const u32 *i0 = (const u32*)(ip + done);
                    const u32 *s0 = (const u32*)stream0;
                    o0[0]=i0[0]^s0[0]; o0[1]=i0[1]^s0[1]; o0[2]=i0[2]^s0[2]; o0[3]=i0[3]^s0[3];
                    u32 *o1 = (u32*)(op + done + 16);
                    const u32 *i1 = (const u32*)(ip + done + 16);
                    const u32 *s1 = (const u32*)stream1;
                    o1[0]=i1[0]^s1[0]; o1[1]=i1[1]^s1[1]; o1[2]=i1[2]^s1[2]; o1[3]=i1[3]^s1[3];
                    u32 *o2 = (u32*)(op + done + 32);
                    const u32 *i2 = (const u32*)(ip + done + 32);
                    const u32 *s2 = (const u32*)stream2;
                    o2[0]=i2[0]^s2[0]; o2[1]=i2[1]^s2[1]; o2[2]=i2[2]^s2[2]; o2[3]=i2[3]^s2[3];
                    u32 *o3 = (u32*)(op + done + 48);
                    const u32 *i3 = (const u32*)(ip + done + 48);
                    const u32 *s3 = (const u32*)stream3;
                    o3[0]=i3[0]^s3[0]; o3[1]=i3[1]^s3[1]; o3[2]=i3[2]^s3[2]; o3[3]=i3[3]^s3[3];
                    done += 64;
                }
                /* 尾部 16~48 字节 */
                uint8_t stream_tail[16];
                while (done + BLOCK_SIZE <= chunk_bytes) {
                    Cipher_auto(ctx, counter, stream_tail);
                    u32 *o4 = (u32*)(op + done);
                    const u32 *i4 = (const u32*)(ip + done);
                    const u32 *s4 = (const u32*)stream_tail;
                    o4[0]=i4[0]^s4[0]; o4[1]=i4[1]^s4[1]; o4[2]=i4[2]^s4[2]; o4[3]=i4[3]^s4[3];
                    done += BLOCK_SIZE;
                    u32 *c32 = (u32*)(void*)counter;
                    c32[3]++;
                    if (c32[3] == 0) { c32[2]++; if (c32[2] == 0) { c32[1]++; if (c32[1] == 0) c32[0]++; } }
                }
                if (done < chunk_bytes) {
                    Cipher_auto(ctx, counter, stream_tail);
                    size_t rem = chunk_bytes - done;
                    for (size_t j = 0; j < rem; ++j) {
                        op[done + j] = ip[done + j] ^ stream_tail[j];
                    }
                }
            }
            ip += chunk_bytes; op += chunk_bytes; remaining -= chunk_bytes;
        }
    }

    *out_size = plaintext_size;
    return ciphertext;
}

/* GHASH 在 GF(2^128) 上的乘法 (常时实现)。
 *
 * 侧信道考虑: H = AES_K(0) 是密钥派生值, X 含密文; 两者均为敏感数据。
 * 旧实现按字节扫描 H 的每一位, 用 `if ((h[i]>>j)&1)` 和 `if (lsb)` 早分支
 * 选择是否异或 V, 这会让攻击者通过 cache/timing 推断 H 的位。
 *
 * 本实现:
 *   1. 用 64 位整数承载 X/H/V/Z 的高/低半 (big-endian, v0=高位对应 V[0..63]);
 *   2. 用 mask = -(uint64_t)(bit) 替代 `if (bit) z ^= v`, 保证无论 bit=0/1
 *      都执行相同的 XOR 指令 (无数据依赖分支);
 *   3. GHASH 规范 (NIST SP 800-38D): 按 X[0],X[1],...,X[127] 顺序处理
 *      (X[0] 是最高有效位 = v0 的 bit63), V>>1 是 128 位整数无符号右移;
 *   4. V>>1 跨 64 位边界: v0 的最低位 (V[63]) 移入 v1 的最高位;
 *      当 V[127]=1 (v1 最低位) 时, V>>1 后异或 R=0xE1<<120, 即 v0 异或 0xE100000000000000。
 *      R 的条件异或同样用 mask 实现, 无分支。
 *
 * 性能: 128 次循环每次几条 ALU 指令, 远快于字节级实现 (原 7.7 MB/s)。
 *
 * 8-bit M-table 加速 (Shoup 算法): 预计算 16×256×16=64KB 查表,
 * M[i][b] = (字节 b 放在大端第 i 位置) · H。gcm_mult 在表就绪时
 * 用 16 次查表 + 16 次 32 位 XOR 代替 128 次位循环, 理论 ~8× 加速。
 */
static uint8_t gcm_M[16][256][16];   /* 8-bit M-table (64KB) */
static uint8_t gcm_M_h[16];           /* 当前表对应的 H */
static int     gcm_M_ready = 0;       /* 表是否就绪 */
static int     gcm_in_init = 0;       /* 预计算进行中标志 (防止递归) */

static void gcm_mult(uint8_t* x, const uint8_t* h);  /* 前向声明 */

/* 预计算 8-bit M-table: 对每个字节位置 i (0..15) 和字节值 b (0..255),
 * 计算 M[i][b] = (b << (8*(15-i))) · H (GF(2^128), big-endian)。
 * 预计算成本: 4096 次位串行乘法, 对大数据可忽略。 */
static void gcm_init_table(const uint8_t h[16]) {
    /* H 未变则跳过 */
    if (gcm_M_ready && memcmp(gcm_M_h, h, 16) == 0) return;

    gcm_in_init = 1;   /* 期间 gcm_mult 走位串行路径 */
    {
        int i, b;
        for (i = 0; i < 16; ++i) {
            for (b = 0; b < 256; ++b) {
                uint8_t tmp[16];
                memset(tmp, 0, 16);
                tmp[i] = (uint8_t)b;
                memcpy(gcm_M[i][b], tmp, 16);
                gcm_mult(gcm_M[i][b], h);   /* M[i][b] = tmp · H */
            }
        }
    }
    gcm_in_init = 0;
    memcpy(gcm_M_h, h, 16);
    gcm_M_ready = 1;
}

static void gcm_mult(uint8_t* x, const uint8_t* h) {
    /* M-table 就绪且 H 匹配时走 8-bit 查表快速路径 */
    if (!gcm_in_init && gcm_M_ready && memcmp(gcm_M_h, h, 16) == 0) {
        uint8_t z[16];
        u32 *z4 = (u32*)z;
        const u32 *m;
        int i;
        /* z = M[0][x[0]] */
        memcpy(z, gcm_M[0][x[0]], 16);
        /* z ^= M[i][x[i]] for i=1..15 (32 位 XOR) */
        for (i = 1; i < 16; ++i) {
            m = (const u32*)gcm_M[i][x[i]];
            z4[0] ^= m[0];
            z4[1] ^= m[1];
            z4[2] ^= m[2];
            z4[3] ^= m[3];
        }
        memcpy(x, z, 16);
        return;
    }

    /* 位串行 fallback (首次调用 / H 未匹配 / 预计算期间) */
    {
    /* 按 big-endian 读入 X 和 H 的两个 64 位半 */
    uint64_t x0 = 0, x1 = 0, h0 = 0, h1 = 0;
    int i;
    for (i = 0; i < 8; ++i) {
        x0 = (x0 << 8) | x[i];
        h0 = (h0 << 8) | h[i];
        x1 = (x1 << 8) | x[i + 8];
        h1 = (h1 << 8) | h[i + 8];
    }

    /* V = H, Z = 0; v0/v1 持续右移, z0/z1 累积结果 */
    uint64_t v0 = h0, v1 = h1;
    uint64_t z0 = 0,  z1 = 0;

    /* 处理 X 的高半 X[0..63] (v0 的 bit63..bit0) */
    for (i = 63; i >= 0; --i) {
        uint64_t mask = -(uint64_t)((x0 >> i) & 1ull);
        z0 ^= (mask & v0);
        z1 ^= (mask & v1);

        /* V >>= 1 (128 位无符号右移, 跨 64 位边界) */
        uint64_t lsb_v0 = v0 & 1ull;          /* V[63], 将移入 v1 最高位 */
        uint64_t lsb_v1 = v1 & 1ull;          /* V[127], 决定是否异或 R */
        v0 = v0 >> 1;
        v1 = (v1 >> 1) | (lsb_v0 << 63);
        /* R = 0xE1<<120, 高 64 位 = 0xE100000000000000, 低 64 位 = 0 */
        v0 ^= (0ull - lsb_v1) & 0xE100000000000000ull;
    }
    /* 处理 X 的低半 X[64..127] (v1 的 bit63..bit0) */
    for (i = 63; i >= 0; --i) {
        uint64_t mask = -(uint64_t)((x1 >> i) & 1ull);
        z0 ^= (mask & v0);
        z1 ^= (mask & v1);

        uint64_t lsb_v0 = v0 & 1ull;
        uint64_t lsb_v1 = v1 & 1ull;
        v0 = v0 >> 1;
        v1 = (v1 >> 1) | (lsb_v0 << 63);
        v0 ^= (0ull - lsb_v1) & 0xE100000000000000ull;
    }

    /* 写回 X (big-endian) */
    for (i = 7; i >= 0; --i) {
        x[i]     = (uint8_t)(z0 & 0xFF); z0 >>= 8;
        x[i + 8] = (uint8_t)(z1 & 0xFF); z1 >>= 8;
    }
    }  /* end 位串行 fallback */
}

static void gcm_ghash(uint8_t* x, const uint8_t* h, const uint8_t* data, size_t data_len) {
    /* 优化: 整块用 32 位 XOR, 尾块逐字节补零。
     * 旧实现每块都 memset+逐字节拷贝+逐字节 XOR, 浪费性能。 */
    size_t full_blocks = data_len >> 4;   /* data_len / 16 */
    size_t tail_bytes  = data_len & 15;   /* data_len % 16 */
    size_t i;
    u32 *x4 = (u32*)x;
    const u32 *d4;

    for (i = 0; i < full_blocks; ++i) {
        d4 = (const u32*)(data + (i << 4));
        x4[0] ^= d4[0];
        x4[1] ^= d4[1];
        x4[2] ^= d4[2];
        x4[3] ^= d4[3];
        gcm_mult(x, h);
    }
    if (tail_bytes) {
        uint8_t block[16] = {0};
        memcpy(block, data + (full_blocks << 4), tail_bytes);
        for (i = 0; i < 16; ++i) x[i] ^= block[i];
        gcm_mult(x, h);
    }
}

static void gcm_ghash_final(uint8_t* x, const uint8_t* h, size_t aad_len, size_t ciphertext_len) {
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len << 3;
    uint64_t cipher_bits = (uint64_t)ciphertext_len << 3;
    int i;

    for (i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (8 * (7 - i)));
        len_block[i + 8] = (uint8_t)(cipher_bits >> (8 * (7 - i)));
    }

    for (i = 0; i < 16; i++) {
        x[i] ^= len_block[i];
    }
    gcm_mult(x, h);
}

uint8_t* aes_gcm_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t h[16];
    uint8_t zero_block[16] = {0};
    uint8_t counter[16] = {0};
    uint8_t x[16];
    uint8_t len_block[16];
    uint8_t* ciphertext;
    uint8_t counter_0[16];
    uint8_t stream_block[16];
    uint64_t nonce_bits;
    int i, j;

    if (!ctx || !plaintext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }

    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }

    if (nonce_size == 0 || nonce_size > 16) {
        *out_size = 0;
        return NULL;
    }

    if (tag_size > 16) {
        tag_size = 16;
    }

    if (!aes_tables_ready) aes_init_tables();

    /* H = AES_K(0) — 用完全展开路径加速 (AES-256/128) */
    Cipher_auto(ctx, zero_block, h);
    gcm_init_table(h);   /* 预计算 8-bit M-table (64KB), 后续 GHASH 查表加速 ~8× */

    if (nonce_size == 12) {
        memcpy(counter, nonce, 12);
        counter[15] = 1;
    } else {
        memset(x, 0, 16);
        gcm_ghash(x, h, nonce, nonce_size);
        memset(len_block, 0, 16);
        nonce_bits = (uint64_t)nonce_size << 3;
        for (i = 7; i >= 0; --i) {
            len_block[i + 8] = (uint8_t)(nonce_bits >> (8 * (7 - i)));
        }
        for (i = 0; i < 16; ++i) {
            x[i] ^= len_block[i];
        }
        gcm_mult(x, h);
        memcpy(counter, x, 16);
    }

    if (plaintext_size == 0) {
        *out_size = 0;
        ciphertext = (uint8_t*)malloc(1);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
        ciphertext[0] = 0;
    } else {
        ciphertext = (uint8_t*)malloc(plaintext_size);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
    }

    /* 保存 J0 = counter, 用于最后计算 tag */
    memcpy(counter_0, counter, 16);

    /* inc32(counter): 仅低 32 位递增 (GCM 规范) */
    {
        uint32_t ctr_low = ((uint32_t)counter[12] << 24) | ((uint32_t)counter[13] << 16)
                         | ((uint32_t)counter[14] << 8) | (uint32_t)counter[15];
        ctr_low++;
        counter[12] = (uint8_t)(ctr_low >> 24);
        counter[13] = (uint8_t)(ctr_low >> 16);
        counter[14] = (uint8_t)(ctr_low >> 8);
        counter[15] = (uint8_t)(ctr_low);
    }

    /* GCM CTR 加密: 16 字节块处理, 使用 AES-256 完全展开路径 */
    {
        size_t full_blocks = plaintext_size >> 4;
        size_t tail_bytes  = plaintext_size & 15;
        size_t bi;
        for (bi = 0; bi < full_blocks; ++bi) {
            uint8_t stream[16];
            if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, counter, stream);
            else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, counter, stream);
            else                    Cipher_inline(ctx->w, ctx->Nr, counter, stream);

            u32 *o4 = (u32*)(ciphertext + (bi << 4));
            const u32 *p4 = (const u32*)(plaintext + (bi << 4));
            const u32 *s4 = (const u32*)stream;
            o4[0] = p4[0] ^ s4[0];
            o4[1] = p4[1] ^ s4[1];
            o4[2] = p4[2] ^ s4[2];
            o4[3] = p4[3] ^ s4[3];

            /* inc32(counter) */
            uint32_t cl = ((uint32_t)counter[12] << 24) | ((uint32_t)counter[13] << 16)
                        | ((uint32_t)counter[14] << 8) | (uint32_t)counter[15];
            cl++;
            counter[12] = (uint8_t)(cl >> 24);
            counter[13] = (uint8_t)(cl >> 16);
            counter[14] = (uint8_t)(cl >> 8);
            counter[15] = (uint8_t)(cl);
        }
        if (tail_bytes) {
            uint8_t stream[16];
            size_t off = full_blocks << 4;
            if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, counter, stream);
            else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, counter, stream);
            else                    Cipher_inline(ctx->w, ctx->Nr, counter, stream);
            for (j = 0; j < (int)tail_bytes; ++j) {
                ciphertext[off + j] = plaintext[off + j] ^ stream[j];
            }
        }
    }

    /* GHASH(AAD || ciphertext || len_block) */
    memset(x, 0, 16);
    if (aad_size > 0) {
        gcm_ghash(x, h, aad, aad_size);
    }
    if (plaintext_size > 0) {
        gcm_ghash(x, h, ciphertext, plaintext_size);
    }
    gcm_ghash_final(x, h, aad_size, plaintext_size);

    /* tag = GHASH_result XOR AES_K(J0) */
    if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, counter_0, stream_block);
    else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, counter_0, stream_block);
    else                    Cipher_inline(ctx->w, ctx->Nr, counter_0, stream_block);
    for (i = 0; i < 16; ++i) {
        x[i] ^= stream_block[i];
    }

    memcpy(tag, x, tag_size);
    *out_size = plaintext_size;

    return ciphertext;
}

uint8_t* aes_gcm_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t h[16];
    uint8_t zero_block[16] = {0};
    uint8_t counter[16] = {0};
    uint8_t x[16];
    uint8_t len_block[16];
    uint8_t* plaintext;
    uint8_t counter_0[16];
    uint8_t stream_block[16];
    uint64_t nonce_bits;
    uint8_t result;
    int i, j;

    if (!ctx || !ciphertext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }

    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }

    if (nonce_size == 0 || nonce_size > 16) {
        *out_size = 0;
        return NULL;
    }

    if (tag_size > 16) {
        tag_size = 16;
    }

    if (!aes_tables_ready) aes_init_tables();

    /* H = AES_K(0) */
    Cipher_auto(ctx, zero_block, h);

    if (nonce_size == 12) {
        memcpy(counter, nonce, 12);
        counter[15] = 1;
    } else {
        memset(x, 0, 16);
        gcm_ghash(x, h, nonce, nonce_size);
        memset(len_block, 0, 16);
        nonce_bits = (uint64_t)nonce_size << 3;
        for (i = 7; i >= 0; --i) {
            len_block[i + 8] = (uint8_t)(nonce_bits >> (8 * (7 - i)));
        }
        for (i = 0; i < 16; ++i) {
            x[i] ^= len_block[i];
        }
        gcm_mult(x, h);
        memcpy(counter, x, 16);
    }

    if (ciphertext_size == 0) {
        *out_size = 0;
        plaintext = (uint8_t*)malloc(1);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
        plaintext[0] = 0;
    } else {
        plaintext = (uint8_t*)malloc(ciphertext_size);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
    }

    memcpy(counter_0, counter, 16);

    /* inc32(counter) */
    {
        uint32_t ctr_low = ((uint32_t)counter[12] << 24) | ((uint32_t)counter[13] << 16)
                         | ((uint32_t)counter[14] << 8) | (uint32_t)counter[15];
        ctr_low++;
        counter[12] = (uint8_t)(ctr_low >> 24);
        counter[13] = (uint8_t)(ctr_low >> 16);
        counter[14] = (uint8_t)(ctr_low >> 8);
        counter[15] = (uint8_t)(ctr_low);
    }

    /* GCM CTR 解密: 16 字节块处理 */
    {
        size_t full_blocks = ciphertext_size >> 4;
        size_t tail_bytes  = ciphertext_size & 15;
        size_t bi;
        for (bi = 0; bi < full_blocks; ++bi) {
            uint8_t stream[16];
            if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, counter, stream);
            else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, counter, stream);
            else                    Cipher_inline(ctx->w, ctx->Nr, counter, stream);

            u32 *o4 = (u32*)(plaintext + (bi << 4));
            const u32 *c4 = (const u32*)(ciphertext + (bi << 4));
            const u32 *s4 = (const u32*)stream;
            o4[0] = c4[0] ^ s4[0];
            o4[1] = c4[1] ^ s4[1];
            o4[2] = c4[2] ^ s4[2];
            o4[3] = c4[3] ^ s4[3];

            uint32_t cl = ((uint32_t)counter[12] << 24) | ((uint32_t)counter[13] << 16)
                        | ((uint32_t)counter[14] << 8) | (uint32_t)counter[15];
            cl++;
            counter[12] = (uint8_t)(cl >> 24);
            counter[13] = (uint8_t)(cl >> 16);
            counter[14] = (uint8_t)(cl >> 8);
            counter[15] = (uint8_t)(cl);
        }
        if (tail_bytes) {
            uint8_t stream[16];
            size_t off = full_blocks << 4;
            if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, counter, stream);
            else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, counter, stream);
            else                    Cipher_inline(ctx->w, ctx->Nr, counter, stream);
            for (j = 0; j < (int)tail_bytes; ++j) {
                plaintext[off + j] = ciphertext[off + j] ^ stream[j];
            }
        }
    }

    /* GHASH(AAD || ciphertext || len_block) — 注意: 用密文计算, 非明文 */
    memset(x, 0, 16);
    if (aad_size > 0) {
        gcm_ghash(x, h, aad, aad_size);
    }
    if (ciphertext_size > 0) {
        gcm_ghash(x, h, ciphertext, ciphertext_size);
    }
    gcm_ghash_final(x, h, aad_size, ciphertext_size);

    /* expected_tag = GHASH_result XOR AES_K(J0) */
    if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, counter_0, stream_block);
    else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, counter_0, stream_block);
    else                    Cipher_inline(ctx->w, ctx->Nr, counter_0, stream_block);
    for (i = 0; i < 16; ++i) {
        x[i] ^= stream_block[i];
    }

    /* 常时 tag 比较: 累积差异, 不早退 */
    result = 0;
    for (i = 0; i < (int)tag_size; ++i) {
        result |= (uint8_t)(x[i] ^ tag[i]);
    }

    if (result != 0) {
        /* 验证失败: 安全擦除并返回 NULL */
        memset(plaintext, 0, ciphertext_size);
        free(plaintext);
        *out_size = 0;
        return NULL;
    }

    *out_size = ciphertext_size;
    return plaintext;
}

static void ccm_ctr(AES_Context* ctx, const uint8_t* nonce, size_t nonce_len,
                    uint8_t* out, size_t out_len) {
    uint8_t counter[16] = {0};  /* 全零初始化, 确保 counter[counter_start..15] 清零 */
    uint8_t block[16];
    int q;
    size_t i, j;
    size_t counter_start = 1 + nonce_len;  /* counter 字节 [counter_start..15] 为递增字段 (q = counter[0]+1 字节) */

    q = 15 - (int)nonce_len;

    counter[0] = (uint8_t)(q - 1);
    memcpy(counter + 1, nonce, nonce_len);

    if (!aes_tables_ready) aes_init_tables();

    /* 整块用 32 位拷贝, 尾块逐字节 */
    size_t full = out_len >> 4;
    size_t tail = out_len & 15;
    for (i = 0; i < full; ++i) {
        Cipher_auto(ctx, counter, out + (i << 4));
        /* counter 递增 (只在 counter_start..15 范围内) */
        for (j = 15; j >= counter_start; --j) {
            if (++counter[j] != 0) break;
        }
    }
    if (tail) {
        Cipher_auto(ctx, counter, block);
        memcpy(out + (full << 4), block, tail);
    }
}

/* CCM CBC-MAC 内部: XOR 一个 16 字节块到 mac, 然后加密 mac。
 * 用 32 位 XOR 加速。块指针须 16 字节可读 (尾块用 pad_block 补零)。 */
static __attribute__((always_inline)) inline void
ccm_mac_xenc(AES_Context* ctx, uint8_t* mac, const uint8_t* blk) {
    u32 *m4 = (u32*)mac;
    const u32 *b4 = (const u32*)blk;
    m4[0] ^= b4[0]; m4[1] ^= b4[1]; m4[2] ^= b4[2]; m4[3] ^= b4[3];
    Cipher_auto(ctx, mac, mac);
}

static void ccm_mac(AES_Context* ctx, const uint8_t* nonce, size_t nonce_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* data, size_t data_len,
                    size_t tag_size,
                    uint8_t* mac) {
    uint8_t b0[16] = {0};
    uint8_t aad_block[16];
    uint8_t data_block[16];
    uint8_t len_block[16];
    int q;
    size_t aad_remaining, data_remaining;
    const uint8_t* aad_ptr;
    const uint8_t* data_ptr;
    int i, j;

    q = 15 - (int)nonce_len;

    b0[0] = (uint8_t)(((aad_len > 0) ? 0x40 : 0x00) | ((tag_size - 2) << 2) | (q - 1));
    memcpy(b0 + 1, nonce, nonce_len);

    for (i = 7; i >= 0; --i) {
        b0[16 - 1 - i] = (uint8_t)(data_len >> (8 * i));
    }

    if (!aes_tables_ready) aes_init_tables();
    Cipher_auto(ctx, b0, mac);

    if (aad_len > 0) {
        aad_remaining = aad_len;
        aad_ptr = aad;

        if (aad_len < 0xFFFE) {
            memset(len_block, 0, 16);
            len_block[0] = (uint8_t)(aad_len >> 8);
            len_block[1] = (uint8_t)(aad_len & 0xFF);
            ccm_mac_xenc(ctx, mac, len_block);

            while (aad_remaining >= 16) {
                ccm_mac_xenc(ctx, mac, aad_ptr);
                aad_ptr += 16;
                aad_remaining -= 16;
            }

            if (aad_remaining > 0) {
                memset(aad_block, 0, 16);
                memcpy(aad_block, aad_ptr, aad_remaining);
                ccm_mac_xenc(ctx, mac, aad_block);
            }
        } else {
            uint8_t prefix[16] = {0};
            prefix[0] = 0xFF;
            prefix[1] = 0xFE;
            for (i = 7; i >= 0; --i) {
                prefix[16 - 1 - i] = (uint8_t)(aad_len >> (8 * i));
            }
            ccm_mac_xenc(ctx, mac, prefix);

            while (aad_remaining >= 16) {
                ccm_mac_xenc(ctx, mac, aad_ptr);
                aad_ptr += 16;
                aad_remaining -= 16;
            }

            if (aad_remaining > 0) {
                memset(aad_block, 0, 16);
                memcpy(aad_block, aad_ptr, aad_remaining);
                ccm_mac_xenc(ctx, mac, aad_block);
            }
        }
    }

    if (data_len > 0) {
        data_remaining = data_len;
        data_ptr = data;

        while (data_remaining >= 16) {
            ccm_mac_xenc(ctx, mac, data_ptr);
            data_ptr += 16;
            data_remaining -= 16;
        }

        if (data_remaining > 0) {
            memset(data_block, 0, 16);
            memcpy(data_block, data_ptr, data_remaining);
            ccm_mac_xenc(ctx, mac, data_block);
        }
    }
}

uint8_t* aes_ccm_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t* ciphertext;
    uint8_t mac[16];
    uint8_t* keystream;
    size_t i;
    
    if (!ctx || !plaintext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }
    
    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }
    
    if (nonce_size < 7 || nonce_size > 13) {
        *out_size = 0;
        return NULL;
    }
    
    if (tag_size < 4 || tag_size > 16 || tag_size % 2 != 0) {
        tag_size = 16;
    }
    
    if (plaintext_size == 0) {
        *out_size = 0;
        ciphertext = (uint8_t*)malloc(1);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
        ciphertext[0] = 0;
    } else {
        ciphertext = (uint8_t*)malloc(plaintext_size);
        if (!ciphertext) {
            *out_size = 0;
            return NULL;
        }
    }
    
    ccm_mac(ctx, nonce, nonce_size, aad, aad_size, plaintext, plaintext_size, tag_size, mac);
    
    keystream = (uint8_t*)malloc(plaintext_size + tag_size);
    if (!keystream) {
        free(ciphertext);
        *out_size = 0;
        return NULL;
    }
    
    ccm_ctr(ctx, nonce, nonce_size, keystream, plaintext_size + tag_size);
    
    for (i = 0; i < plaintext_size; ++i) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
    
    for (i = 0; i < tag_size; ++i) {
        tag[i] = mac[i] ^ keystream[plaintext_size + i];
    }
    
    memset(keystream, 0, plaintext_size + tag_size);
    free(keystream);
    memset(mac, 0, 16);
    *out_size = plaintext_size;
    
    return ciphertext;
}

uint8_t* aes_ccm_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size, size_t* out_size) {
    uint8_t* plaintext;
    uint8_t* keystream;
    uint8_t expected_tag[16] = {0};
    uint8_t mac[16];
    uint8_t result;
    size_t i;
    
    if (!ctx || !ciphertext || !nonce || !tag) {
        *out_size = 0;
        return NULL;
    }
    
    if (aad_size > 0 && !aad) {
        *out_size = 0;
        return NULL;
    }
    
    if (nonce_size < 7 || nonce_size > 13) {
        *out_size = 0;
        return NULL;
    }
    
    if (tag_size < 4 || tag_size > 16 || tag_size % 2 != 0) {
        tag_size = 16;
    }
    
    if (ciphertext_size == 0) {
        *out_size = 0;
        plaintext = (uint8_t*)malloc(1);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
        plaintext[0] = 0;
    } else {
        plaintext = (uint8_t*)malloc(ciphertext_size);
        if (!plaintext) {
            *out_size = 0;
            return NULL;
        }
    }
    
    keystream = (uint8_t*)malloc(ciphertext_size + tag_size);
    if (!keystream) {
        free(plaintext);
        *out_size = 0;
        return NULL;
    }
    
    ccm_ctr(ctx, nonce, nonce_size, keystream, ciphertext_size + tag_size);
    
    for (i = 0; i < ciphertext_size; ++i) {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }
    
    for (i = 0; i < tag_size; ++i) {
        expected_tag[i] = tag[i] ^ keystream[ciphertext_size + i];
    }
    
    memset(keystream, 0, ciphertext_size + tag_size);
    free(keystream);
    
    ccm_mac(ctx, nonce, nonce_size, aad, aad_size, plaintext, ciphertext_size, tag_size, mac);
    
    result = 0;
    for (i = 0; i < tag_size; ++i) {
        result |= mac[i] ^ expected_tag[i];
    }
    
    memset(mac, 0, 16);
    memset(expected_tag, 0, 16);
    
    if (result != 0) {
        memset(plaintext, 0, ciphertext_size);
        free(plaintext);
        *out_size = 0;
        return NULL;
    }
    
    *out_size = ciphertext_size;
    return plaintext;
}

uint8_t* aes_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                     AES_Mode mode, AES_Padding padding,
                     const uint8_t* iv, size_t iv_size, size_t* out_size) {
    const uint8_t* use_iv;
    
    if (!ctx || !plaintext || !out_size) {
        *out_size = 0;
        return NULL;
    }
    
    use_iv = iv;
    if (!use_iv && ctx->iv_set) {
        use_iv = ctx->iv;
        iv_size = BLOCK_SIZE;
    }
    
    switch (mode) {
        case AES_MODE_ECB:
            return ecb_encrypt(ctx, plaintext, plaintext_size, padding, out_size);
        case AES_MODE_CBC:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cbc_encrypt(ctx, plaintext, plaintext_size, use_iv, padding, out_size);
        case AES_MODE_CFB8:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb8_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_CFB128:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb128_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_OFB:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ofb_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_CTR:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ctr_encrypt(ctx, plaintext, plaintext_size, use_iv, out_size);
        case AES_MODE_GCM:
            *out_size = 0;
            return NULL;
        case AES_MODE_CCM:
            *out_size = 0;
            return NULL;
        case AES_MODE_XTS:
            if (!use_iv || iv_size != BLOCK_SIZE) { *out_size = 0; return NULL; }
            return aes_xts_encrypt(ctx, plaintext, plaintext_size, NULL, use_iv, BLOCK_SIZE, out_size);
        default:
            *out_size = 0;
            return NULL;
    }
}

uint8_t* aes_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                     AES_Mode mode, AES_Padding padding,
                     const uint8_t* iv, size_t iv_size, size_t* out_size) {
    const uint8_t* use_iv;
    
    if (!ctx || !ciphertext || !out_size) {
        *out_size = 0;
        return NULL;
    }
    
    use_iv = iv;
    if (!use_iv && ctx->iv_set) {
        use_iv = ctx->iv;
        iv_size = BLOCK_SIZE;
    }
    
    switch (mode) {
        case AES_MODE_ECB:
            return ecb_decrypt(ctx, ciphertext, ciphertext_size, padding, out_size);
        case AES_MODE_CBC:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cbc_decrypt(ctx, ciphertext, ciphertext_size, use_iv, padding, out_size);
        case AES_MODE_CFB8:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb8_decrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_CFB128:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return cfb128_decrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_OFB:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ofb_encrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_CTR:
            if (!use_iv || iv_size != BLOCK_SIZE) {
                *out_size = 0;
                return NULL;
            }
            return ctr_encrypt(ctx, ciphertext, ciphertext_size, use_iv, out_size);
        case AES_MODE_GCM:
            *out_size = 0;
            return NULL;
        case AES_MODE_CCM:
            *out_size = 0;
            return NULL;
        case AES_MODE_XTS:
            if (!use_iv || iv_size != BLOCK_SIZE) { *out_size = 0; return NULL; }
            return aes_xts_decrypt(ctx, ciphertext, ciphertext_size, NULL, use_iv, BLOCK_SIZE, out_size);
        default:
            *out_size = 0;
            return NULL;
    }
}

char* aes_bytes_to_hex(const uint8_t* data, size_t size) {
    char* hex;
    const char* hex_chars;
    size_t i;
    
    if (!data || size == 0) return NULL;
    
    hex = (char*)malloc(size * 2 + 1);
    if (!hex) return NULL;
    
    hex_chars = "0123456789abcdef";
    for (i = 0; i < size; ++i) {
        hex[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    hex[size * 2] = '\0';
    
    return hex;
}

uint8_t* aes_hex_to_bytes(const char* hex, size_t* out_size) {
    size_t len;
    uint8_t* bytes;
    char h, l;
    size_t i;
    
    if (!hex || !out_size) {
        *out_size = 0;
        return NULL;
    }
    
    len = strlen(hex);
    if (len % 2 != 0) {
        *out_size = 0;
        return NULL;
    }
    
    *out_size = len / 2;
    bytes = (uint8_t*)malloc(*out_size);
    if (!bytes) {
        *out_size = 0;
        return NULL;
    }
    
    for (i = 0; i < *out_size; ++i) {
        h = hex[i * 2];
        l = hex[i * 2 + 1];
        
        if (h >= '0' && h <= '9') h -= '0';
        else if (h >= 'a' && h <= 'f') h -= 'a' - 10;
        else if (h >= 'A' && h <= 'F') h -= 'A' - 10;
        else {
            free(bytes);
            *out_size = 0;
            return NULL;
        }
        
        if (l >= '0' && l <= '9') l -= '0';
        else if (l >= 'a' && l <= 'f') l -= 'a' - 10;
        else if (l >= 'A' && l <= 'F') l -= 'A' - 10;
        else {
            free(bytes);
            *out_size = 0;
            return NULL;
        }
        
        bytes[i] = (h << 4) | l;
    }
    
    return bytes;
}

/* =========================================================================
 * XTS 模式 (NIST SP 800-38E)
 *
 *   域: GF(2^128), 不可约多项式 p(x) = x^128 + x^7 + x^2 + x + 1
 *   大端字节序: X[0] 是最高字节 (x^127..x^120), X[15] 是最低字节 (x^7..x^0)
 *
 *   两把 key:
 *     - 主 key ctx      : 数据块加解密 E/D (AES-128/192/256)
 *     - tweak_key       : tweak 加密 E_tweak (可为 NULL, 则复用 ctx 单 key 模式)
 *
 *   加密 C = AES-XTS-PI2(Key, Tweak, Plaintext)
 *     X = E_tweak(Tweak_16)
 *     对每个完整块 i: C_i = E(P_i XOR X) XOR X, 然后 X = X XOR alpha
 *     对最后部分块 (last_frac > 0):
 *       C_prev = E(P_prev XOR X) XOR X; X = X XOR alpha
 *       C_last_frac = P_last_frac XOR C_prev[0..last_frac-1]   (swap 技术)
 *
 *   无填充, 输出长度 = 输入长度
 * ========================================================================= */

/* GF(2^128) 乘以 α = 2, big-endian byte order.
 *   X[0] 是最高字节 (bit 127..120 = 系数 x^127..x^120),
 *   X[15] 是最低字节 (bit 7..0   = 系数 x^7..x^0).
 * 乘法: 整个 128 位左移 1 bit; 若原最高位 (X[0]&0x80) 为 1,
 * 则 X[15] XOR 0x87 (x^128 mod p(x) = x^7+x^2+x+1 = 0x87). */
static void xts_mul_alpha(uint8_t x[16])
{
    int i;
    uint8_t top_bit = (uint8_t)(x[0] & 0x80);
    for (i = 0; i < 15; ++i) {
        x[i] = (uint8_t)((x[i] << 1) | (x[i + 1] >> 7));
    }
    x[15] = (uint8_t)(x[15] << 1);
    if (top_bit) x[15] ^= 0x87;
}

static __attribute__((always_inline)) inline void
InvCipher_auto(const AES_Context *ctx, const u8 *in, u8 *out)
{
    if (ctx->Nr == 14)      InvCipher_inline_aes256(ctx->dw, in, out);
    else if (ctx->Nr == 12) InvCipher_inline_aes192(ctx->dw, in, out);
    else if (ctx->Nr == 10) InvCipher_inline_aes128(ctx->dw, in, out);
    else                    InvCipher_inline(ctx->dw, ctx->Nr, in, out);
}

static uint8_t* xts_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t size,
                            const uint8_t* tweak_key, const uint8_t* tweak,
                            size_t tweak_size, size_t* out_size)
{
    if (!ctx || !plaintext || size == 0 || !out_size) {
        if (out_size) *out_size = 0;
        return NULL;
    }

    *out_size = size;

    uint8_t* ciphertext = (uint8_t*)malloc(size);
    if (!ciphertext) { *out_size = 0; return NULL; }

    if (!aes_tables_ready) aes_init_tables();

    uint8_t X[16];
    AES_Context tweak_ctx;
    int free_tweak_ctx = 0;

    if (tweak_key && tweak_size >= 16) {
        if (aes_init(&tweak_ctx, ctx->key_len, tweak_key, ctx->key_len, NULL, 0) != 0) {
            free(ciphertext); *out_size = 0; return NULL;
        }
        memcpy(X, tweak, 16);
        Cipher_auto(&tweak_ctx, X, X);
        free_tweak_ctx = 1;
    } else {
        memcpy(X, tweak, 16);
        Cipher_auto(ctx, X, X);
    }

    size_t num_full = size / 16;
    size_t last_frac = size % 16;
    size_t k = 0;

    /* 内联 xts_mul_alpha (GF(2^128) 乘 2, big-endian) - 省函数调用开销 */
#define XTS_MUL_ALPHA(xarr) do { \
        int _i; u8 _t = (xarr)[0] & 0x80; \
        for (_i = 0; _i < 15; ++_i) (xarr)[_i] = (u8)(((xarr)[_i] << 1) | ((xarr)[_i+1] >> 7)); \
        (xarr)[15] = (u8)((xarr)[15] << 1); \
        if (_t) (xarr)[15] ^= 0x87; \
    } while (0)

    if (ctx->Nr == 14) {
        /* ======== AES-256: 完全展开 2 块并行 Cipher_inline_aes256_x2 ======== */
        const u8 *rk = ctx->w;
        while (k + 2 <= num_full) {
            u8 P0[16], P1[16];
            u8 X0[16];
            memcpy(X0, X, 16);
            XTS_MUL_ALPHA(X);         /* X 现在是 X1 */

            const u8 *pi0 = plaintext + (k+0)*16;
            const u8 *pi1 = plaintext + (k+1)*16;
            u8 *co0 = ciphertext + (k+0)*16;
            u8 *co1 = ciphertext + (k+1)*16;

            for (int j = 0; j < 16; ++j) { P0[j] = pi0[j] ^ X0[j]; P1[j] = pi1[j] ^ X[j]; }
            Cipher_inline_aes256_x2(rk, P0, P1, co0, co1);
            for (int j = 0; j < 16; ++j) { co0[j] ^= X0[j]; co1[j] ^= X[j]; }
            XTS_MUL_ALPHA(X);         /* X -> next X0 */
            k += 2;
        }
    } else {
        /* 其他 key size: 单块内联 */
        while (k + 2 <= num_full) {
            u8 P0[16], P1[16];
            u8 X0[16];
            memcpy(X0, X, 16);
            XTS_MUL_ALPHA(X);

            const u8 *pi0 = plaintext + (k+0)*16;
            const u8 *pi1 = plaintext + (k+1)*16;
            u8 *co0 = ciphertext + (k+0)*16;
            u8 *co1 = ciphertext + (k+1)*16;

            if (ctx->Nr == 10) {
                for (int j = 0; j < 16; ++j) P0[j] = pi0[j] ^ X0[j];
                Cipher_inline_aes128(ctx->w, P0, co0);
                for (int j = 0; j < 16; ++j) co0[j] ^= X0[j];
                for (int j = 0; j < 16; ++j) P1[j] = pi1[j] ^ X[j];
                Cipher_inline_aes128(ctx->w, P1, co1);
                for (int j = 0; j < 16; ++j) co1[j] ^= X[j];
            } else if (ctx->Nr == 12) {
                for (int j = 0; j < 16; ++j) P0[j] = pi0[j] ^ X0[j];
                Cipher_inline_aes192(ctx->w, P0, co0);
                for (int j = 0; j < 16; ++j) co0[j] ^= X0[j];
                for (int j = 0; j < 16; ++j) P1[j] = pi1[j] ^ X[j];
                Cipher_inline_aes192(ctx->w, P1, co1);
                for (int j = 0; j < 16; ++j) co1[j] ^= X[j];
            } else {
                for (int j = 0; j < 16; ++j) P0[j] = pi0[j] ^ X0[j];
                Cipher_auto(ctx, P0, co0);
                for (int j = 0; j < 16; ++j) co0[j] ^= X0[j];
                for (int j = 0; j < 16; ++j) P1[j] = pi1[j] ^ X[j];
                Cipher_auto(ctx, P1, co1);
                for (int j = 0; j < 16; ++j) co1[j] ^= X[j];
            }
            XTS_MUL_ALPHA(X);
            k += 2;
        }
    }
    /* 单块尾 */
    for (; k < num_full; ++k) {
        u8 P[16];
        u8 C[16];
        for (int j = 0; j < 16; ++j) P[j] = plaintext[k*16+j] ^ X[j];
        if (ctx->Nr == 14)      Cipher_inline_aes256(ctx->w, P, C);
        else if (ctx->Nr == 12) Cipher_inline_aes192(ctx->w, P, C);
        else if (ctx->Nr == 10) Cipher_inline_aes128(ctx->w, P, C);
        else                    Cipher_auto(ctx, P, C);
        for (int j = 0; j < 16; ++j) C[j] ^= X[j];
        memcpy(ciphertext + k*16, C, 16);
        XTS_MUL_ALPHA(X);
    }

    if (last_frac > 0) {
        uint8_t P_prev[16];
        uint8_t C_prev[16];

        memcpy(P_prev, plaintext + (num_full - 1) * 16, 16);

        for (int j = 0; j < 16; ++j) P_prev[j] ^= X[j];
        Cipher_auto(ctx, P_prev, C_prev);
        for (int j = 0; j < 16; ++j) C_prev[j] ^= X[j];
        XTS_MUL_ALPHA(X);

        for (size_t j = 0; j < last_frac; ++j) {
            ciphertext[num_full * 16 + j] = plaintext[num_full * 16 + j] ^ C_prev[j];
        }
        memcpy(ciphertext + (num_full - 1) * 16, C_prev, 16);
    }

    if (free_tweak_ctx) aes_free(&tweak_ctx);

#undef XTS_MUL_ALPHA
    return ciphertext;
}

static uint8_t* xts_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t size,
                            const uint8_t* tweak_key, const uint8_t* tweak,
                            size_t tweak_size, size_t* out_size)
{
    if (!ctx || !ciphertext || size == 0 || !out_size) {
        if (out_size) *out_size = 0;
        return NULL;
    }

    *out_size = size;

    uint8_t* plaintext = (uint8_t*)malloc(size);
    if (!plaintext) { *out_size = 0; return NULL; }

    if (!aes_tables_ready) aes_init_tables();

    uint8_t X[16];
    AES_Context tweak_ctx;
    int free_tweak_ctx = 0;

    if (tweak_key && tweak_size >= 16) {
        if (aes_init(&tweak_ctx, ctx->key_len, tweak_key, ctx->key_len, NULL, 0) != 0) {
            free(plaintext); *out_size = 0; return NULL;
        }
        memcpy(X, tweak, 16);
        Cipher_auto(&tweak_ctx, X, X);
        free_tweak_ctx = 1;
    } else {
        memcpy(X, tweak, 16);
        Cipher_auto(ctx, X, X);
    }

    size_t num_full = size / 16;
    size_t last_frac = size % 16;
    size_t k = 0;

#define XTS_MUL_ALPHA(xarr) do { \
        int _i; u8 _t = (xarr)[0] & 0x80; \
        for (_i = 0; _i < 15; ++_i) (xarr)[_i] = (u8)(((xarr)[_i] << 1) | ((xarr)[_i+1] >> 7)); \
        (xarr)[15] = (u8)((xarr)[15] << 1); \
        if (_t) (xarr)[15] ^= 0x87; \
    } while (0)

    if (ctx->Nr == 14) {
        /* ======== AES-256: 完全展开 2 块并行 InvCipher_inline_aes256_x2 ======== */
        const u8 *dk = ctx->dw;
        while (k + 2 <= num_full) {
            u8 C0[16], C1[16];
            u8 X0[16];
            memcpy(X0, X, 16);
            XTS_MUL_ALPHA(X);

            const u8 *ci0 = ciphertext + (k+0)*16;
            const u8 *ci1 = ciphertext + (k+1)*16;
            u8 *po0 = plaintext + (k+0)*16;
            u8 *po1 = plaintext + (k+1)*16;

            for (int j = 0; j < 16; ++j) { C0[j] = ci0[j] ^ X0[j]; C1[j] = ci1[j] ^ X[j]; }
            InvCipher_inline_aes256_x2(dk, C0, C1, po0, po1);
            for (int j = 0; j < 16; ++j) { po0[j] ^= X0[j]; po1[j] ^= X[j]; }
            XTS_MUL_ALPHA(X);
            k += 2;
        }
    } else {
        while (k + 2 <= num_full) {
            u8 C0[16], C1[16];
            u8 X0[16];
            memcpy(X0, X, 16);
            XTS_MUL_ALPHA(X);

            const u8 *ci0 = ciphertext + (k+0)*16;
            const u8 *ci1 = ciphertext + (k+1)*16;
            u8 *po0 = plaintext + (k+0)*16;
            u8 *po1 = plaintext + (k+1)*16;

            if (ctx->Nr == 10) {
                for (int j = 0; j < 16; ++j) C0[j] = ci0[j] ^ X0[j];
                InvCipher_inline_aes128(ctx->dw, C0, po0);
                for (int j = 0; j < 16; ++j) po0[j] ^= X0[j];
                for (int j = 0; j < 16; ++j) C1[j] = ci1[j] ^ X[j];
                InvCipher_inline_aes128(ctx->dw, C1, po1);
                for (int j = 0; j < 16; ++j) po1[j] ^= X[j];
            } else if (ctx->Nr == 12) {
                for (int j = 0; j < 16; ++j) C0[j] = ci0[j] ^ X0[j];
                InvCipher_inline_aes192(ctx->dw, C0, po0);
                for (int j = 0; j < 16; ++j) po0[j] ^= X0[j];
                for (int j = 0; j < 16; ++j) C1[j] = ci1[j] ^ X[j];
                InvCipher_inline_aes192(ctx->dw, C1, po1);
                for (int j = 0; j < 16; ++j) po1[j] ^= X[j];
            } else {
                for (int j = 0; j < 16; ++j) C0[j] = ci0[j] ^ X0[j];
                InvCipher_auto(ctx, C0, po0);
                for (int j = 0; j < 16; ++j) po0[j] ^= X0[j];
                for (int j = 0; j < 16; ++j) C1[j] = ci1[j] ^ X[j];
                InvCipher_auto(ctx, C1, po1);
                for (int j = 0; j < 16; ++j) po1[j] ^= X[j];
            }
            XTS_MUL_ALPHA(X);
            k += 2;
        }
    }
    for (; k < num_full; ++k) {
        u8 C[16], P[16];
        for (int j = 0; j < 16; ++j) C[j] = ciphertext[k*16+j] ^ X[j];
        if (ctx->Nr == 14)      InvCipher_inline_aes256(ctx->dw, C, P);
        else if (ctx->Nr == 12) InvCipher_inline_aes192(ctx->dw, C, P);
        else if (ctx->Nr == 10) InvCipher_inline_aes128(ctx->dw, C, P);
        else                    InvCipher_auto(ctx, C, P);
        for (int j = 0; j < 16; ++j) P[j] ^= X[j];
        memcpy(plaintext + k*16, P, 16);
        XTS_MUL_ALPHA(X);
    }

    if (last_frac > 0) {
        uint8_t C_last_full[16];
        uint8_t P_last_full[16];
        const uint8_t *C_last_frac = ciphertext + num_full * 16;
        const uint8_t *C_last_full_ct = ciphertext + (num_full - 1) * 16;

        memcpy(C_last_full, C_last_full_ct, 16);

        for (int j = 0; j < 16; ++j) C_last_full[j] ^= X[j];
        InvCipher_auto(ctx, C_last_full, P_last_full);
        for (int j = 0; j < 16; ++j) P_last_full[j] ^= X[j];

        /* P_last_frac_j = C_last_frac_j XOR C_last_full_j
         *  (C_last_full 是密文里的完整块, 不是解出来的 P_last_full!) */
        for (size_t j = 0; j < last_frac; ++j) {
            plaintext[num_full * 16 + j] = C_last_frac[j] ^ C_last_full_ct[j];
        }
        memcpy(plaintext + (num_full - 1) * 16, P_last_full, 16);
    }

    if (free_tweak_ctx) aes_free(&tweak_ctx);

    return plaintext;
}

uint8_t* aes_xts_encrypt(AES_Context* ctx, const uint8_t* plaintext, size_t plaintext_size,
                         const uint8_t* tweak_key, const uint8_t* tweak, size_t tweak_size,
                         size_t* out_size)
{
    return xts_encrypt(ctx, plaintext, plaintext_size, tweak_key, tweak, tweak_size, out_size);
}

uint8_t* aes_xts_decrypt(AES_Context* ctx, const uint8_t* ciphertext, size_t ciphertext_size,
                         const uint8_t* tweak_key, const uint8_t* tweak, size_t tweak_size,
                         size_t* out_size)
{
    return xts_decrypt(ctx, ciphertext, ciphertext_size, tweak_key, tweak, tweak_size, out_size);
}

int aes_self_test(void) {
    uint8_t key_128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t plaintext_128[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t expected_ciphertext_128[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                           0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    uint8_t gcm_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                           0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t gcm_nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x01};
    uint8_t gcm_plaintext[32] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    uint8_t gcm_aad[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t expected_gcm_tag[16] = {0x97, 0x15, 0x0d, 0xab, 0x5a, 0xc1, 0x8a, 0xa8,
                                     0x2e, 0x2e, 0x46, 0x68, 0x27, 0x22, 0x81, 0x09};
    uint8_t ccm_key[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                           0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    uint8_t ccm_nonce[11] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1a};
    uint8_t ccm_plaintext[32] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ccm_aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    AES_Context ctx;
    uint8_t* ciphertext;
    uint8_t* decrypted;
    uint8_t gcm_tag[16];
    uint8_t ccm_tag[16];
    size_t out_size;
    int i;
    
    if (aes_init(&ctx, AES_128, key_128, 16, NULL, 0) != 0) {
        return -1;
    }
    ciphertext = ecb_encrypt(&ctx, plaintext_128, 16, AES_PADDING_NONE, &out_size);
    if (!ciphertext || out_size != 16) {
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 16; ++i) {
        if (ciphertext[i] != expected_ciphertext_128[i]) {
            free(ciphertext);
            aes_free(&ctx);
            return -1;
        }
    }
    free(ciphertext);
    aes_free(&ctx);
    
    if (aes_init(&ctx, AES_128, gcm_key, 16, NULL, 0) != 0) {
        return -1;
    }
    ciphertext = aes_gcm_encrypt(&ctx, gcm_plaintext, 32, gcm_nonce, 12, gcm_aad, 16, gcm_tag, 16, &out_size);
    if (!ciphertext || out_size != 32) {
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 16; ++i) {
        if (gcm_tag[i] != expected_gcm_tag[i]) {
            free(ciphertext);
            aes_free(&ctx);
            return -1;
        }
    }
    decrypted = aes_gcm_decrypt(&ctx, ciphertext, 32, gcm_nonce, 12, gcm_aad, 16, gcm_tag, 16, &out_size);
    if (!decrypted || out_size != 32) {
        free(ciphertext);
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != gcm_plaintext[i]) {
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return -1;
        }
    }
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    
    if (aes_init(&ctx, AES_128, ccm_key, 16, NULL, 0) != 0) {
        return -1;
    }
    ciphertext = aes_ccm_encrypt(&ctx, ccm_plaintext, 32, ccm_nonce, 11, ccm_aad, 16, ccm_tag, 16, &out_size);
    if (!ciphertext || out_size != 32) {
        aes_free(&ctx);
        return -1;
    }
    decrypted = aes_ccm_decrypt(&ctx, ciphertext, 32, ccm_nonce, 11, ccm_aad, 16, ccm_tag, 16, &out_size);
    if (!decrypted || out_size != 32) {
        free(ciphertext);
        aes_free(&ctx);
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        if (decrypted[i] != ccm_plaintext[i]) {
            free(ciphertext);
            free(decrypted);
            aes_free(&ctx);
            return -1;
        }
    }
    free(ciphertext);
    free(decrypted);
    aes_free(&ctx);
    
    return 0;
}

int aes_stream_init(AES_StreamContext* sctx, AES_Context* ctx, AES_Mode mode, AES_Padding padding,
                    const uint8_t* iv, size_t iv_size, int is_encrypt) {
    if (!sctx || !ctx) {
        return -1;
    }
    
    /* ECB 模式不需要 IV；其他模式必须提供 16 字节 IV */
    if (mode != AES_MODE_ECB) {
        if (!iv || iv_size != BLOCK_SIZE) {
            return -1;
        }
    }
    
    memset(sctx, 0, sizeof(AES_StreamContext));
    sctx->ctx = ctx;
    sctx->mode = mode;
    sctx->padding = padding;
    if (iv && iv_size == BLOCK_SIZE) {
        memcpy(sctx->iv, iv, BLOCK_SIZE);
        memcpy(sctx->feedback, iv, BLOCK_SIZE);
        memcpy(sctx->counter, iv, BLOCK_SIZE);
    }
    sctx->is_encrypt = is_encrypt;
    
    return 0;
}

static void stream_gcm_ghash_update(AES_StreamContext* sctx, const uint8_t* data, size_t data_len) {
    uint8_t block[16];
    size_t i, j;
    
    for (i = 0; i < data_len; i += 16) {
        memset(block, 0, 16);
        for (j = 0; j < 16; j++) {
            if (i + j < data_len) {
                block[j] = data[i + j];
            }
        }
        for (j = 0; j < 16; j++) {
            sctx->gcm_x[j] ^= block[j];
        }
        gcm_mult(sctx->gcm_x, sctx->gcm_h);
    }
}

static void stream_gcm_ghash_final(AES_StreamContext* sctx) {
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = (uint64_t)sctx->gcm_aad_len << 3;
    uint64_t data_bits = (uint64_t)sctx->gcm_data_len << 3;
    int i;
    
    for (i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (8 * (7 - i)));
        len_block[i + 8] = (uint8_t)(data_bits >> (8 * (7 - i)));
    }
    
    for (i = 0; i < 16; i++) {
        sctx->gcm_x[i] ^= len_block[i];
    }
    gcm_mult(sctx->gcm_x, sctx->gcm_h);
}

int aes_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                      uint8_t* out, size_t* out_size) {
    uint8_t stream_block[16];
    uint8_t temp_block[16];
    size_t i, remaining;
    int idx, j;
    
    if (!sctx || !in || !out || !out_size) {
        return -1;
    }
    
    *out_size = 0;
    
    switch (sctx->mode) {
        case AES_MODE_ECB:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->buffer, out + *out_size);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        InvCipher(sctx->ctx->dw, sctx->ctx->Nr, sctx->buffer, temp_block);
                        /* 带填充的解密：暂存最后一块，finish 时去填充 */
                        if (sctx->padding != AES_PADDING_NONE) {
                            if (sctx->has_last_decrypted) {
                                memcpy(out + *out_size, sctx->last_decrypted, BLOCK_SIZE);
                                *out_size += BLOCK_SIZE;
                            }
                            memcpy(sctx->last_decrypted, temp_block, BLOCK_SIZE);
                            sctx->has_last_decrypted = 1;
                        } else {
                            memcpy(out + *out_size, temp_block, BLOCK_SIZE);
                            *out_size += BLOCK_SIZE;
                        }
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        case AES_MODE_CBC:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    idx = (int)remaining;
                    sctx->buffer[idx] = in[i];   /* buffer 存纯明文, 块满时统一异或 */
                    remaining++;
                    if (remaining == BLOCK_SIZE) {
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            sctx->buffer[j] ^= sctx->feedback[j];
                        }
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->buffer, out + *out_size);
                        memcpy(sctx->feedback, out + *out_size, BLOCK_SIZE);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        InvCipher(sctx->ctx->dw, sctx->ctx->Nr, sctx->buffer, temp_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            temp_block[j] ^= sctx->feedback[j];
                        }
                        /* 带填充的解密：暂存最后一块，finish 时去填充 */
                        if (sctx->padding != AES_PADDING_NONE) {
                            if (sctx->has_last_decrypted) {
                                memcpy(out + *out_size, sctx->last_decrypted, BLOCK_SIZE);
                                *out_size += BLOCK_SIZE;
                            }
                            memcpy(sctx->last_decrypted, temp_block, BLOCK_SIZE);
                            sctx->has_last_decrypted = 1;
                        } else {
                            memcpy(out + *out_size, temp_block, BLOCK_SIZE);
                            *out_size += BLOCK_SIZE;
                        }
                        memcpy(sctx->feedback, sctx->buffer, BLOCK_SIZE);
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        case AES_MODE_CFB8:
            /* CFB8 是逐字节模式：每输入1字节就可输出1字节 */
            for (i = 0; i < in_size; i++) {
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                out[*out_size] = in[i] ^ stream_block[0];
                memmove(sctx->feedback, sctx->feedback + 1, BLOCK_SIZE - 1);
                sctx->feedback[BLOCK_SIZE - 1] = sctx->is_encrypt ? out[*out_size] : in[i];
                (*out_size)++;
            }
            sctx->buffer_len = 0;
            break;
            
        case AES_MODE_CFB128:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        memcpy(sctx->feedback, out + *out_size, BLOCK_SIZE);
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            temp_block[j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        /* 带填充的解密：暂存最后一块，finish 时去填充 */
                        if (sctx->padding != AES_PADDING_NONE) {
                            if (sctx->has_last_decrypted) {
                                memcpy(out + *out_size, sctx->last_decrypted, BLOCK_SIZE);
                                *out_size += BLOCK_SIZE;
                            }
                            memcpy(sctx->last_decrypted, temp_block, BLOCK_SIZE);
                            sctx->has_last_decrypted = 1;
                        } else {
                            memcpy(out + *out_size, temp_block, BLOCK_SIZE);
                            *out_size += BLOCK_SIZE;
                        }
                        memcpy(sctx->feedback, sctx->buffer, BLOCK_SIZE);
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        case AES_MODE_OFB:
            remaining = sctx->buffer_len;
            for (i = 0; i < in_size; i++) {
                sctx->buffer[remaining++] = in[i];
                if (remaining == BLOCK_SIZE) {
                    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                    for (j = 0; j < BLOCK_SIZE; j++) {
                        out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                    }
                    memcpy(sctx->feedback, stream_block, BLOCK_SIZE);
                    *out_size += BLOCK_SIZE;
                    remaining = 0;
                }
            }
            sctx->buffer_len = remaining;
            break;
            
        case AES_MODE_CTR:
            remaining = sctx->buffer_len;
            for (i = 0; i < in_size; i++) {
                sctx->buffer[remaining++] = in[i];
                if (remaining == BLOCK_SIZE) {
                    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
                    for (j = 0; j < BLOCK_SIZE; j++) {
                        out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                    }
                    for (j = BLOCK_SIZE - 1; j >= 0; --j) {
                        if (++sctx->counter[j] != 0) {
                            break;
                        }
                    }
                    *out_size += BLOCK_SIZE;
                    remaining = 0;
                }
            }
            sctx->buffer_len = remaining;
            break;
            
        case AES_MODE_GCM:
            if (sctx->is_encrypt) {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        stream_gcm_ghash_update(sctx, out + *out_size, BLOCK_SIZE);
                        sctx->gcm_data_len += BLOCK_SIZE;
                        {
                            uint32_t cl = ((uint32_t)sctx->counter[12] << 24) | ((uint32_t)sctx->counter[13] << 16) | ((uint32_t)sctx->counter[14] << 8) | (uint32_t)sctx->counter[15];
                            cl++;
                            sctx->counter[12] = (uint8_t)(cl >> 24);
                            sctx->counter[13] = (uint8_t)(cl >> 16);
                            sctx->counter[14] = (uint8_t)(cl >> 8);
                            sctx->counter[15] = (uint8_t)(cl);
                        }
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            } else {
                remaining = sctx->buffer_len;
                for (i = 0; i < in_size; i++) {
                    sctx->buffer[remaining++] = in[i];
                    if (remaining == BLOCK_SIZE) {
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
                        for (j = 0; j < BLOCK_SIZE; j++) {
                            out[*out_size + j] = sctx->buffer[j] ^ stream_block[j];
                        }
                        stream_gcm_ghash_update(sctx, sctx->buffer, BLOCK_SIZE);
                        sctx->gcm_data_len += BLOCK_SIZE;
                        {
                            uint32_t cl = ((uint32_t)sctx->counter[12] << 24) | ((uint32_t)sctx->counter[13] << 16) | ((uint32_t)sctx->counter[14] << 8) | (uint32_t)sctx->counter[15];
                            cl++;
                            sctx->counter[12] = (uint8_t)(cl >> 24);
                            sctx->counter[13] = (uint8_t)(cl >> 16);
                            sctx->counter[14] = (uint8_t)(cl >> 8);
                            sctx->counter[15] = (uint8_t)(cl);
                        }
                        *out_size += BLOCK_SIZE;
                        remaining = 0;
                    }
                }
                sctx->buffer_len = remaining;
            }
            break;
            
        default:
            return -1;
    }
    
    memset(stream_block, 0, BLOCK_SIZE);
    memset(temp_block, 0, BLOCK_SIZE);
    
    return 0;
}

int aes_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size) {
    uint8_t padded[16];
    size_t i, j;
    size_t padding_len;
    uint8_t last_byte;
    int valid;
    
    if (!sctx || !out || !out_size) {
        return -1;
    }
    
    *out_size = 0;
    
    switch (sctx->mode) {
        case AES_MODE_ECB:
        case AES_MODE_CBC:
            if (sctx->is_encrypt) {
                /* ---- 加密：加填充 ---- */
                if (sctx->padding != AES_PADDING_NONE) {
                    if (sctx->buffer_len > 0) {
                        memset(padded, 0, BLOCK_SIZE);
                        memcpy(padded, sctx->buffer, sctx->buffer_len);
                        
                        switch (sctx->padding) {
                            case AES_PADDING_ZERO:
                                break;
                            case AES_PADDING_PKCS5:
                            case AES_PADDING_PKCS7:
                                for (i = sctx->buffer_len; i < BLOCK_SIZE; i++) {
                                    padded[i] = (uint8_t)(BLOCK_SIZE - sctx->buffer_len);
                                }
                                break;
                            case AES_PADDING_ANSIX923:
                                padded[BLOCK_SIZE - 1] = (uint8_t)(BLOCK_SIZE - sctx->buffer_len);
                                break;
                            case AES_PADDING_ISO10126:
                                if (BLOCK_SIZE - sctx->buffer_len > 1) {
                                    aes_random_bytes(padded + sctx->buffer_len, BLOCK_SIZE - sctx->buffer_len - 1);
                                }
                                padded[BLOCK_SIZE - 1] = (uint8_t)(BLOCK_SIZE - sctx->buffer_len);
                                break;
                            case AES_PADDING_ISO7816:
                                padded[sctx->buffer_len] = 0x80;
                                break;
                            default:
                                break;
                        }
                        
                        if (sctx->mode == AES_MODE_CBC) {
                            for (j = 0; j < BLOCK_SIZE; j++) {
                                padded[j] ^= sctx->feedback[j];
                            }
                        }
                        
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, padded, out);
                        *out_size = BLOCK_SIZE;
                        
                        if (sctx->mode == AES_MODE_CBC) {
                            memcpy(sctx->feedback, out, BLOCK_SIZE);
                        }
                    } else if (sctx->padding != AES_PADDING_NONE) {
                        /* 数据刚好整块，需要额外加一个整块填充 */
                        memset(padded, BLOCK_SIZE, BLOCK_SIZE);
                        
                        if (sctx->mode == AES_MODE_CBC) {
                            for (j = 0; j < BLOCK_SIZE; j++) {
                                padded[j] ^= sctx->feedback[j];
                            }
                        }
                        
                        Cipher(sctx->ctx->w, sctx->ctx->Nr, padded, out);
                        *out_size = BLOCK_SIZE;
                        
                        if (sctx->mode == AES_MODE_CBC) {
                            memcpy(sctx->feedback, out, BLOCK_SIZE);
                        }
                    }
                }
            } else {
                /* ---- 解密：去填充 ---- */
                if (sctx->padding != AES_PADDING_NONE) {
                    if (!sctx->has_last_decrypted) {
                        /* 没有任何数据块，错误或空数据 */
                        memset(sctx->last_decrypted, 0, BLOCK_SIZE);
                        sctx->has_last_decrypted = 0;
                        break;
                    }
                    
                    padding_len = 0;
                    valid = 1;
                    
                    switch (sctx->padding) {
                        case AES_PADDING_NONE:
                            padding_len = 0;
                            break;
                        case AES_PADDING_ZERO:
                            /* 去掉末尾的 0 字节 */
                            padding_len = 0;
                            for (j = BLOCK_SIZE - 1; j < BLOCK_SIZE; j--) {
                                if (sctx->last_decrypted[j] != 0) {
                                    padding_len = BLOCK_SIZE - (size_t)(j + 1);
                                    break;
                                }
                                if (j == 0) {
                                    padding_len = BLOCK_SIZE;
                                    break;
                                }
                            }
                            break;
                        case AES_PADDING_PKCS5:
                        case AES_PADDING_PKCS7:
                            last_byte = sctx->last_decrypted[BLOCK_SIZE - 1];
                            padding_len = (size_t)last_byte;
                            if (padding_len == 0 || padding_len > BLOCK_SIZE) {
                                valid = 0;
                            } else {
                                for (j = BLOCK_SIZE - padding_len; j < BLOCK_SIZE; j++) {
                                    if (sctx->last_decrypted[j] != last_byte) {
                                        valid = 0;
                                        break;
                                    }
                                }
                            }
                            break;
                        case AES_PADDING_ANSIX923:
                            last_byte = sctx->last_decrypted[BLOCK_SIZE - 1];
                            padding_len = (size_t)last_byte;
                            if (padding_len == 0 || padding_len > BLOCK_SIZE) {
                                valid = 0;
                            } else {
                                for (j = BLOCK_SIZE - padding_len; j < BLOCK_SIZE - 1; j++) {
                                    if (sctx->last_decrypted[j] != 0) {
                                        valid = 0;
                                        break;
                                    }
                                }
                            }
                            break;
                        case AES_PADDING_ISO10126:
                            last_byte = sctx->last_decrypted[BLOCK_SIZE - 1];
                            padding_len = (size_t)last_byte;
                            if (padding_len == 0 || padding_len > BLOCK_SIZE) {
                                valid = 0;
                            }
                            break;
                        case AES_PADDING_ISO7816:
                            padding_len = 0;
                            for (j = BLOCK_SIZE - 1; j < BLOCK_SIZE; j--) {
                                if (sctx->last_decrypted[j] == 0x80) {
                                    padding_len = BLOCK_SIZE - (size_t)j;
                                    break;
                                } else if (sctx->last_decrypted[j] != 0) {
                                    valid = 0;
                                    break;
                                }
                                if (j == 0) {
                                    valid = 0;
                                    break;
                                }
                            }
                            if (padding_len == 0) valid = 0;
                            break;
                    }
                    
                    if (!valid) {
                        memset(sctx->last_decrypted, 0, BLOCK_SIZE);
                        sctx->has_last_decrypted = 0;
                        return -1;
                    }
                    
                    *out_size = BLOCK_SIZE - padding_len;
                    if (*out_size > 0) {
                        memcpy(out, sctx->last_decrypted, *out_size);
                    }
                    
                    memset(sctx->last_decrypted, 0, BLOCK_SIZE);
                    sctx->has_last_decrypted = 0;
                }
            }
            break;
            
        case AES_MODE_CFB128:
            /* 流模式: 无填充, finish 输出缓冲区残留尾块 (keystream XOR) */
            if (sctx->buffer_len > 0) {
                uint8_t stream_block[16];
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                for (j = 0; j < (int)sctx->buffer_len; ++j) {
                    out[j] = sctx->buffer[j] ^ stream_block[j];
                }
                memmove(sctx->feedback, sctx->feedback + sctx->buffer_len,
                        BLOCK_SIZE - sctx->buffer_len);
                memcpy(sctx->feedback + (BLOCK_SIZE - sctx->buffer_len),
                       sctx->is_encrypt ? out : sctx->buffer, sctx->buffer_len);
                *out_size = sctx->buffer_len;
                sctx->buffer_len = 0;
            }
            break;

        case AES_MODE_OFB:
            if (sctx->buffer_len > 0) {
                uint8_t stream_block[16];
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->feedback, stream_block);
                for (j = 0; j < (int)sctx->buffer_len; ++j) {
                    out[j] = sctx->buffer[j] ^ stream_block[j];
                }
                memcpy(sctx->feedback, stream_block, BLOCK_SIZE);
                *out_size = sctx->buffer_len;
                sctx->buffer_len = 0;
            }
            break;

        case AES_MODE_CTR:
            if (sctx->buffer_len > 0) {
                uint8_t stream_block[16];
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
                for (j = 0; j < (int)sctx->buffer_len; ++j) {
                    out[j] = sctx->buffer[j] ^ stream_block[j];
                }
                for (j = BLOCK_SIZE - 1; j >= 0; --j) {
                    if (++sctx->counter[j] != 0) {
                        break;
                    }
                }
                *out_size = sctx->buffer_len;
                sctx->buffer_len = 0;
            }
            break;

        case AES_MODE_CFB8:
            break;

        default:
            break;
    }
    
    memset(padded, 0, BLOCK_SIZE);
    
    return 0;
}

void aes_stream_free(AES_StreamContext* sctx) {
    if (sctx) {
        memset(sctx->iv, 0, BLOCK_SIZE);
        memset(sctx->feedback, 0, BLOCK_SIZE);
        memset(sctx->counter, 0, BLOCK_SIZE);
        memset(sctx->counter_0, 0, BLOCK_SIZE);
        memset(sctx->buffer, 0, BLOCK_SIZE);
        memset(sctx->last_decrypted, 0, BLOCK_SIZE);
        sctx->has_last_decrypted = 0;
        memset(sctx->gcm_h, 0, BLOCK_SIZE);
        memset(sctx->gcm_x, 0, BLOCK_SIZE);
        memset(sctx->ccm_mac, 0, BLOCK_SIZE);
    }
}

int aes_gcm_stream_init(AES_StreamContext* sctx, AES_Context* ctx,
                        const uint8_t* nonce, size_t nonce_size,
                        const uint8_t* aad, size_t aad_size, int is_encrypt) {
    uint8_t zero_block[16] = {0};
    uint8_t len_block[16];
    uint64_t nonce_bits;
    int i;
    
    if (!sctx || !ctx || !nonce) {
        return -1;
    }
    
    if (nonce_size == 0 || nonce_size > 16) {
        return -1;
    }
    
    memset(sctx, 0, sizeof(AES_StreamContext));
    sctx->ctx = ctx;
    sctx->mode = AES_MODE_GCM;
    sctx->is_encrypt = is_encrypt;
    
    Cipher(ctx->w, ctx->Nr, zero_block, sctx->gcm_h);
    gcm_init_table(sctx->gcm_h);   /* 预计算 8-bit M-table, 流式 GHASH 加速 */
    
    if (nonce_size == 12) {
        memcpy(sctx->counter, nonce, 12);
        sctx->counter[15] = 1;
        memcpy(sctx->counter_0, sctx->counter, 16);
    } else {
        memset(sctx->gcm_x, 0, 16);
        stream_gcm_ghash_update(sctx, nonce, nonce_size);
        memset(len_block, 0, 16);
        nonce_bits = (uint64_t)nonce_size << 3;
        for (i = 7; i >= 0; --i) {
            len_block[i + 8] = (uint8_t)(nonce_bits >> (8 * (7 - i)));
        }
        for (i = 0; i < 16; ++i) {
            sctx->gcm_x[i] ^= len_block[i];
        }
        gcm_mult(sctx->gcm_x, sctx->gcm_h);
        memcpy(sctx->counter, sctx->gcm_x, 16);
        memcpy(sctx->counter_0, sctx->counter, 16);
        memset(sctx->gcm_x, 0, 16);
    }
    
    sctx->gcm_aad_len = aad_size;
    if (aad && aad_size > 0) {
        stream_gcm_ghash_update(sctx, aad, aad_size);
    }
    
    return 0;
}

int aes_gcm_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                          uint8_t* out, size_t* out_size) {
    return aes_stream_update(sctx, in, in_size, out, out_size);
}

int aes_gcm_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size,
                          uint8_t* tag, size_t* tag_size) {
    uint8_t encrypted[16];
    uint8_t stream_block[16];
    uint8_t temp[16];
    int i;
    size_t j;
    
    if (!sctx || !out || !out_size || !tag || !tag_size) {
        return -1;
    }
    
    *out_size = 0;
    if (*tag_size > 16) {
        *tag_size = 16;
    }
    
    if (sctx->buffer_len > 0) {
        Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, stream_block);
        
        memset(temp, 0, BLOCK_SIZE);
        for (j = 0; j < sctx->buffer_len; j++) {
            temp[j] = sctx->buffer[j] ^ stream_block[j];
        }
        
        if (sctx->is_encrypt) {
            for (j = 0; j < sctx->buffer_len; j++) {
                out[j] = temp[j];
            }
        } else {
            for (j = 0; j < sctx->buffer_len; j++) {
                out[j] = temp[j];
            }
        }
        *out_size = sctx->buffer_len;
        
        stream_gcm_ghash_update(sctx, sctx->is_encrypt ? out : sctx->buffer, sctx->buffer_len);
        sctx->gcm_data_len += sctx->buffer_len;
        
        memset(stream_block, 0, BLOCK_SIZE);
        memset(temp, 0, BLOCK_SIZE);
    }
    
    stream_gcm_ghash_final(sctx);
    
    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter_0, encrypted);
    for (i = 0; i < 16; ++i) {
        sctx->gcm_x[i] ^= encrypted[i];
    }
    
    memcpy(tag, sctx->gcm_x, *tag_size);
    
    memset(encrypted, 0, BLOCK_SIZE);
    
    return 0;
}

static int ccm_stream_mac_update(AES_StreamContext* sctx, const uint8_t* data, size_t data_len) {
    uint8_t block[16];
    uint8_t temp[16];
    size_t i, j;
    
    if (!sctx || !data) {
        return -1;
    }
    
    for (i = 0; i < data_len; i += 16) {
        memset(block, 0, 16);
        for (j = 0; j < 16 && i + j < data_len; j++) {
            block[j] = data[i + j];
        }
        for (j = 0; j < 16; j++) {
            temp[j] = sctx->ccm_mac[j] ^ block[j];
        }
        Cipher(sctx->ctx->w, sctx->ctx->Nr, temp, sctx->ccm_mac);
    }
    
    return 0;
}

int aes_ccm_stream_init(AES_StreamContext* sctx, AES_Context* ctx,
                        const uint8_t* nonce, size_t nonce_size,
                        const uint8_t* aad, size_t aad_size,
                        size_t total_len, int is_encrypt) {
    uint8_t b0[16] = {0};
    uint8_t aad_block[16];
    uint8_t len_block[16];
    int q;
    int i, j;
    
    if (!sctx || !ctx || !nonce) {
        return -1;
    }
    
    if (nonce_size < 7 || nonce_size > 13) {
        return -1;
    }
    
    memset(sctx, 0, sizeof(AES_StreamContext));
    sctx->ctx = ctx;
    sctx->mode = AES_MODE_CCM;
    sctx->is_encrypt = is_encrypt;
    memcpy(sctx->iv, nonce, nonce_size);
    sctx->ccm_total_len = total_len;
    
    q = 15 - (int)nonce_size;
    sctx->counter[0] = (uint8_t)(q - 1);
    memcpy(sctx->counter + 1, nonce, nonce_size);
    
    b0[0] = (uint8_t)(((aad_size > 0) ? 0x40 : 0x00) | ((16 - 2) << 2) | (q - 1));
    memcpy(b0 + 1, nonce, nonce_size);
    for (i = 7; i >= 0; --i) {
        b0[16 - 1 - i] = (uint8_t)(total_len >> (8 * i));
    }
    
    Cipher(ctx->w, ctx->Nr, b0, sctx->ccm_mac);
    
    if (aad_size > 0 && aad) {
        if (aad_size <= 14) {
            memset(aad_block, 0, 16);
            aad_block[0] = (uint8_t)(aad_size >> 8);
            aad_block[1] = (uint8_t)(aad_size & 0xFF);
            memcpy(aad_block + 2, aad, aad_size);
            for (j = 0; j < 16; ++j) {
                b0[j] = sctx->ccm_mac[j] ^ aad_block[j];
            }
            Cipher(ctx->w, ctx->Nr, b0, sctx->ccm_mac);
        } else if (aad_size < 0xFFFE) {
            memset(len_block, 0, 16);
            len_block[0] = (uint8_t)(aad_size >> 8);
            len_block[1] = (uint8_t)(aad_size & 0xFF);
            for (j = 0; j < 16; ++j) {
                b0[j] = sctx->ccm_mac[j] ^ len_block[j];
            }
            Cipher(ctx->w, ctx->Nr, b0, sctx->ccm_mac);
            
            ccm_stream_mac_update(sctx, aad, aad_size);
        } else {
            memset(aad_block, 0, 16);
            aad_block[0] = 0xFF;
            aad_block[1] = 0xFE;
            for (j = 7; j >= 0; --j) {
                aad_block[16 - 1 - j] = (uint8_t)(aad_size >> (8 * j));
            }
            for (j = 0; j < 16; ++j) {
                b0[j] = sctx->ccm_mac[j] ^ aad_block[j];
            }
            Cipher(ctx->w, ctx->Nr, b0, sctx->ccm_mac);
            
            ccm_stream_mac_update(sctx, aad, aad_size);
        }
    }
    
    sctx->buffer_len = 0;
    
    return 0;
}

int aes_ccm_stream_update(AES_StreamContext* sctx, const uint8_t* in, size_t in_size,
                          uint8_t* out, size_t* out_size) {
    uint8_t keystream[16];
    uint8_t temp[16];
    size_t i;
    int j;
    size_t remaining;
    
    if (!sctx || !in || !out || !out_size) {
        return -1;
    }
    
    *out_size = 0;
    remaining = sctx->buffer_len;
    
    if (sctx->is_encrypt) {
        for (i = 0; i < in_size; i++) {
            sctx->buffer[remaining++] = in[i];
            
            if (remaining == BLOCK_SIZE) {
                ccm_stream_mac_update(sctx, sctx->buffer, BLOCK_SIZE);
                
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
                for (j = 0; j < BLOCK_SIZE; j++) {
                    out[*out_size + j] = sctx->buffer[j] ^ keystream[j];
                }
                *out_size += BLOCK_SIZE;
                
                /* CCM 计数器：q = counter[0] + 1 字节，范围 [15-counter[0], 15] */
                for (j = 15; j >= (int)(15 - sctx->counter[0]); --j) {
                    if (++sctx->counter[j] != 0) {
                        break;
                    }
                }
                remaining = 0;
            }
        }
        sctx->buffer_len = remaining;
    } else {
        for (i = 0; i < in_size; i++) {
            sctx->buffer[remaining++] = in[i];
            
            if (remaining == BLOCK_SIZE) {
                Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
                for (j = 0; j < BLOCK_SIZE; j++) {
                    temp[j] = sctx->buffer[j] ^ keystream[j];
                }
                
                ccm_stream_mac_update(sctx, temp, BLOCK_SIZE);
                
                for (j = 0; j < BLOCK_SIZE; j++) {
                    out[*out_size + j] = temp[j];
                }
                *out_size += BLOCK_SIZE;
                
                /* CCM 计数器：q = counter[0] + 1 字节，范围 [15-counter[0], 15] */
                for (j = 15; j >= (int)(15 - sctx->counter[0]); --j) {
                    if (++sctx->counter[j] != 0) {
                        break;
                    }
                }
                remaining = 0;
            }
        }
        sctx->buffer_len = remaining;
    }
    
    memset(keystream, 0, BLOCK_SIZE);
    memset(temp, 0, BLOCK_SIZE);
    
    return 0;
}

int aes_ccm_stream_finish(AES_StreamContext* sctx, uint8_t* out, size_t* out_size,
                          uint8_t* tag, size_t* tag_size) {
    uint8_t keystream[16];
    uint8_t temp[16];
    uint8_t expected_tag[16] = {0};
    uint8_t result;
    size_t i;
    int j;
    
    if (!sctx || !out || !out_size || !tag || !tag_size) {
        return -1;
    }
    
    *out_size = 0;
    if (*tag_size > 16) {
        *tag_size = 16;
    }
    
    if (sctx->buffer_len > 0) {
        memset(temp, 0, BLOCK_SIZE);
        memcpy(temp, sctx->buffer, sctx->buffer_len);
        
        if (sctx->is_encrypt) {
            ccm_stream_mac_update(sctx, temp, BLOCK_SIZE);
            
            Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
            for (j = 0; j < (int)sctx->buffer_len; j++) {
                out[j] = sctx->buffer[j] ^ keystream[j];
            }
            *out_size = sctx->buffer_len;
        } else {
            Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
            for (j = 0; j < (int)sctx->buffer_len; j++) {
                temp[j] = sctx->buffer[j] ^ keystream[j];
            }
            ccm_stream_mac_update(sctx, temp, BLOCK_SIZE);
            
            for (j = 0; j < (int)sctx->buffer_len; j++) {
                out[j] = temp[j];
            }
            *out_size = sctx->buffer_len;
        }
        
        /* CCM 计数器：q = counter[0] + 1 字节，范围 [15-counter[0], 15] */
        for (j = 15; j >= (int)(15 - sctx->counter[0]); --j) {
            if (++sctx->counter[j] != 0) {
                break;
            }
        }
    }
    
    Cipher(sctx->ctx->w, sctx->ctx->Nr, sctx->counter, keystream);
    
    if (sctx->is_encrypt) {
        for (i = 0; i < *tag_size; i++) {
            tag[i] = sctx->ccm_mac[i] ^ keystream[i];
        }
    } else {
        for (i = 0; i < *tag_size; i++) {
            expected_tag[i] = tag[i] ^ keystream[i];
        }
        
        result = 0;
        for (i = 0; i < *tag_size; i++) {
            result |= sctx->ccm_mac[i] ^ expected_tag[i];
        }
        
        memset(expected_tag, 0, 16);
        
        if (result != 0) {
            memset(keystream, 0, BLOCK_SIZE);
            memset(temp, 0, BLOCK_SIZE);
            return -1;
        }
    }
    
    memset(keystream, 0, BLOCK_SIZE);
    memset(temp, 0, BLOCK_SIZE);
    
    return 0;
}