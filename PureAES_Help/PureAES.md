# PureAES 库使用文档

> 一个全模式、全位数、支持 AES 硬件指令集（AES-NI / ARM NEON）与纯软件实现的双路径 AES 加解密库。
> 适用版本：MinGW-w64 / MSYS2 GCC（推荐 13.2.0），实测兼容 MinGW.org GCC 9.2.0。

---

## 目录
1. [库文件清单](#1-库文件清单)
2. [编译与链接](#2-编译与链接)
3. [头文件与基础概念](#3-头文件与基础概念)
4. [第一个程序：加密与解密](#4-第一个程序加密与解密)
5. [支持的加密模式](#5-支持的加密模式)
6. [填充机制](#6-填充机制)
7. [密钥与 IV 生成](#7-密钥与-iv-生成)
8. [GCM / CCM 认证加密](#8-gcm--ccm-认证加密)
9. [XTS 磁盘加密模式](#9-xts-磁盘加密模式)
10. [HEX / Base64 编解码](#10-hex--base64-编解码)
11. [文件加解密](#11-文件加解密)
12. [流式接口（大文件 / 增量处理）](#12-流式接口大文件--增量处理)
13. [硬件加速说明](#13-硬件加速说明)
14. [常见问题与安全注意事项](#14-常见问题与安全注意事项)

---

## 1. 库文件清单

编译产物位于 `build/` 目录：

| 文件 | 类型 | 说明 |
|------|------|------|
| `pureaes.lib` | 静态库 | MinGW 链接器可直接使用（已验证） |
| `libpureaes.a` | 静态库 | 与 `.lib` 内容等价 |
| `pureaes.dll` | 动态库 | 运行时需与 exe 同目录或加入 PATH |
| `libpureaes.dll.a` | 导入库 | 链接 `pureaes.dll` 时使用 |

源码（编译进库的 5 个文件）：

```
aes_c.c / aes_c.h          ← AES 算法核心（模式、轮函数、硬件加速、流式接口）
aes_file.c / aes_file.h    ← 文件级加解密封装
aes_keygen.c / aes_keygen.h← 安全随机密钥/IV 生成
hex_convert.c / hex_convert.h   ← HEX 编解码
base64_convert.c / base64_convert.h ← Base64 编解码
```

---

## 2. 编译与链接

### 2.1 编译库（可选，已有产物可跳过）

```bash
# 编译对象文件（-maes -msse2 -mpclmul 是启用硬件加速的关键，必须全局加）
gcc -O2 -maes -msse2 -mpclmul -c aes_c.c aes_file.c aes_keygen.c hex_convert.c base64_convert.c

# 静态库
ar rcs pureaes.lib aes_c.o aes_file.o aes_keygen.o hex_convert.o base64_convert.o

# 动态库 + 导入库（注意：PowerShell 里 -Wl 参数要加引号）
gcc -shared -O2 -maes -msse2 -mpclmul -o pureaes.dll \
    aes_c.o aes_file.o aes_keygen.o hex_convert.o base64_convert.o \
    "-Wl,--out-implib,libpureaes.dll.a" "-Wl,--export-all-symbols"
```

### 2.2 链接到你的程序

**方式 A：静态链接（推荐，单 exe 免依赖）**

```bash
gcc -O2 -maes -msse2 -mpclmul -I<PureAES目录> your_program.c pureaes.lib -o your_program.exe
```

**方式 B：动态链接（依赖 pureaes.dll）**

```bash
gcc -O2 -I<PureAES目录> your_program.c -L<build目录> -lpureaes -o your_program.exe
# 运行：把 pureaes.dll 放到 exe 同目录
```

> `-I` 指向包含 `aes_c.h` 的目录；`.lib` 是静态库，直接写路径即可，不需要 `-L/-l`。

---

## 3. 头文件与基础概念

```c
#include "aes_c.h"
#include "aes_file.h"    // 用文件加解密时才需要
#include "aes_keygen.h"  // 用随机密钥生成时才需要
```

### 3.1 密钥长度（全位数）

```c
typedef enum {
    AES_128 = 16,   // 128 位，10 轮
    AES_192 = 24,   // 192 位，12 轮
    AES_256 = 32    // 256 位，14 轮
} AES_KeyLength;
```

### 3.2 加密模式（全模式）

```c
typedef enum {
    AES_MODE_ECB     = 0,  // 电子密码本（不安全，仅演示）
    AES_MODE_CBC     = 1,  // 密码分组链接（需要 IV）
    AES_MODE_CFB8    = 2,  // 8 位密码反馈
    AES_MODE_CFB128  = 3,  // 128 位密码反馈（需要 IV）
    AES_MODE_OFB     = 4,  // 输出反馈（需要 IV）
    AES_MODE_CTR     = 5,  // 计数器模式（需要 IV/nonce）
    AES_MODE_GCM     = 6,  // Galois 认证模式（推荐，认证加密）
    AES_MODE_CCM     = 7,  // Counter 认证模式（认证加密）
    AES_MODE_XTS     = 8   // 磁盘加密模式（需要 tweak）
} AES_Mode;
```

### 3.3 填充方式

```c
typedef enum {
    AES_PADDING_NONE     = 0,  // 不填充，数据必须是 16 字节整数倍
    AES_PADDING_ZERO     = 1,  // 补 0x00
    AES_PADDING_PKCS5    = 2,  // PKCS#5（与 PKCS#7 相同）
    AES_PADDING_PKCS7    = 3,  // PKCS#7（最常用）
    AES_PADDING_ANSIX923 = 4,  // ANSI X.923
    AES_PADDING_ISO10126 = 5,  // ISO 10126
    AES_PADDING_ISO7816  = 6   // ISO/IEC 7816-4
} AES_Padding;
```

### 3.4 上下文结构

```c
typedef struct {
    int Nk;                 // 密钥字组数（4/6/8）
    int Nr;                 // 轮数（10/12/14）
    uint8_t* w;             // 原始轮密钥
    uint8_t* dw;            // AES-NI 专用解密等效轮密钥
    uint32_t hw_flags;      // 硬件能力（AES_HW_NI / AES_HW_PCLMUL / AES_HW_NEON）
    AES_KeyLength key_len;
    uint8_t iv[16];
    int iv_set;
} AES_Context;
```

**核心流程三步曲：`aes_init`（初始化）→ `aes_encrypt/decrypt`（加解密）→ `aes_free`（释放）**

> 所有 `aes_encrypt/aes_decrypt/aes_bytes_to_hex` 等返回的指针都**需要调用 `free()` 释放**，否则内存泄漏。

---

## 4. 第一个程序：加密与解密

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aes_c.h"

int main(void) {
    AES_Context ctx;

    /* AES-128 密钥（16 字节）与 IV（16 字节） */
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t iv[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

    const char* msg = "Hello, PureAES!";
    size_t out_size;
    uint8_t *cipher, *plain;
    int i;

    /* 1. 初始化上下文 */
    if (aes_init(&ctx, AES_128, key, sizeof(key), iv, sizeof(iv)) != 0) {
        printf("aes_init failed\n");
        return 1;
    }
    printf("hw_flags = 0x%08x, Nr = %d\n", ctx.hw_flags, ctx.Nr);

    /* 2. 加密（CBC + PKCS7 填充） */
    cipher = aes_encrypt(&ctx, (const uint8_t*)msg, strlen(msg),
                         AES_MODE_CBC, AES_PADDING_PKCS7, iv, sizeof(iv), &out_size);
    if (!cipher) { printf("encrypt failed\n"); return 1; }
    printf("cipher (%d bytes): ", (int)out_size);
    for (i = 0; i < (int)out_size; i++) printf("%02x", cipher[i]);
    printf("\n");

    /* 3. 解密（必须用相同的密钥、IV、模式、填充） */
    plain = aes_decrypt(&ctx, cipher, out_size,
                        AES_MODE_CBC, AES_PADDING_PKCS7, iv, sizeof(iv), &out_size);
    if (!plain) { printf("decrypt failed\n"); return 1; }
    printf("plain: %.*s\n", (int)out_size, plain);

    /* 4. 释放 */
    free(cipher);
    free(plain);
    aes_free(&ctx);
    return 0;
}
```

**编译运行：**
```bash
gcc -O2 -maes -msse2 -mpclmul -I. demo1.c pureaes.lib -o demo1.exe && demo1.exe
```

**输出示例：**
```
hw_flags = 0x00000003, Nr = 10
cipher (32 bytes): <16字节随机密文><16字节>
plain: Hello, PureAES!
```

---

## 5. 支持的加密模式

除 ECB 外，流模式（CBC/CFB/OFB/CTR）都**必须传入 16 字节 IV**。

| 模式 | IV/nonce 要求 | 是否认证 | 典型用途 |
|------|--------------|---------|---------|
| ECB | 无 | 否 | 不推荐（相同明文→相同密文） |
| CBC | 16 字节 IV | 否 | 通用数据加密 |
| CFB8 | 16 字节 IV | 否 | 逐字节流加密 |
| CFB128 | 16 字节 IV | 否 | 流式加密 |
| OFB | 16 字节 IV | 否 | 流式加密 |
| CTR | 16 字节 nonce | 否 | 高速并行加密 |
| GCM | 12 字节 nonce（推荐） | **是** | 网络协议、认证加密 |
| CCM | nonce | **是** | 无线协议 |
| XTS | tweak（通常 16 字节） | 否 | 磁盘全盘加密 |

**统一的调用方式**（以 CTR 为例）：

```c
/* 加密 */
cipher = aes_encrypt(&ctx, data, data_len,
                     AES_MODE_CTR, AES_PADDING_NONE, nonce, 16, &out_size);
/* 解密（CTR 是流模式，无需填充） */
plain = aes_decrypt(&ctx, cipher, out_size,
                    AES_MODE_CTR, AES_PADDING_NONE, nonce, 16, &out_size);
```

> **提醒**：流模式（CTR/OFB/CFB）下加解密使用同一个函数方向的 IV/nonce；`AES_PADDING_NONE` 对任意长度数据都安全（流模式不做分块填充）。

---

## 6. 填充机制

填充**只对分组模式（ECB/CBC/CFB128）有意义**，用于把数据补齐到 16 字节整数倍。

- **`AES_PADDING_NONE`**：不填充。数据长度必须是 16 的倍数，否则报错。
- **`AES_PADDING_PKCS7`**（最常用）：缺 n 字节就补 n 个 `0x0n`。
- 加密用哪种填充，解密必须用**同一种**。

```c
/* PKCS7：明文 5 字节 → 加密后补到 16 字节；解密自动去掉填充 */
cipher = aes_encrypt(&ctx, (uint8_t*)"hello", 5,
                     AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &out_size);
/* out_size 会是 16（5 + 11 字节填充） */
plain = aes_decrypt(&ctx, cipher, out_size,
                    AES_MODE_CBC, AES_PADDING_PKCS7, iv, 16, &out_size);
/* 解密后 out_size 恢复为 5 */
```

---

## 7. 密钥与 IV 生成

```c
#include "aes_keygen.h"

/* 生成 32 字节（AES-256）随机密钥 */
uint8_t* key = aes_generate_key(32);      // 返回 malloc 内存，用完 free
/* 生成 16 字节随机 IV */
uint8_t* iv  = aes_generate_iv(16);

/* 或写入已有缓冲区（推荐，避免额外 malloc） */
uint8_t keybuf[32], ivbuf[16];
aes_random_bytes(keybuf, 32);
aes_random_bytes(ivbuf, 16);

/* 用完释放 */
free(key);
free(iv);
```

> `aes_random_bytes` 使用系统安全随机源（Windows 上基于 `rand_s`/`CryptGenRandom`），**不要用 `rand()`**。

---

## 8. GCM / CCM 认证加密

GCM/CCM 是**认证加密模式**：既能加密又能校验完整性，是网络传输场景的推荐选择。

### 8.1 GCM

```c
uint8_t nonce[12] = {0};           // GCM 推荐 12 字节 nonce
uint8_t aad[] = "header info";     // 附加认证数据（可选，可为空）
uint8_t tag[16];                   // 认证标签缓冲区
size_t out_size;

/* 加密：返回密文，tag 填入 tag[] */
uint8_t* cipher = aes_gcm_encrypt(&ctx, plaintext, plain_len,
                                  nonce, sizeof(nonce),
                                  aad, strlen((char*)aad),
                                  tag, sizeof(tag), &out_size);

/* 传输：把密文 + tag + nonce 一起发给接收方 */
/* 解密：校验 tag，tag 不对说明被篡改 */
uint8_t* plain = aes_gcm_decrypt(&ctx, cipher, out_size,
                                 nonce, sizeof(nonce),
                                 aad, strlen((char*)aad),
                                 tag, sizeof(tag), &out_size);
if (!plain) printf("认证失败！数据被篡改或密钥错误\n");
else printf("认证通过，明文：%.*s\n", (int)out_size, plain);
```

### 8.2 CCM

```c
uint8_t nonce[13] = {0};
uint8_t tag[16];
size_t out_size;

uint8_t* cipher = aes_ccm_encrypt(&ctx, plaintext, plain_len,
                                  nonce, sizeof(nonce),
                                  aad, aad_len, tag, sizeof(tag), &out_size);

uint8_t* plain = aes_ccm_decrypt(&ctx, cipher, out_size,
                                 nonce, sizeof(nonce),
                                 aad, aad_len, tag, sizeof(tag), &out_size);
if (!plain) printf("CCM 认证失败\n");
```

---

## 9. XTS 磁盘加密模式

XTS 用于**磁盘/存储加密**（BitLocker、dm-crypt 同款原理），特点：可随机访问扇区、不需要填充。

```c
uint8_t main_key[32]  = {0};   // 主密钥（AES-256）
uint8_t tweak_key[32] = {0};   // 第二把密钥，长度须等于主密钥
uint8_t tweak[16]     = {0};   // tweak，通常 = nonce || sector_number

size_t out_size;
/* 加密单个扇区（4096 字节） */
uint8_t* ct = aes_xts_encrypt(&ctx, sector, 4096,
                              tweak_key, tweak, sizeof(tweak), &out_size);
/* 解密同一扇区 */
uint8_t* pt = aes_xts_decrypt(&ctx, ct, out_size,
                              tweak_key, tweak, sizeof(tweak), &out_size);

/* 也可以只用一个密钥（tweak_key 传 NULL，复用主密钥） */
ct = aes_xts_encrypt(&ctx, sector, 4096, NULL, tweak, sizeof(tweak), &out_size);
```

> XTS 对**不足 16 字节的末段**会自动做 ciphertext-stealing 处理，`AES_PADDING_NONE` 即可。

---

## 10. HEX / Base64 编解码

用于把二进制密文转成可打印/可传输的文本。

```c
#include "hex_convert.h"
#include "base64_convert.h"

/* HEX */
char* hex = hex_to_string(cipher, out_size);      // 密文 → "1a2b3c..."
uint8_t* bin = string_to_hex(hex, &len);          // 转回二进制
free(hex); free(bin);

/* Base64 */
char* b64 = base64_encode(cipher, out_size);      // 密文 → "AQID..."
uint8_t* bin2 = base64_decode(b64, &len);
free(b64); free(bin2);
```

> 返回的 `char*`/`uint8_t*` 都由库 malloc，**必须 free**。

---

## 11. 文件加解密

```c
#include "aes_file.h"

/* CBC 加密文件 */
if (aes_cbc_encrypt_file(&ctx, "in.txt", "out.enc", iv, 16, AES_PADDING_PKCS7) == 0)
    printf("加密成功\n");

/* CBC 解密文件 */
if (aes_cbc_decrypt_file(&ctx, "out.enc", "restored.txt", iv, 16, AES_PADDING_PKCS7) == 0)
    printf("解密成功\n");

/* 通用入口（任意模式） */
aes_encrypt_file(&ctx, "in.bin", "out.bin", AES_MODE_CTR, AES_PADDING_NONE, iv, 16);
aes_decrypt_file(&ctx, "out.bin", "back.bin", AES_MODE_CTR, AES_PADDING_NONE, iv, 16);

/* GCM 文件（带认证标签） */
uint8_t tag[16]; size_t tag_len = 16;
aes_gcm_encrypt_file(&ctx, "in.bin", "out.bin", nonce, 12, aad, aad_len, tag, &tag_len);
aes_gcm_decrypt_file(&ctx, "out.bin", "back.bin", nonce, 12, aad, aad_len, tag, &tag_len);

/* 安全删除：覆写多次再删除 */
aes_secure_delete_file("secret.txt", 3);   // 3 次覆写后删除
/* 或零填充覆写后删除 */
aes_zero_fill_delete_file("secret.txt");
```

各模式的专用文件接口（同签名）：
`aes_ecb_encrypt_file`、`aes_cbc_encrypt_file`、`aes_cfb8_encrypt_file`、`aes_cfb128_encrypt_file`、`aes_ofb_encrypt_file`、`aes_ctr_encrypt_file`，以及对应的 `*_decrypt_file`。

---

## 12. 流式接口（大文件 / 增量处理）

用于无法一次性加载的内存或需要增量加解密的场景（如网络流、大文件）。

```c
AES_StreamContext sctx;

/* 初始化（加解密方向由 is_encrypt 决定） */
aes_stream_init(&sctx, &ctx, AES_MODE_CTR, AES_PADDING_NONE, iv, 16, 1 /* 加密 */);

uint8_t in[4096], out[4096];
size_t in_len, out_len;

while (读取数据到 in, in_len) {
    aes_stream_update(&sctx, in, in_len, out, &out_len);
    写出 out, out_len;
}

/* 收尾：处理填充/输出剩余块 */
aes_stream_finish(&sctx, out, &out_len);
写出 out, out_len;
aes_stream_free(&sctx);
```

GCM/CCM 也有流式版本：
```c
aes_gcm_stream_init(&sctx, &ctx, nonce, nonce_size, aad, aad_size, is_encrypt);
aes_gcm_stream_update(&sctx, in, in_len, out, &out_len);
aes_gcm_stream_finish(&sctx, out, &out_len, tag, &tag_len);

aes_ccm_stream_init(&sctx, &ctx, nonce, nonce_size, aad, aad_size, total_len, is_encrypt);
aes_ccm_stream_update(&sctx, in, in_len, out, &out_len);
aes_ccm_stream_finish(&sctx, out, &out_len, tag, &tag_len);
```

> `aes_ccm_stream_init` 需要传入**总明文长度 `total_len`**（CCM 规范要求）。

---

## 13. 硬件加速说明

库自动检测 CPU 能力并选择最快的实现路径，**无需手动开关**。

| 硬件标志 | 含义 |
|---------|------|
| `AES_HW_NI` (0x01) | x86 AES-NI（CPUID ECX.25） |
| `AES_HW_PCLMUL` (0x02) | PCLMULQDQ，加速 GCM/GMAC |
| `AES_HW_NEON` (0x04) | ARMv8 NEON AES 扩展 |

- 初始化后读 `ctx.hw_flags`：`0x03` = 支持 AES-NI + PCLMUL。
- **编译时**必须加 `-maes -msse2 -mpclmul`，否则 `AES_HAS_WMMINTRIN` 为 0，代码自动退化为纯 C 实现（此时 `hw_flags` 仍可能置位，但硬件代码被裁掉，走纯软件）。
- 若想强制纯软件路径（如跨平台测试），把 `ctx.hw_flags = 0` 即可。

---

## 14. 常见问题与安全注意事项

### 常见问题

| 问题 | 原因 / 解决 |
|------|------------|
| 解密出来乱码 | 密钥、IV、模式、填充任一不一致 |
| `hw_flags` 显示 0x00 | 编译时没加 `-maes`，走纯软件 |
| 返回 NULL | 数据长度非 16 倍数却用 `PADDING_NONE`；或 GCM tag 校验失败 |
| 内存泄漏 | 忘 `free()` 加密/解密/编解码返回的指针 |
| DLL 找不到 | `pureaes.dll` 未放 exe 同目录，或未加 PATH |

### 安全注意事项（重要）

1. **IV/nonce 每次加密都要换新的**（随机生成），绝不能复用，否则 CTR/GCM 会泄露信息。
2. **ECB 模式不要用于真实数据**，相同明文块会产生相同密文块，模式本身不安全。
3. **优先用 GCM/CCM**：它们提供完整性校验，能检测数据被篡改。
4. **密钥妥善保管**：密钥是唯一秘密，IV/tweak 可以公开。
5. **流模式下 IV 泄露不影响安全**，但 GCM 下 IV 复用是致命漏洞。
6. 安全删除文件：先用 `aes_secure_delete_file` 多次覆写再删，或对敏感数据用加密存储。
7. 不要用 `rand()` 生成密钥，务必用 `aes_generate_key`/`aes_random_bytes` 这类安全随机源。

---

## 附：完整的 AES 上下文生命周期

```
aes_init()              初始化（填充 w/dw 轮密钥，检测硬件）
   │
   ├── aes_encrypt()    一次性加密 → free()
   ├── aes_decrypt()    一次性解密 → free()
   ├── aes_gcm_encrypt/decrypt()  认证加密 → free()
   ├── aes_xts_encrypt/decrypt()  磁盘模式 → free()
   ├── *_file()         文件加解密
   └── aes_stream_init() → update() → finish() → free()
aes_free()              释放轮密钥内存
```

> 一个 `AES_Context` 可在 `aes_init` 后重复用于多次加解密；换密钥时重新 `aes_init` 即可。
