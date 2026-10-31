#include "aes_file.h"
#include "aes_c.h"
#include "aes_keygen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_BUFFER_SIZE (64 * 1024)

int aes_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                     AES_Mode mode, AES_Padding padding, const uint8_t* iv, size_t iv_size) {
    FILE* in_fp;
    FILE* out_fp;
    AES_StreamContext sctx;
    uint8_t in_buffer[FILE_BUFFER_SIZE];
    uint8_t out_buffer[FILE_BUFFER_SIZE + BLOCK_SIZE];
    size_t bytes_read;
    size_t bytes_written;
    size_t out_size;
    int result;
    
    if (!ctx || !in_filename || !out_filename) {
        return -1;
    }
    
    in_fp = fopen(in_filename, "rb");
    if (!in_fp) {
        return -1;
    }
    
    out_fp = fopen(out_filename, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return -1;
    }
    
    result = aes_stream_init(&sctx, ctx, mode, padding, iv, iv_size, 1);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        remove(out_filename);
        return -1;
    }
    
    while ((bytes_read = fread(in_buffer, 1, FILE_BUFFER_SIZE, in_fp)) > 0) {
        result = aes_stream_update(&sctx, in_buffer, bytes_read, out_buffer, &out_size);
        if (result != 0) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    result = aes_stream_finish(&sctx, out_buffer, &out_size);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        aes_stream_free(&sctx);
        remove(out_filename);
        return -1;
    }
    if (out_size > 0) {
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    aes_stream_free(&sctx);
    fclose(in_fp);
    fclose(out_fp);
    
    return 0;
}

int aes_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                     AES_Mode mode, AES_Padding padding, const uint8_t* iv, size_t iv_size) {
    FILE* in_fp;
    FILE* out_fp;
    AES_StreamContext sctx;
    uint8_t in_buffer[FILE_BUFFER_SIZE];
    uint8_t out_buffer[FILE_BUFFER_SIZE];
    size_t bytes_read;
    size_t bytes_written;
    size_t out_size;
    int result;
    
    if (!ctx || !in_filename || !out_filename) {
        return -1;
    }
    
    in_fp = fopen(in_filename, "rb");
    if (!in_fp) {
        return -1;
    }
    
    out_fp = fopen(out_filename, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return -1;
    }
    
    result = aes_stream_init(&sctx, ctx, mode, padding, iv, iv_size, 0);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        remove(out_filename);
        return -1;
    }
    
    while ((bytes_read = fread(in_buffer, 1, FILE_BUFFER_SIZE, in_fp)) > 0) {
        result = aes_stream_update(&sctx, in_buffer, bytes_read, out_buffer, &out_size);
        if (result != 0) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    result = aes_stream_finish(&sctx, out_buffer, &out_size);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        aes_stream_free(&sctx);
        remove(out_filename);
        return -1;
    }
    if (out_size > 0) {
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    aes_stream_free(&sctx);
    fclose(in_fp);
    fclose(out_fp);
    
    return 0;
}

int aes_gcm_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t* tag_size) {
    FILE* in_fp;
    FILE* out_fp;
    AES_StreamContext sctx;
    uint8_t in_buffer[FILE_BUFFER_SIZE];
    uint8_t out_buffer[FILE_BUFFER_SIZE];
    size_t bytes_read;
    size_t bytes_written;
    size_t out_size;
    int result;
    
    if (!ctx || !in_filename || !out_filename || !nonce || !tag || !tag_size) {
        return -1;
    }
    
    in_fp = fopen(in_filename, "rb");
    if (!in_fp) {
        return -1;
    }
    
    out_fp = fopen(out_filename, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return -1;
    }
    
    result = aes_gcm_stream_init(&sctx, ctx, nonce, nonce_size, aad, aad_size, 1);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        remove(out_filename);
        return -1;
    }
    
    while ((bytes_read = fread(in_buffer, 1, FILE_BUFFER_SIZE, in_fp)) > 0) {
        result = aes_gcm_stream_update(&sctx, in_buffer, bytes_read, out_buffer, &out_size);
        if (result != 0) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    result = aes_gcm_stream_finish(&sctx, out_buffer, &out_size, tag, tag_size);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        aes_stream_free(&sctx);
        remove(out_filename);
        return -1;
    }
    if (out_size > 0) {
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    aes_stream_free(&sctx);
    fclose(in_fp);
    fclose(out_fp);
    
    return 0;
}

int aes_gcm_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size) {
    FILE* in_fp;
    FILE* out_fp;
    AES_StreamContext sctx;
    uint8_t in_buffer[FILE_BUFFER_SIZE];
    uint8_t out_buffer[FILE_BUFFER_SIZE];
    uint8_t computed_tag[16];
    size_t computed_tag_size;
    size_t bytes_read;
    size_t bytes_written;
    size_t out_size;
    int result;
    uint8_t verify;
    int i;
    
    if (!ctx || !in_filename || !out_filename || !nonce || !tag) {
        return -1;
    }
    
    in_fp = fopen(in_filename, "rb");
    if (!in_fp) {
        return -1;
    }
    
    out_fp = fopen(out_filename, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return -1;
    }
    
    result = aes_gcm_stream_init(&sctx, ctx, nonce, nonce_size, aad, aad_size, 0);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        remove(out_filename);
        return -1;
    }
    
    while ((bytes_read = fread(in_buffer, 1, FILE_BUFFER_SIZE, in_fp)) > 0) {
        result = aes_gcm_stream_update(&sctx, in_buffer, bytes_read, out_buffer, &out_size);
        if (result != 0) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    computed_tag_size = 16;
    result = aes_gcm_stream_finish(&sctx, out_buffer, &out_size, computed_tag, &computed_tag_size);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        aes_stream_free(&sctx);
        remove(out_filename);
        return -1;
    }
    if (out_size > 0) {
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    verify = 0;
    for (i = 0; i < (int)tag_size; i++) {
        verify |= computed_tag[i] ^ tag[i];
    }
    
    aes_stream_free(&sctx);
    
    if (verify != 0) {
        fclose(in_fp);
        fclose(out_fp);
        remove(out_filename);
        return -1;
    }
    
    fclose(in_fp);
    fclose(out_fp);
    
    return 0;
}

int aes_ccm_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         uint8_t* tag, size_t* tag_size) {
    FILE* in_fp;
    FILE* out_fp;
    AES_StreamContext sctx;
    uint8_t in_buffer[FILE_BUFFER_SIZE];
    uint8_t out_buffer[FILE_BUFFER_SIZE];
    size_t file_size;
    size_t bytes_read;
    size_t bytes_written;
    size_t out_size;
    int result;
    
    if (!ctx || !in_filename || !out_filename || !nonce || !tag || !tag_size) {
        return -1;
    }
    
    in_fp = fopen(in_filename, "rb");
    if (!in_fp) {
        return -1;
    }
    
    fseek(in_fp, 0, SEEK_END);
    file_size = (size_t)ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    out_fp = fopen(out_filename, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return -1;
    }
    
    result = aes_ccm_stream_init(&sctx, ctx, nonce, nonce_size, aad, aad_size, file_size, 1);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        remove(out_filename);
        return -1;
    }
    
    while ((bytes_read = fread(in_buffer, 1, FILE_BUFFER_SIZE, in_fp)) > 0) {
        result = aes_ccm_stream_update(&sctx, in_buffer, bytes_read, out_buffer, &out_size);
        if (result != 0) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    result = aes_ccm_stream_finish(&sctx, out_buffer, &out_size, tag, tag_size);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        aes_stream_free(&sctx);
        remove(out_filename);
        return -1;
    }
    if (out_size > 0) {
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    aes_stream_free(&sctx);
    fclose(in_fp);
    fclose(out_fp);
    
    return 0;
}

int aes_ccm_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* nonce, size_t nonce_size,
                         const uint8_t* aad, size_t aad_size,
                         const uint8_t* tag, size_t tag_size) {
    FILE* in_fp;
    FILE* out_fp;
    AES_StreamContext sctx;
    uint8_t in_buffer[FILE_BUFFER_SIZE];
    uint8_t out_buffer[FILE_BUFFER_SIZE];
    size_t file_size;
    size_t bytes_read;
    size_t bytes_written;
    size_t out_size;
    int result;
    
    if (!ctx || !in_filename || !out_filename || !nonce || !tag) {
        return -1;
    }
    
    in_fp = fopen(in_filename, "rb");
    if (!in_fp) {
        return -1;
    }
    
    fseek(in_fp, 0, SEEK_END);
    file_size = (size_t)ftell(in_fp);
    fseek(in_fp, 0, SEEK_SET);
    
    out_fp = fopen(out_filename, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return -1;
    }
    
    result = aes_ccm_stream_init(&sctx, ctx, nonce, nonce_size, aad, aad_size, file_size, 0);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        remove(out_filename);
        return -1;
    }
    
    while ((bytes_read = fread(in_buffer, 1, FILE_BUFFER_SIZE, in_fp)) > 0) {
        result = aes_ccm_stream_update(&sctx, in_buffer, bytes_read, out_buffer, &out_size);
        if (result != 0) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    result = aes_ccm_stream_finish(&sctx, out_buffer, &out_size, (uint8_t*)tag, (size_t*)&tag_size);
    if (result != 0) {
        fclose(in_fp);
        fclose(out_fp);
        aes_stream_free(&sctx);
        remove(out_filename);
        return -1;
    }
    if (out_size > 0) {
        bytes_written = fwrite(out_buffer, 1, out_size, out_fp);
        if (bytes_written != out_size) {
            fclose(in_fp);
            fclose(out_fp);
            aes_stream_free(&sctx);
            remove(out_filename);
            return -1;
        }
    }
    
    aes_stream_free(&sctx);
    fclose(in_fp);
    fclose(out_fp);
    
    return 0;
}

int aes_ecb_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         AES_Padding padding) {
    return aes_encrypt_file(ctx, in_filename, out_filename, AES_MODE_ECB, padding, NULL, 0);
}

int aes_ecb_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         AES_Padding padding) {
    return aes_decrypt_file(ctx, in_filename, out_filename, AES_MODE_ECB, padding, NULL, 0);
}

int aes_cbc_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size, AES_Padding padding) {
    return aes_encrypt_file(ctx, in_filename, out_filename, AES_MODE_CBC, padding, iv, iv_size);
}

int aes_cbc_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size, AES_Padding padding) {
    return aes_decrypt_file(ctx, in_filename, out_filename, AES_MODE_CBC, padding, iv, iv_size);
}

int aes_cfb8_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                          const uint8_t* iv, size_t iv_size) {
    return aes_encrypt_file(ctx, in_filename, out_filename, AES_MODE_CFB8, AES_PADDING_NONE, iv, iv_size);
}

int aes_cfb8_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                          const uint8_t* iv, size_t iv_size) {
    return aes_decrypt_file(ctx, in_filename, out_filename, AES_MODE_CFB8, AES_PADDING_NONE, iv, iv_size);
}

int aes_cfb128_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                            const uint8_t* iv, size_t iv_size, AES_Padding padding) {
    return aes_encrypt_file(ctx, in_filename, out_filename, AES_MODE_CFB128, padding, iv, iv_size);
}

int aes_cfb128_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                            const uint8_t* iv, size_t iv_size, AES_Padding padding) {
    return aes_decrypt_file(ctx, in_filename, out_filename, AES_MODE_CFB128, padding, iv, iv_size);
}

int aes_ofb_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size) {
    return aes_encrypt_file(ctx, in_filename, out_filename, AES_MODE_OFB, AES_PADDING_NONE, iv, iv_size);
}

int aes_ofb_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size) {
    return aes_decrypt_file(ctx, in_filename, out_filename, AES_MODE_OFB, AES_PADDING_NONE, iv, iv_size);
}

int aes_ctr_encrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size) {
    return aes_encrypt_file(ctx, in_filename, out_filename, AES_MODE_CTR, AES_PADDING_NONE, iv, iv_size);
}

int aes_ctr_decrypt_file(AES_Context* ctx, const char* in_filename, const char* out_filename,
                         const uint8_t* iv, size_t iv_size) {
    return aes_decrypt_file(ctx, in_filename, out_filename, AES_MODE_CTR, AES_PADDING_NONE, iv, iv_size);
}

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif

int aes_secure_delete_file(const char* filename, int passes) {
    FILE* fp;
    uint8_t buffer[FILE_BUFFER_SIZE];
    size_t file_size;
    size_t bytes_written;
    size_t remaining;
    size_t i;
    int p;
    
    if (!filename || passes < 1) {
        return -1;
    }
    
    fp = fopen(filename, "r+b");
    if (!fp) {
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    file_size = (size_t)ftell(fp);
    if (file_size == 0) {
        fclose(fp);
        remove(filename);
        return 0;
    }
    fseek(fp, 0, SEEK_SET);
    
    for (p = 0; p < passes; p++) {
        switch (p % 3) {
            case 0:
                memset(buffer, 0x00, FILE_BUFFER_SIZE);
                break;
            case 1:
                memset(buffer, 0xFF, FILE_BUFFER_SIZE);
                break;
            case 2:
                aes_random_bytes(buffer, FILE_BUFFER_SIZE);
                break;
        }
        
        remaining = file_size;
        while (remaining > 0) {
            bytes_written = fwrite(buffer, 1, remaining > FILE_BUFFER_SIZE ? FILE_BUFFER_SIZE : remaining, fp);
            if (bytes_written != (remaining > FILE_BUFFER_SIZE ? FILE_BUFFER_SIZE : remaining)) {
                fclose(fp);
                return -1;
            }
            remaining -= bytes_written;
        }
        
        fflush(fp);
        
        #if defined(_WIN32) || defined(_WIN64)
        {
            HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(hFile);
                CloseHandle(hFile);
            }
        }
        #else
        fsync(fileno(fp));
        #endif
        
        fseek(fp, 0, SEEK_SET);
    }
    
    memset(buffer, 0x00, FILE_BUFFER_SIZE);
    
    fclose(fp);
    
    return remove(filename) == 0 ? 0 : -1;
}

int aes_zero_fill_delete_file(const char* filename) {
    FILE* fp;
    uint8_t buffer[FILE_BUFFER_SIZE];
    size_t file_size;
    size_t bytes_written;
    size_t remaining;
    
    if (!filename) {
        return -1;
    }
    
    fp = fopen(filename, "r+b");
    if (!fp) {
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    file_size = (size_t)ftell(fp);
    if (file_size == 0) {
        fclose(fp);
        remove(filename);
        return 0;
    }
    fseek(fp, 0, SEEK_SET);
    
    memset(buffer, 0x00, FILE_BUFFER_SIZE);
    
    remaining = file_size;
    while (remaining > 0) {
        bytes_written = fwrite(buffer, 1, remaining > FILE_BUFFER_SIZE ? FILE_BUFFER_SIZE : remaining, fp);
        if (bytes_written != (remaining > FILE_BUFFER_SIZE ? FILE_BUFFER_SIZE : remaining)) {
            fclose(fp);
            return -1;
        }
        remaining -= bytes_written;
    }
    
    fflush(fp);
    
    #if defined(_WIN32) || defined(_WIN64)
    {
        HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(hFile);
            CloseHandle(hFile);
        }
    }
    #else
    fsync(fileno(fp));
    #endif
    
    memset(buffer, 0x00, FILE_BUFFER_SIZE);
    
    fclose(fp);
    
    return remove(filename) == 0 ? 0 : -1;
}