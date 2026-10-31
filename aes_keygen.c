#include "aes_keygen.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)

#if !defined(NTSTATUS)
typedef long NTSTATUS;
#endif

#if !defined(STATUS_SUCCESS)
#define STATUS_SUCCESS 0
#endif

#include <windows.h>

static int win32_random_bytes(uint8_t* buffer, size_t size) {
    HMODULE hModule;
    typedef NTSTATUS (WINAPI* BCryptOpenAlgorithmProviderFunc)(void**, const char*, const char*, unsigned long);
    typedef NTSTATUS (WINAPI* BCryptGenRandomFunc)(void*, unsigned char*, unsigned long, unsigned long);
    typedef NTSTATUS (WINAPI* BCryptCloseAlgorithmProviderFunc)(void*, unsigned long);
    typedef int (WINAPI* RtlGenRandomFunc)(void*, unsigned long);
    BCryptOpenAlgorithmProviderFunc pBCryptOpenAlgorithmProvider;
    BCryptGenRandomFunc pBCryptGenRandom;
    BCryptCloseAlgorithmProviderFunc pBCryptCloseAlgorithmProvider;
    RtlGenRandomFunc pRtlGenRandom;
    void* hAlgorithm;
    
    hModule = LoadLibraryA("bcrypt.dll");
    if (hModule) {
        pBCryptOpenAlgorithmProvider = 
            (BCryptOpenAlgorithmProviderFunc)GetProcAddress(hModule, "BCryptOpenAlgorithmProvider");
        pBCryptGenRandom = 
            (BCryptGenRandomFunc)GetProcAddress(hModule, "BCryptGenRandom");
        pBCryptCloseAlgorithmProvider = 
            (BCryptCloseAlgorithmProviderFunc)GetProcAddress(hModule, "BCryptCloseAlgorithmProvider");
        
        if (pBCryptOpenAlgorithmProvider && pBCryptGenRandom && pBCryptCloseAlgorithmProvider) {
            hAlgorithm = NULL;
            if (pBCryptOpenAlgorithmProvider(&hAlgorithm, "RNG", NULL, 0) == STATUS_SUCCESS) {
                if (pBCryptGenRandom(hAlgorithm, buffer, (unsigned long)size, 2) == STATUS_SUCCESS) {
                    pBCryptCloseAlgorithmProvider(hAlgorithm, 0);
                    FreeLibrary(hModule);
                    return 1;
                }
                pBCryptCloseAlgorithmProvider(hAlgorithm, 0);
            }
        }
        FreeLibrary(hModule);
    }
    
    hModule = LoadLibraryA("advapi32.dll");
    if (hModule) {
        pRtlGenRandom = 
            (RtlGenRandomFunc)GetProcAddress(hModule, "SystemFunction036");
        if (pRtlGenRandom) {
            if (pRtlGenRandom(buffer, (unsigned long)size)) {
                FreeLibrary(hModule);
                return 1;
            }
        }
        FreeLibrary(hModule);
    }
    
    return 0;
}

#define HAVE_URANDOM 0

#else

#define HAVE_URANDOM 1

static int unix_random_bytes(uint8_t* buffer, size_t size) {
    FILE* fp;
    size_t read;
    
    fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        return 0;
    }
    read = fread(buffer, 1, size, fp);
    fclose(fp);
    return (read == size) ? 1 : 0;
}

#endif

static uint32_t mix_entropy(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352dUL;
    x ^= x >> 15;
    x *= 0x846ca68bUL;
    x ^= x >> 16;
    return x;
}

static void fallback_random_bytes(uint8_t* buffer, size_t size) {
    uint32_t seed;
    size_t i, j;
    uint32_t temp;
    uint8_t* ptr;
    
    seed = (uint32_t)time(NULL);
    seed ^= (uint32_t)(clock() * 0x9e3779b9UL);
    seed ^= (uint32_t)((uintptr_t)&buffer);
    seed ^= (uint32_t)((uintptr_t)&size);
    
#if HAVE_URANDOM
    {
        FILE* fp = fopen("/dev/random", "rb");
        if (fp) {
            if (fread(&temp, sizeof(temp), 1, fp) == 1) {
                seed ^= temp;
            }
            fclose(fp);
        }
    }
#endif
    
    seed = mix_entropy(seed);
    
    for (i = 0; i < size; i += sizeof(uint32_t)) {
        seed = mix_entropy(seed);
        if (i + sizeof(uint32_t) <= size) {
            memcpy(buffer + i, &seed, sizeof(uint32_t));
        } else {
            ptr = (uint8_t*)&seed;
            for (j = 0; j < size - i; j++) {
                buffer[i + j] = ptr[j];
            }
        }
    }
}

int aes_random_bytes(uint8_t* buffer, size_t size) {
    int ok = 0;
    
    if (!buffer || size == 0) {
        return 0;
    }
    
#if HAVE_URANDOM
    ok = unix_random_bytes(buffer, size);
#else
    ok = win32_random_bytes(buffer, size);
#endif
    
    return ok;
}

uint8_t* aes_generate_key(size_t key_size) {
    uint8_t* key;
    
    if (key_size == 0) {
        return NULL;
    }
    
    key = (uint8_t*)malloc(key_size);
    if (!key) {
        return NULL;
    }
    
    if (!aes_random_bytes(key, key_size)) {
        free(key);
        return NULL;
    }
    
    return key;
}

uint8_t* aes_generate_iv(size_t iv_size) {
    return aes_generate_key(iv_size);
}