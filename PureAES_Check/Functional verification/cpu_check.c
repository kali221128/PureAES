#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    int aes_ni = (ecx >> 25) & 1;
    int sse41  = (ecx >> 19) & 1;
    int sse42  = (ecx >> 20) & 1;
    printf("CPU AES-NI : %s\n", aes_ni ? "YES" : "NO");
    printf("CPU SSE4.1 : %s\n", sse41  ? "YES" : "NO");
    printf("CPU SSE4.2 : %s\n", sse42  ? "YES" : "NO");
    return 0;
}
