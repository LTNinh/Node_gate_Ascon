#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "crypto_aead.h" 
#include "ascon-c/crypto_aead/asconaead128/ref/api.h"
#include "ascon-c/crypto_aead/asconaead128/ref/ascon.h"
#include "ascon-c/crypto_aead/asconaead128/ref/permutations.h"

// Tham số benchmark
#define NUMBER_OF_ITERATIONS 100
#define WARMUP_ITERATIONS 10

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

// Prototypes (thường không có sẵn trong api.h bản ref)
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec,
                        const unsigned char* npub,
                        const unsigned char* k);

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec,
                        const unsigned char* c, unsigned long long clen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* npub,
                        const unsigned char* k);

int main(int argc, char** argv) {
    // Độ dài dữ liệu cố định (byte) — truyền tham số
    // Ví dụ: 12 (giống payload), 1024 (1KB), 1048576 (1MB)
    unsigned long long mlen = 1024ULL;
    if (argc >= 2) {
        char* endp = NULL;
        unsigned long long v = strtoull(argv[1], &endp, 10);
        if (endp == argv[1] || *endp != '\0' || v == 0ULL) {
            fprintf(stderr, "Usage: %s <message_size_bytes>\n", argv[0]);
            return 1;
        }
        mlen = v;
    }

    unsigned char key[CRYPTO_KEYBYTES];
    unsigned char nonce[CRYPTO_NPUBBYTES];
    unsigned long long ct_len = 0ULL;

    // Dữ liệu ngẫu nhiên cho benchmark (không nhằm mục đích bảo mật)
    srand((unsigned)time(NULL));
    for (int i = 0; i < CRYPTO_KEYBYTES; i++) key[i] = rand() & 0xFF;
    for (int i = 0; i < CRYPTO_NPUBBYTES; i++) nonce[i] = rand() & 0xFF;

    // Cấp phát buffer theo mlen
    unsigned long long clen = mlen + CRYPTO_ABYTES;
    unsigned char* message       = (unsigned char*)malloc(mlen);
    unsigned char* ciphertext    = (unsigned char*)malloc(clen);
    unsigned char* plaintext_out = (unsigned char*)malloc(mlen);

    if (!message || !ciphertext || !plaintext_out) {
        fprintf(stderr, "malloc failed\n");
        free(message); free(ciphertext); free(plaintext_out);
        return 1;
    }

    // Điền message ngẫu nhiên
    for (unsigned long long i = 0; i < mlen; i++) message[i] = rand() & 0xFF;

    // ===================== ENCRYPTION BENCH =====================
    printf("\nASCON-128 Encryption Benchmark (fixed size)\n");
    printf("Message Size (bytes) : %llu\n", mlen);
    printf("Iterations (warmup/run): %d / %d\n", WARMUP_ITERATIONS, NUMBER_OF_ITERATIONS);
    printf("--------------------------------------------------------\n");
    printf("Metric              | Value\n");
    printf("--------------------+--------------------\n");

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        crypto_aead_encrypt(ciphertext, &ct_len, message, mlen, NULL, 0, NULL, nonce, key);
    }

    // Benchmark encrypt
    double start_e = get_time_ms();
    for (int i = 0; i < NUMBER_OF_ITERATIONS; i++) {
        crypto_aead_encrypt(ciphertext, &ct_len, message, mlen, NULL, 0, NULL, nonce, key);
    }
    double end_e = get_time_ms();

    double total_e_ms       = end_e - start_e;
    double time_per_byte_ns = (total_e_ms * 1e6) / (NUMBER_OF_ITERATIONS * (double)mlen);
    double thr_mb_s        = (NUMBER_OF_ITERATIONS * (double)mlen) / (total_e_ms / 1000.0) / (1024.0 * 1024.0);

    printf("Time/byte (ns)      | %.2f\n", time_per_byte_ns);
    printf("Throughput (MB/s)  | %.2f\n", thr_mb_s);

    // ===================== PREPARE FOR DECRYPT =====================
    // Tạo ciphertext hợp lệ (ct||tag) cho decrypt benchmark
    if (crypto_aead_encrypt(ciphertext, &ct_len, message, mlen, NULL, 0, NULL, nonce, key) != 0 || ct_len != clen) {
        fprintf(stderr, "pre-encrypt failed\n");
        free(message); free(ciphertext); free(plaintext_out);
        return 1;
    }

    // ===================== DECRYPTION BENCH =====================
    printf("\nASCON-128 Decryption Benchmark (fixed size)\n");
    printf("Message Size (bytes) : %llu\n", mlen);
    printf("Iterations (warmup/run): %d / %d\n", WARMUP_ITERATIONS, NUMBER_OF_ITERATIONS);
    printf("--------------------------------------------------------\n");
    printf("Metric              | Value\n");
    printf("--------------------+--------------------\n");

    // Warmup decrypt (xác thực tag)
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        unsigned long long dec_len = 0ULL;
        int rc = crypto_aead_decrypt(plaintext_out, &dec_len, NULL, ciphertext, clen, NULL, 0, nonce, key);
        if (rc != 0 || dec_len != mlen) {
            fprintf(stderr, "warmup decrypt failed (rc=%d, dec_len=%llu)\n", rc, dec_len);
            free(message); free(ciphertext); free(plaintext_out);
            return 1;
        }
    }

    // Benchmark decrypt
    double start_d = get_time_ms();
    for (int i = 0; i < NUMBER_OF_ITERATIONS; i++) {
        unsigned long long dec_len = 0ULL;
        int rc = crypto_aead_decrypt(plaintext_out, &dec_len, NULL, ciphertext, clen, NULL, 0, nonce, key);
        if (rc != 0 || dec_len != mlen) {
            fprintf(stderr, "decrypt failed (rc=%d, dec_len=%llu)\n", rc, dec_len);
            free(message); free(ciphertext); free(plaintext_out);
            return 1;
        }
    }
    double end_d = get_time_ms();

    double total_d_ms        = end_d - start_d;
    double time_per_byte_ns2 = (total_d_ms * 1e6) / (NUMBER_OF_ITERATIONS * (double)mlen);
    double thr_mb_s2        = (NUMBER_OF_ITERATIONS * (double)mlen) / (total_d_ms / 1000.0) / (1024.0 * 1024.0);

    printf("Time/byte (ns)      | %.2f\n", time_per_byte_ns2);
    printf("Throughput (MB/s)  | %.2f\n", thr_mb_s2);

    free(message);
    free(ciphertext);
    free(plaintext_out);
    return 0;
}

