//test1
#define _GNU_SOURCE  // để dùng CRTSCTS trên một số hệ
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <string.h>
#include <sys/select.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#include <sys/random.h>  // getrandom()

// Ascon AEAD (dùng repo ascon-c)
#include "crypto_aead.h"
#include "api.h"
#include "ascon-c/crypto_aead/asconaead128/ref/api.h"
#include "ascon-c/crypto_aead/asconaead128/ref/ascon.h"
#include "ascon-c/crypto_aead/asconaead128/ref/permutations.h"

// Tham số benchmark
#define NUMBER_OF_ITERATIONS 100
#define WARMUP_ITERATIONS    10
#define BENCH_SIZES_INIT     {1024}   // có thể đổi {64,1024,4096}

// ---- prototypes Ascon (phòng khi api.h ref không có) ----
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

// ---- util time ----
static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

// getrandom()
static int get_random_bytes(uint8_t *buf, size_t len) {
    ssize_t r = getrandom(buf, len, 0);
    return (r == (ssize_t)len) ? 0 : -1;
}

// ---------- tiện ích in hex ----------
static void print_hex_line(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

// ---- key/ad giống ESP ----
static const uint8_t KEY[CRYPTO_KEYBYTES] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};
static const uint8_t AD[16] = {
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F
};

// Key/AD mới dùng để mã hoá lại (lần 2)
static const uint8_t NEW_KEY[CRYPTO_KEYBYTES] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
};
static const uint8_t NEW_AD[16] = {
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
    0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F
};

// ---------- helpers ----------
static unsigned char* make_padded_from_real(const unsigned char* real,
                                            unsigned long long real_len,
                                            unsigned long long target_len)
{
    unsigned char* buf = (unsigned char*)malloc((size_t)target_len);
    if (!buf) return NULL;
    if (real_len >= target_len) {
        memcpy(buf, real, (size_t)target_len);
    } else {
        unsigned long long pos = 0ULL;
        while (pos + real_len <= target_len) {
            memcpy(buf + pos, real, (size_t)real_len);
            pos += real_len;
        }
        if (pos < target_len) {
            unsigned long long rem = target_len - pos;
            memcpy(buf + pos, real, (size_t)rem);
        }
    }
    return buf;
}

static inline void nonce_increment(uint8_t* npub) {
    for (int i = CRYPTO_NPUBBYTES - 1; i >= 0; --i) {
        if (++npub[i] != 0) break;
    }
}

// ====================== BENCHMARKS ======================

/* Stage 1: đo GIẢI MÃ với KEY/AD (Decrypt-only).
   Dùng plaintext thật + padding -> pre-encrypt 1 lần (ngoài vùng đo) để có ct||tag hợp lệ,
   rồi lặp decrypt để đo. Chạy 1 lần duy nhất. */
static void bench_stage1_decrypt_once(const unsigned char* real, unsigned long long real_len)
{
    static int done = 0; if (done) return; done = 1;
    static const unsigned long long sizes[] = BENCH_SIZES_INIT; // ví dụ {1024}

    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        unsigned long long mlen = sizes[si];
        unsigned long long clen = mlen + CRYPTO_ABYTES;

        unsigned char* message       = make_padded_from_real(real, real_len, mlen);
        unsigned char* ciphertext    = (unsigned char*)malloc((size_t)clen);
        unsigned char* plaintext_out = (unsigned char*)malloc((size_t)mlen);
        if (!message || !ciphertext || !plaintext_out) {
            fprintf(stderr, "[stage1] malloc failed\n");
            free(message); free(ciphertext); free(plaintext_out);
            return;
        }

        // Tạo ct||tag hợp lệ 1 lần (ngoài vùng đo) với KEY/AD
        uint8_t npub[CRYPTO_NPUBBYTES];
        if (get_random_bytes(npub, sizeof(npub)) != 0) {
            fprintf(stderr, "[stage1] getrandom nonce failed\n");
            free(message); free(ciphertext); free(plaintext_out);
            return;
        }
        unsigned long long ct_len = 0ULL;
        if (crypto_aead_encrypt(ciphertext, &ct_len,
                                message, mlen,
                                AD, sizeof(AD),
                                NULL, npub, KEY) != 0 || ct_len != clen) {
            fprintf(stderr, "[stage1] pre-encrypt failed\n");
            free(message); free(ciphertext); free(plaintext_out);
            return;
        }

        // Header kết quả
        fprintf(stderr, "\nASCON-128 Stage 1 — Decryption (KEY/AD)\n");
        fprintf(stderr, "Message Size (bytes) : %llu\n", mlen);
        //fprintf(stderr, "Iterations (warmup/run): %d / %d\n", WARMUP_ITERATIONS, NUMBER_OF_ITERATIONS);
        fprintf(stderr, "--------------------------------------------------------\n");
        fprintf(stderr, "Metric              | Value\n");
        fprintf(stderr, "--------------------+--------------------\n");

        // Warmup decrypt
        for (int i = 0; i < WARMUP_ITERATIONS; ++i) {
            unsigned long long dec_len = 0ULL;
            int rc = crypto_aead_decrypt(plaintext_out, &dec_len, NULL,
                                         ciphertext, clen,
                                         AD, sizeof(AD),
                                         npub, KEY);
            if (rc != 0 || dec_len != mlen || memcmp(plaintext_out, message, (size_t)mlen) != 0) {
                fprintf(stderr, "[stage1] warmup decrypt failed (rc=%d, dec_len=%llu)\n", rc, dec_len);
                free(message); free(ciphertext); free(plaintext_out);
                return;
            }
        }

        // Benchmark decrypt-only
        double start = get_time_ms();
        for (int i = 0; i < NUMBER_OF_ITERATIONS; ++i) {
            unsigned long long dec_len = 0ULL;
            (void)crypto_aead_decrypt(plaintext_out, &dec_len, NULL,
                                      ciphertext, clen,
                                      AD, sizeof(AD),
                                      npub, KEY);
        }
        double end = get_time_ms();

        double total_ms         = end - start;
        double time_per_byte_ns = (total_ms * 1e6) / (NUMBER_OF_ITERATIONS * (double)mlen);
        double thr_mb_s         = (NUMBER_OF_ITERATIONS * (double)mlen) / (total_ms / 1000.0) / (1024.0 * 1024.0);

        fprintf(stderr, "Time/byte (ns)      | %.2f\n", time_per_byte_ns);
        fprintf(stderr, "Throughput (MB/s)   | %.2f\n", thr_mb_s);

        free(message);
        free(ciphertext);
        free(plaintext_out);
    }
}

/* Stage 2: đo MÃ HOÁ LẠI với NEW_KEY/NEW_AD (Encrypt-only).
   Dùng plaintext thật + padding. Nonce tăng dần để không nhiễu RNG. Chạy 1 lần duy nhất. */
static void bench_stage2_reencrypt_once(const unsigned char* real, unsigned long long real_len)
{
    static int done2 = 0; if (done2) return; done2 = 1;
    static const unsigned long long sizes[] = BENCH_SIZES_INIT;

    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        unsigned long long mlen = sizes[si];
        unsigned long long clen = mlen + CRYPTO_ABYTES;

        unsigned char* message = make_padded_from_real(real, real_len, mlen);
        unsigned char* ct_tag  = (unsigned char*)malloc((size_t)clen);
        if (!message || !ct_tag) {
            fprintf(stderr, "[stage2] malloc failed\n");
            free(message); free(ct_tag);
            return;
        }

        uint8_t base_nonce[CRYPTO_NPUBBYTES] = {0};
        if (get_random_bytes(base_nonce, sizeof(base_nonce)) != 0) {
            fprintf(stderr, "[stage2] getrandom nonce failed\n");
            free(message); free(ct_tag);
            return;
        }

        fprintf(stderr, "\nASCON-128 Stage 2 — Re-Encryption (NEW_KEY/NEW_AD)\n");
        fprintf(stderr, "Message Size (bytes) : %llu\n", mlen);
        //fprintf(stderr, "Iterations (warmup/run): %d / %d\n", WARMUP_ITERATIONS, NUMBER_OF_ITERATIONS);
        fprintf(stderr, "--------------------------------------------------------\n");
        fprintf(stderr, "Metric              | Value\n");
        fprintf(stderr, "--------------------+--------------------\n");

        // Warmup
        uint8_t npub_wu[CRYPTO_NPUBBYTES]; memcpy(npub_wu, base_nonce, sizeof(npub_wu));
        for (int i = 0; i < WARMUP_ITERATIONS; ++i) {
            unsigned long long clen2 = 0ULL;
            crypto_aead_encrypt(ct_tag, &clen2,
                                message, mlen,
                                NEW_AD, sizeof(NEW_AD),
                                NULL, npub_wu, NEW_KEY);
            nonce_increment(npub_wu);
        }

        // Benchmark encrypt-only
        uint8_t npub[CRYPTO_NPUBBYTES]; memcpy(npub, base_nonce, sizeof(npub));
        double start = get_time_ms();
        for (int i = 0; i < NUMBER_OF_ITERATIONS; ++i) {
            unsigned long long clen2 = 0ULL;
            crypto_aead_encrypt(ct_tag, &clen2,
                                message, mlen,
                                NEW_AD, sizeof(NEW_AD),
                                NULL, npub, NEW_KEY);
            nonce_increment(npub);
        }
        double end = get_time_ms();

        double total_ms         = end - start;
        double time_per_byte_ns = (total_ms * 1e6) / (NUMBER_OF_ITERATIONS * (double)mlen);
        double thr_mb_s         = (NUMBER_OF_ITERATIONS * (double)mlen) / (total_ms / 1000.0) / (1024.0 * 1024.0);

        fprintf(stderr, "Time/byte (ns)      | %.2f\n", time_per_byte_ns);
        fprintf(stderr, "Throughput (MB/s)   | %.2f\n", thr_mb_s);

        free(message);
        free(ct_tag);
    }
}

// ====================== phần nhận/giải mã/mã hoá lại như cũ ======================
static volatile int keep_running = 1;
static void on_sigint(int s){ (void)s; keep_running = 0; }

static int open_serial(const char *dev, speed_t baud)
{
    int fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { perror("open"); return -1; }

    struct termios tio;
    if (tcgetattr(fd, &tio) < 0) { perror("tcgetattr"); close(fd); return -1; }

    cfmakeraw(&tio);
    cfsetispeed(&tio, baud);
    cfsetospeed(&tio, baud);

    // 8N1, không flow control
    tio.c_cflag &= ~PARENB;
    tio.c_cflag &= ~CSTOPB;
    tio.c_cflag &= ~CSIZE;
    tio.c_cflag |= CS8;
#ifdef CRTSCTS
    tio.c_cflag &= ~CRTSCTS;
#endif
    tio.c_cflag |= CLOCAL | CREAD;

    tio.c_cc[VMIN]  = 0;
    tio.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &tio) < 0) { perror("tcsetattr"); close(fd); return -1; }
    tcflush(fd, TCIOFLUSH);
    return fd;
}

// ---- helpers parse hex ----
static int hex_nibble(char c){
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return 10+(c-'a');
    if (c>='A'&&c<='F') return 10+(c-'A');
    return -1;
}
static int hex_to_bytes(const char *hex, uint8_t *out, size_t outcap, size_t *outlen){
    size_t L = strlen(hex);
    if (L % 2 != 0) return 0;
    size_t need = L/2;
    if (need > outcap) return 0;
    for (size_t i=0;i<need;i++){
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i+1]);
        if (hi<0 || lo<0) return 0;
        out[i] = (uint8_t)((hi<<4)|lo);
    }
    if (outlen) *outlen = need;
    return 1;
}
static void print_parsed_plaintext(const uint8_t *m, size_t mlen){
    if (mlen != 12){
        fprintf(stderr,"Invalid plaintext length: %zu\n", mlen);
        return;
    }
    printf("Light:       %u\n",  m[0]);
    printf("Motion:      %u\n",  m[1]);
    printf("Temperature: %u\n",  m[2]);
    printf("Humidity:    %u\n",  m[3]);
    printf("Latitude : %u° %u' %u\" %c\n",  m[4], m[5], m[6],  (m[7] >=32&&m[7]<=126)?(char)m[7]:'?');
    printf("Longitude: %u° %u' %u\" %c\n",  m[8], m[9], m[10], (m[11]>=32&&m[11]<=126)?(char)m[11]:'?');
    puts("----");
}

int main(int argc, char **argv)
{
    const char *dev = (argc > 1) ? argv[1] : "/dev/serial0";
    int fd = open_serial(dev, B115200);
    if (fd < 0) return 1;

    signal(SIGINT, on_sigint);
    fprintf(stderr, "Listening LoRa on %s @115200 ... (3 lines: nonce, ciphertext, tag)\n", dev);

    unsigned char buf[512];
    char line[4096]; size_t lp = 0;

    // buffer 3 dòng
    char hx_nonce[128] = {0};
    char hx_ct[8192]   = {0};
    char hx_tag[128]   = {0};
    int have = 0;

    while (keep_running) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        int rv = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }
        if (rv == 0) continue;

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            for (ssize_t i = 0; i < n; ++i) {
                unsigned char c = buf[i];
                if (c == '\n' || lp >= sizeof(line)-1) {
                    line[lp] = '\0';

                    if (line[0] != '\0'){  // bỏ dòng rỗng
                        size_t L = strlen(line);
                        if (have == 0) { // nonce
                            if (L >= sizeof(hx_nonce)) {
                                fprintf(stderr, "Nonce line too long (%zu)\n", L);
                                have = 0; lp = 0; continue;
                            }
                            memcpy(hx_nonce, line, L + 1);
                            have = 1;
                        } else if (have == 1) { // ciphertext
                            if (L >= sizeof(hx_ct)) {
                                fprintf(stderr, "Ciphertext line too long (%zu)\n", L);
                                have = 0; lp = 0; continue;
                            }
                            memcpy(hx_ct, line, L + 1);
                            have = 2;
                        } else if (have == 2) { // tag
                            if (L >= sizeof(hx_tag)) {
                                fprintf(stderr, "Tag line too long (%zu)\n", L);
                                have = 0; lp = 0; continue;
                            }
                            memcpy(hx_tag, line, L + 1);
                            have = 3;
                        }
                    }
                    lp = 0;

                    if (have == 3) {
                        // ---- convert & validate ----
                        uint8_t nonce[CRYPTO_NPUBBYTES], tag[CRYPTO_ABYTES];
                        size_t nlen=0,tlen=0,clen=0;
                        if (!hex_to_bytes(hx_nonce, nonce, sizeof(nonce), &nlen) || nlen != CRYPTO_NPUBBYTES) {
                            fprintf(stderr,"Bad nonce hex (need %d bytes): %s\n", CRYPTO_NPUBBYTES, hx_nonce);
                            have = 0; continue;
                        }
                        // ciphertext
                        uint8_t *ct = NULL;
                        clen = strlen(hx_ct)/2;
                        ct = (uint8_t*)malloc(clen + CRYPTO_ABYTES);
                        if (!ct){ perror("malloc"); have=0; continue; }
                        if (!hex_to_bytes(hx_ct, ct, clen + CRYPTO_ABYTES, &clen)) {
                            fprintf(stderr,"Bad ciphertext hex: %s\n", hx_ct);
                            free(ct); have=0; continue;
                        }
                        if (!hex_to_bytes(hx_tag, tag, sizeof(tag), &tlen) || tlen != CRYPTO_ABYTES) {
                            fprintf(stderr,"Bad tag hex (need %d bytes): %s\n", CRYPTO_ABYTES, hx_tag);
                            free(ct); have=0; continue;
                        }
                        // gộp ct||tag
                        memcpy(ct + clen, tag, tlen);
                        unsigned long long mlen = 0;
                        uint8_t m[4096];

                        int rc = crypto_aead_decrypt(
                            m, &mlen, NULL,
                            ct, (unsigned long long)(clen + tlen),
                            AD, sizeof(AD),
                            nonce, KEY
                        );
                        if (rc != 0) {
                            fprintf(stderr,"Decryption FAILED\n");
                        } else {
                            fprintf(stderr,"Decryption OK (mlen=%llu)\n", mlen);
                            print_parsed_plaintext(m, (size_t)mlen);

                            // === ĐO THÔNG LƯỢNG THEO LUỒNG THỰC TẾ ===
                            // Stage 1: GIẢI MÃ với KEY/AD (decrypt-only)
                            bench_stage1_decrypt_once(m, mlen);
                            // Stage 2: MÃ HOÁ LẠI với NEW_KEY/NEW_AD (encrypt-only)
                            bench_stage2_reencrypt_once(m, mlen);
                        }

                        // ===== MÃ HOÁ LẠI (thực tế) để đưa lên web =====
                        uint8_t new_nonce[CRYPTO_NPUBBYTES];
                        if (get_random_bytes(new_nonce, sizeof(new_nonce)) != 0) {
                            fprintf(stderr, "getrandom() failed, cannot generate nonce\n");
                        } else {
                            unsigned long long clen2 = 0;
                            uint8_t *ct_tag = (uint8_t*)malloc(mlen + CRYPTO_ABYTES);
                            if (!ct_tag) {
                                perror("malloc");
                            } else {
                                int rc2 = crypto_aead_encrypt(
                                    ct_tag, &clen2,
                                    m, mlen,                 // plaintext vừa giải mã
                                    NEW_AD, sizeof(NEW_AD),  // AAD mới (hoặc AD cũ tuỳ bạn)
                                    NULL,
                                    new_nonce,
                                    NEW_KEY
                                );
                                if (rc2 != 0) {
                                    fprintf(stderr, "Re-encrypt failed\n");
                                } else {
                                    size_t ct_only = (size_t)clen2 - CRYPTO_ABYTES;
                                    uint8_t *new_ct  = ct_tag;
                                    uint8_t *new_tag = ct_tag + ct_only;

                                    // In ra 3 dòng theo format
                                    fprintf(stderr, "Nonce:\n");
                                    print_hex_line(new_nonce, CRYPTO_NPUBBYTES); // dòng 1: nonce
                                    fprintf(stderr, "ciphertext:\n");
                                    print_hex_line(new_ct,   ct_only);           // dòng 2: ciphertext
                                    fprintf(stderr, "tag:\n");
                                    print_hex_line(new_tag,  CRYPTO_ABYTES);     // dòng 3: tag
                                }
                                free(ct_tag);
                            }
                        }

                        free(ct);
                        have = 0; // sẵn sàng packet tiếp theo
                    }
                } else if (c != '\r') {
                    line[lp++] = (char)c;
                }
            }
        } else if (n < 0 && errno != EAGAIN) {
            perror("read"); break;
        }
    }

    if (lp > 0) { line[lp] = '\0'; printf("%s\n", line); }
    close(fd);
    return 0;
}
