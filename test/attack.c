#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

// ChaCha20 implementation
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QUARTERROUND(a,b,c,d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8); \
    c += d; b ^= c; b = ROTL32(b, 7)

typedef struct {
    uint32_t state[16];
    uint32_t counter;
} chacha20_ctx;

static void chacha20_init(chacha20_ctx *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    const uint8_t sigma[16] = "expand 32-byte k";
    
    ctx->state[0] = ((uint32_t*)sigma)[0];
    ctx->state[1] = ((uint32_t*)sigma)[1];
    ctx->state[2] = ((uint32_t*)sigma)[2];
    ctx->state[3] = ((uint32_t*)sigma)[3];
    
    for(int i = 0; i < 8; i++)
        ctx->state[4+i] = ((uint32_t*)key)[i];
    
    ctx->state[12] = 0; // counter start
    
    for(int i = 0; i < 3; i++)
        ctx->state[13+i] = ((uint32_t*)nonce)[i];
    
    ctx->counter = 0;
}

static void chacha20_block(chacha20_ctx *ctx, uint8_t output[64]) {
    uint32_t x[16];
    memcpy(x, ctx->state, sizeof(x));
    x[12] = ctx->counter;
    
    for(int i = 0; i < 10; i++) {
        QUARTERROUND(x[0], x[4], x[8],  x[12]);
        QUARTERROUND(x[1], x[5], x[9],  x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8],  x[13]);
        QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }
    
    for(int i = 0; i < 16; i++)
        x[i] += ctx->state[i];
    
    x[12] += ctx->counter;
    memcpy(output, x, 64);
    ctx->counter++;
}

static void chacha20_xor(chacha20_ctx *ctx, uint8_t *data, size_t len) {
    uint8_t keystream[64];
    size_t pos = 0;
    
    while(len > 0) {
        chacha20_block(ctx, keystream);
        size_t chunk = (len > 64) ? 64 : len;
        
        for(size_t i = 0; i < chunk; i++)
            data[pos + i] ^= keystream[i];
        
        pos += chunk;
        len -= chunk;
    }
}

static void die(const char *m) {
    perror(m);
    exit(1);
}

// Generate dummy key
static void derive_key(const char *path, struct stat *st, uint8_t key[32], uint8_t nonce[12]) {
    
    //derive from filename + size (deterministic)
    
    uint64_t seed = st->st_size ^ st->st_ino ^ st->st_mtime;
    
    for(int i = 0; i < (int)strlen(path); i++)
        seed = seed * 31 + path[i];
    
    // Simple PRNG
    for(int i = 0; i < 32; i++) {
        seed = seed * 1103515245 + 12345;
        key[i] = (seed >> 16) & 0xFF;
    }
    
    for(int i = 0; i < 12; i++) {
        seed = seed * 1103515245 + 12345;
        nonce[i] = (seed >> 16) & 0xFF;
    }
}

int main(int argc, char **argv) {
    if(argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    
    const char *path = argv[1];
    
    // Open file
    int fd = open(path, O_RDWR);
    if(fd < 0) die("open");
    
    struct stat st;
    if(fstat(fd, &st) < 0) die("fstat");
    
    if(st.st_size <= 0) {
        fprintf(stderr, "empty file\n");
        close(fd);
        return 1;
    }
    
    // Read entire file
    uint8_t *buf = malloc(st.st_size);
    if(!buf) die("malloc");
    
    ssize_t r = pread(fd, buf, st.st_size, 0);
    if(r != st.st_size) die("pread");
    
    // Derive encryption key from file metadata
    uint8_t key[32], nonce[12];
    derive_key(path, &st, key, nonce);
    
    printf("[*] Encrypting %s (%ld bytes)\n", path, st.st_size);
    printf("[*] Key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) printf("%02x", key[i]);
    printf("\n");
    
    // Encrypt with ChaCha20
    chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce);
    chacha20_xor(&ctx, buf, st.st_size);
    
    // Overwrite file
    if(pwrite(fd, buf, st.st_size, 0) != st.st_size)
        die("pwrite");
    
    if(fsync(fd) != 0) die("fsync");
    
    close(fd);
    free(buf);
    
    printf("[+] Encryption completed\n");
    printf("[+] File has been encrypted with ChaCha20\n");
    
    return 0;
}