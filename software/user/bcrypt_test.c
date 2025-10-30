/*
 * Bcrypt Basic Test
 *
 * This file is part of LiteX-Bcrypt.
 *
 * Initializes the Bcrypt accelerator once with CMP_CONFIG, then runs multiple
 * password hashing operations (WORD_LIST + WORD_GEN) and reports performance.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "liblitepcie.h"
#include "csr.h"
#include "mem.h"

/* Variables */
/*-----------*/
static char litepcie_device[1024];
static int litepcie_device_num = 0;

/* Connection Functions */
/*----------------------*/
static int litepcie_open(void) {
    int fd = open(litepcie_device, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Could not init driver\n");
        exit(1);
    }
    return fd;
}
static void litepcie_close(int fd) {
    close(fd);
}

/* Packet Helpers */
/*----------------*/
#define PKT_VERSION 2
#define PKT_TYPE_WORD_LIST 0x01
#define PKT_TYPE_WORD_GEN  0x02
#define PKT_TYPE_CMP_CONFIG 0x03

static void le16(uint16_t x, uint8_t *out) {
    out[0] = x & 0xFF;
    out[1] = (x >> 8) & 0xFF;
}
static void le24(uint32_t x, uint8_t *out) {
    out[0] = x & 0xFF;
    out[1] = (x >> 8) & 0xFF;
    out[2] = (x >> 16) & 0xFF;
}
static void le32(uint32_t x, uint8_t *out) {
    out[0] = x & 0xFF;
    out[1] = (x >> 8) & 0xFF;
    out[2] = (x >> 16) & 0xFF;
    out[3] = (x >> 24) & 0xFF;
}
static uint32_t csum32_le(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = 0;
        for (int j = 0; j < 4 && i + j < len; j++)
            w |= data[i + j] << (8 * j);
        sum = (sum + w) & 0xFFFFFFFF;
    }
    return sum ^ 0xFFFFFFFF;
}
static void add_checksums(uint8_t *pkt, size_t *len, const uint8_t *header, size_t hlen,
                          const uint8_t *payload, size_t plen) {
    uint8_t hsum[4], psum[4];
    uint32_t h = csum32_le(header, hlen);
    uint32_t p = csum32_le(payload, plen);
    le32(h, hsum);
    le32(p, psum);
    memcpy(pkt, header, hlen);
    memcpy(pkt + hlen, hsum, 4);
    memcpy(pkt + hlen + 4, payload, plen);
    memcpy(pkt + hlen + 4 + plen, psum, 4);
    *len = hlen + 4 + plen + 4;
}
static void build_cmp_config_payload(uint8_t *out, size_t *len,
                                     uint32_t iter_count, const uint8_t *salt16, size_t nhashes, const uint32_t *hashes) {
    uint8_t *p = out;
    memcpy(p, salt16, 16); p += 16;
    *p++ = 'b';
    le32(iter_count, p); p += 4;
    le16(nhashes, p); p += 2;
    for (size_t i = 0; i < nhashes; i++) {
        le32(hashes[i] & 0x7FFFFFFF, p); p += 4;
    }
    *p++ = 0xCC;
    *len = p - out;
}
static void build_word_list_payload(uint8_t *out, size_t *len, const char **words, size_t nwords) {
    uint8_t *p = out;
    for (size_t i = 0; i < nwords; i++) {
        const char *w = words[i];
        while (*w) *p++ = *w++;
        *p++ = 0;
    }
    *len = p - out;
}
static void build_word_gen_payload(uint8_t *out, size_t *len) {
    uint8_t payload[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0xBB};
    memcpy(out, payload, sizeof(payload));
    *len = sizeof(payload);
}
static void print_hash(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

/* Wishbone Helpers */
/*------------------*/
static void write_bytes(int fd, uint32_t base, const uint8_t *data, size_t len) {
    uint8_t buf[4] = {0};
    for (size_t i = 0; i < len; i += 4) {
        size_t rem = len - i > 4 ? 4 : len - i;
        memcpy(buf, data + i, rem);
        litepcie_writel(fd, base + i, buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
    }
}
static void read_bytes(int fd, uint32_t base, uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = litepcie_readl(fd, base + i);
        size_t rem = len - i > 4 ? 4 : len - i;
        for (size_t j = 0; j < rem; j++)
            data[i + j] = (w >> (8 * j)) & 0xFF;
    }
}

/* Bcrypt Test */
/*-------------*/
static void bcrypt_test(int fd) {
    uint8_t cmp_pl[128], wl_pl[128], wg_pl[128], pkt_cmp[256], pkt_wl[256], pkt_wg[256];
    size_t cmp_pl_len, wl_pl_len, wg_pl_len, pkt_cmp_len, pkt_wl_len, pkt_wg_len;

    /* Build packets */
    uint8_t salt16[16];
    for (int i = 0; i < 16; i++) salt16[i] = i;
    uint32_t hashes[] = {0};
    build_cmp_config_payload(cmp_pl, &cmp_pl_len, 5, salt16, 1, hashes);

    uint8_t hdr[10];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = PKT_VERSION;
    hdr[1] = PKT_TYPE_CMP_CONFIG;
    le24(cmp_pl_len, hdr + 4);
    hdr[7] = 0;
    le16(0x0001, hdr + 8);
    add_checksums(pkt_cmp, &pkt_cmp_len, hdr, 10, cmp_pl, cmp_pl_len);

    const char *words[] = {"pass"};
    build_word_list_payload(wl_pl, &wl_pl_len, words, 1);

    memset(hdr, 0, sizeof(hdr));
    hdr[0] = PKT_VERSION;
    hdr[1] = PKT_TYPE_WORD_LIST;
    le24(wl_pl_len, hdr + 4);
    hdr[7] = 0;
    le16(0x0002, hdr + 8);
    add_checksums(pkt_wl, &pkt_wl_len, hdr, 10, wl_pl, wl_pl_len);

    build_word_gen_payload(wg_pl, &wg_pl_len);
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = PKT_VERSION;
    hdr[1] = PKT_TYPE_WORD_GEN;
    le24(wg_pl_len, hdr + 4);
    hdr[7] = 0;
    le16(0x0003, hdr + 8);
    add_checksums(pkt_wg, &pkt_wg_len, hdr, 10, wg_pl, wg_pl_len);

    /* Initialize core (no response) */
    printf("\e[1m[> Initializing Bcrypt core...\e[0m\n");
    write_bytes(fd, STREAMER_MEM_BASE, pkt_cmp, pkt_cmp_len);
    litepcie_writel(fd, CSR_STREAMER_LENGTH_ADDR, pkt_cmp_len);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 0);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 1);
    while (!litepcie_readl(fd, CSR_STREAMER_DONE_ADDR)) usleep(100);

    /* Multi-run */
    const int runs = 10;
    double total_time = 0.0;
    int total_hashes = 0;

    printf("\e[1m[> Running %d iterations (1 word per run)...\e[0m\n", runs);
    printf("Run Out Time(s) H/s Hash\n");
    printf("------------------------------------------\n");

    uint8_t result[32];

    for (int run = 0; run < runs; run++) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        /* Start recorder */
        litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 0);
        litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 1);

        /* Stream WORD_LIST */
        write_bytes(fd, STREAMER_MEM_BASE, pkt_wl, pkt_wl_len);
        litepcie_writel(fd, CSR_STREAMER_LENGTH_ADDR, pkt_wl_len);
        litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 0);
        litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 1);
        while (!litepcie_readl(fd, CSR_STREAMER_DONE_ADDR)) usleep(100);

        /* Stream WORD_GEN */
        write_bytes(fd, STREAMER_MEM_BASE, pkt_wg, pkt_wg_len);
        litepcie_writel(fd, CSR_STREAMER_LENGTH_ADDR, pkt_wg_len);
        litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 0);
        litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 1);
        while (!litepcie_readl(fd, CSR_STREAMER_DONE_ADDR)) usleep(100);

        /* Wait recorder */
        while (!litepcie_readl(fd, CSR_RECORDER_DONE_ADDR)) usleep(100);
        uint32_t out_len = litepcie_readl(fd, CSR_RECORDER_COUNT_ADDR);

        /* Read result */
        read_bytes(fd, RECORDER_MEM_BASE, result, out_len < 32 ? out_len : 32);

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        double hps = 1.0 / elapsed;

        total_time += elapsed;
        total_hashes++;

        printf("%3d %3u %7.3f %8.0f ", run + 1, out_len, elapsed, hps);
        print_hash(result, out_len);
    }

    /* Final stats */
    double avg_hps = total_hashes / total_time;
    printf("------------------------------------------\n");
    printf("Total: %d hashes in %.3f s → %.0f H/s\n", total_hashes, total_time, avg_hps);

    /* Status */
    uint32_t app = litepcie_readl(fd, CSR_BCRYPT_APP_STATUS_ADDR);
    uint32_t pkt = litepcie_readl(fd, CSR_BCRYPT_PKT_COMM_STATUS_ADDR);
    printf("\e[1m[> app_status=0x%02x pkt_comm_status=0x%02x\e[0m\n", app, pkt);

    printf("\e[1m[> Test complete.\e[0m\n");
}

/* Help */
/*------*/
static void help(void) {
    printf("Bcrypt Hardware Test Utility\n"
           "usage: bcrypt_test [options]\n"
           "\n"
           "Options:\n"
           "-h Display this help message.\n"
           "-c device_num Select the device (default = 0).\n");
    exit(1);
}

/* Main */
/*------*/
int main(int argc, char **argv) {
    int c;
    /* Parameters */
    for (;;) {
        c = getopt(argc, argv, "hc:");
        if (c == -1)
            break;
        switch (c) {
        case 'h':
            help();
            break;
        case 'c':
            litepcie_device_num = atoi(optarg);
            break;
        default:
            exit(1);
        }
    }
    /* Select device */
    snprintf(litepcie_device, sizeof(litepcie_device), "/dev/litepcie%d", litepcie_device_num);
    /* Open connection */
    int fd = litepcie_open();
    /* Run test */
    bcrypt_test(fd);
    /* Close connection */
    litepcie_close(fd);
    return 0;
}
