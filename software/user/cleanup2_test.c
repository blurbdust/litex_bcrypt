/*
 * Cleanup2 Test
 *
 * This file is part of LiteX-Bcrypt.
 *
 * cleanup2_test.c — Test Bcrypt Sim
 * Demonstrates LiteX Bcrypt Proof-of-Concept (PoC) for flexible hardware acceleration.
 *
 * High-level:
 * - Constructs and checksums application-level packets.
 * - Streams packets via AXI8Streamer from streamer_mem @ 0x40100000.
 * - Captures Bcrypt output into recorder_mem @ 0x40200000 using AXI8Recorder.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

#include "liblitepcie.h"
#include "csr.h"
#include "mem.h"

/* Variables */
/*-----------*/
static char litepcie_device[1024];
static int litepcie_device_num = 0;

/* Packet Constants */
/*------------------*/
#define PKT_VERSION         2
#define PKT_TYPE_WORD_LIST  0x01
#define PKT_TYPE_WORD_GEN   0x02
#define PKT_TYPE_CMP_CONFIG 0x03
#define PKT_TYPE_RESET      0x05

#define STREAMER_TIMEOUT    10000000
#define RECORDER_TIMEOUT    10000000
#define DRAIN_SHORT_TIMEOUT 5000
#define DRAIN_MAX_PACKETS   10

#define MAX_WORDS           4096
#define MAX_WORD_LEN        256
#define MAX_WORDLIST_SIZE   (MAX_WORDS * MAX_WORD_LEN)

/* Connection Functions */
/*----------------------*/
static int litepcie_open_device(void) {
    int fd = open(litepcie_device, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Could not init driver\n");
        exit(1);
    }
    return fd;
}

static void litepcie_close_device(int fd) {
    close(fd);
}

/* Packet Helpers */
/*----------------*/
static void le16_encode(uint16_t x, uint8_t *out) {
    out[0] = x & 0xFF;
    out[1] = (x >> 8) & 0xFF;
}

static void le24_encode(uint32_t x, uint8_t *out) {
    out[0] = x & 0xFF;
    out[1] = (x >> 8) & 0xFF;
    out[2] = (x >> 16) & 0xFF;
}

static void le32_encode(uint32_t x, uint8_t *out) {
    out[0] = x & 0xFF;
    out[1] = (x >> 8) & 0xFF;
    out[2] = (x >> 16) & 0xFF;
    out[3] = (x >> 24) & 0xFF;
}

static uint16_t le16_decode(const uint8_t *data) {
    return data[0] | (data[1] << 8);
}

static uint32_t le32_decode(const uint8_t *data) {
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
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

static void build_header(uint8_t *out, uint8_t pkt_type, uint16_t pkt_id, uint32_t payload_len) {
    out[0] = PKT_VERSION;
    out[1] = pkt_type;
    out[2] = 0x00;
    out[3] = 0x00;
    le24_encode(payload_len, out + 4);
    out[7] = 0x00;
    le16_encode(pkt_id, out + 8);
}

static void add_checksums_around_payload(uint8_t *pkt, size_t *pkt_len,
                                          const uint8_t *header, size_t hlen,
                                          const uint8_t *payload, size_t plen) {
    uint8_t hsum[4], psum[4];
    uint32_t h = csum32_le(header, hlen);
    uint32_t p = csum32_le(payload, plen);
    le32_encode(h, hsum);
    le32_encode(p, psum);
    memcpy(pkt, header, hlen);
    memcpy(pkt + hlen, hsum, 4);
    memcpy(pkt + hlen + 4, payload, plen);
    memcpy(pkt + hlen + 4 + plen, psum, 4);
    *pkt_len = hlen + 4 + plen + 4;
}

static void build_cmp_config_payload_bcrypt(uint8_t *out, size_t *len,
                                            uint32_t iter_count, const uint8_t *salt16,
                                            uint8_t subtype, size_t nhashes, const uint32_t *hashes) {
    uint8_t *p = out;
    memcpy(p, salt16, 16); p += 16;
    *p++ = subtype;
    le32_encode(iter_count, p); p += 4;
    le16_encode((uint16_t)nhashes, p); p += 2;
    for (size_t i = 0; i < nhashes; i++) {
        le32_encode(hashes[i], p); p += 4;
    }
    *p++ = 0xCC;
    *len = p - out;
}

static void build_word_list_payload(uint8_t *out, size_t *len, char **words, size_t nwords) {
    uint8_t *p = out;
    for (size_t i = 0; i < nwords; i++) {
        const char *w = words[i];
        while (*w) *p++ = (uint8_t)*w++;
        *p++ = 0x00;
    }
    *len = p - out;
}

static void build_empty_word_gen_payload(uint8_t *out, size_t *len) {
    uint8_t payload[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xBB};
    memcpy(out, payload, sizeof(payload));
    *len = sizeof(payload);
}

static void print_packet(const char *name, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes): ", name, len);
    for (size_t i = 0; i < len; i++)
        printf("%02x ", data[i]);
    printf("\n");
}

/* Wishbone Helpers */
/*------------------*/
static void write_bytes(int fd, uint32_t base, const uint8_t *data, size_t len) {
    uint8_t buf[4] = {0};
    for (size_t i = 0; i < len; i += 4) {
        memset(buf, 0, 4);
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

/* Streamer / Recorder Control */
/*-----------------------------*/
static void kick_streamer(int fd, const uint8_t *pkt_bytes, size_t pkt_len) {
    printf("Writing %zu bytes into streamer_mem @ 0x%08x...\n", pkt_len, STREAMER_MEM_BASE);
    write_bytes(fd, STREAMER_MEM_BASE, pkt_bytes, pkt_len);
    litepcie_writel(fd, CSR_STREAMER_LENGTH_ADDR, pkt_len);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 0);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 1);
    uint32_t cnt = 0;
    while (!litepcie_readl(fd, CSR_STREAMER_DONE_ADDR)) {
        cnt++;
        if (cnt >= STREAMER_TIMEOUT) {
            fprintf(stderr, "streamer timeout\n");
            exit(1);
        }
    }
    printf("  -> streamer done\n");
}

static void start_recorder(int fd) {
    printf("Starting recorder (captures until last packet)...\n");
    litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 0);
    litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 1);
}

static uint32_t wait_recorder(int fd) {
    uint32_t cnt = 0;
    while (!litepcie_readl(fd, CSR_RECORDER_DONE_ADDR)) {
        cnt++;
        if (cnt >= RECORDER_TIMEOUT) {
            fprintf(stderr, "recorder timeout\n");
            exit(1);
        }
    }
    uint32_t recorder_len = litepcie_readl(fd, CSR_RECORDER_COUNT_ADDR);
    printf("Recorder captured %u bytes.\n", recorder_len);
    return recorder_len;
}

static void send_reset(int fd) {
    printf("Sending reset packet to clear FPGA state...\n");
    uint8_t reset_pl[] = {0xCC};
    size_t reset_pl_len = 1;
    uint8_t reset_hdr[10];
    build_header(reset_hdr, PKT_TYPE_RESET, 0x0000, reset_pl_len);
    uint8_t pkt_reset[32];
    size_t pkt_reset_len;
    add_checksums_around_payload(pkt_reset, &pkt_reset_len, reset_hdr, 10, reset_pl, reset_pl_len);

    write_bytes(fd, STREAMER_MEM_BASE, pkt_reset, pkt_reset_len);
    litepcie_writel(fd, CSR_STREAMER_LENGTH_ADDR, pkt_reset_len);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 0);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 1);
    uint32_t cnt = 0;
    while (!litepcie_readl(fd, CSR_STREAMER_DONE_ADDR)) {
        cnt++;
        if (cnt >= STREAMER_TIMEOUT) {
            fprintf(stderr, "reset streamer timeout\n");
            exit(1);
        }
    }
    printf("  -> reset complete\n");
}

static uint32_t drain_output_fifo(int fd) {
    uint32_t total_drained = 0;
    int packets_drained = 0;
    uint8_t discarded[256];

    while (packets_drained < DRAIN_MAX_PACKETS) {
        /* Start recorder */
        litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 0);
        litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 1);

        /* Wait with short timeout */
        uint32_t cnt = 0;
        while (!litepcie_readl(fd, CSR_RECORDER_DONE_ADDR)) {
            cnt++;
            if (cnt >= DRAIN_SHORT_TIMEOUT) {
                /* Timeout - no more data pending */
                if (total_drained > 0) {
                    printf("  -> drained %d packet(s), %u bytes total\n", packets_drained, total_drained);
                } else {
                    printf("  -> FIFO empty (nothing to drain)\n");
                }
                return total_drained;
            }
        }

        /* Check how much was captured */
        uint32_t captured = litepcie_readl(fd, CSR_RECORDER_COUNT_ADDR);
        if (captured == 0) {
            if (total_drained > 0) {
                printf("  -> drained %d packet(s), %u bytes total\n", packets_drained, total_drained);
            } else {
                printf("  -> FIFO empty (nothing to drain)\n");
            }
            return total_drained;
        }

        /* Data was captured - read and display it */
        packets_drained++;
        total_drained += captured;

        size_t read_len = captured < sizeof(discarded) ? captured : sizeof(discarded);
        read_bytes(fd, RECORDER_MEM_BASE, discarded, read_len);
        uint8_t pkt_type = (read_len > 1) ? discarded[1] : 0;

        /* Parse and display packet contents */
        if (pkt_type == 0xd2 && read_len >= 18) {
            /* PACKET_DONE */
            uint16_t pkt_id = le16_decode(discarded + 8);
            uint32_t num_processed = le32_decode(discarded + 14);
            printf("  [drain] PACKET_DONE (0xd2): pkt_id=0x%04x, num_processed=%u\n", pkt_id, num_processed);
        } else if (pkt_type == 0xd4 && read_len >= 22) {
            /* CMP_RESULT */
            uint16_t pkt_id = le16_decode(discarded + 8);
            uint16_t hash_num = le16_decode(discarded + 20);
            printf("  [drain] CMP_RESULT (0xd4): pkt_id=0x%04x, hash_num=%u (MATCH FOUND)\n", pkt_id, hash_num);
        } else if (pkt_type == 0xd3) {
            /* RESULT */
            uint16_t pkt_id = (read_len >= 10) ? le16_decode(discarded + 8) : 0;
            printf("  [drain] RESULT (0xd3): pkt_id=0x%04x\n", pkt_id);
        } else {
            printf("  [drain] packet type 0x%02x, %u bytes\n", pkt_type, captured);
            printf("          raw: ");
            size_t print_len = read_len < 32 ? read_len : 32;
            for (size_t i = 0; i < print_len; i++)
                printf("%02x ", discarded[i]);
            printf("\n");
        }
    }

    printf("  -> drained %d packet(s), %u bytes total (hit max)\n", packets_drained, total_drained);
    return total_drained;
}

/* Custom Base64 Decoding */
/*------------------------*/

/* Custom bcrypt alphabet: ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 */
static const char *custom_alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static const char *std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int custom_b64_char_to_index(char c) {
    const char *p = strchr(custom_alphabet, c);
    if (p == NULL) return -1;
    return (int)(p - custom_alphabet);
}

static int std_b64_index_to_value(int idx) {
    /* Convert custom alphabet index to standard base64 value */
    if (idx < 0 || idx >= 64) return -1;
    char std_char = std_alphabet[idx];
    if (std_char >= 'A' && std_char <= 'Z') return std_char - 'A';
    if (std_char >= 'a' && std_char <= 'z') return std_char - 'a' + 26;
    if (std_char >= '0' && std_char <= '9') return std_char - '0' + 52;
    if (std_char == '+') return 62;
    if (std_char == '/') return 63;
    return -1;
}

static size_t custom_b64decode(const char *input, uint8_t *output, size_t max_output) {
    size_t input_len = strlen(input);
    size_t out_idx = 0;

    for (size_t i = 0; i < input_len && out_idx < max_output; i += 4) {
        int vals[4] = {0, 0, 0, 0};
        int valid_chars = 0;

        for (int j = 0; j < 4 && (i + j) < input_len; j++) {
            int idx = custom_b64_char_to_index(input[i + j]);
            if (idx >= 0) {
                vals[j] = std_b64_index_to_value(idx);
                valid_chars++;
            }
        }

        if (valid_chars >= 2 && out_idx < max_output) {
            output[out_idx++] = (vals[0] << 2) | (vals[1] >> 4);
        }
        if (valid_chars >= 3 && out_idx < max_output) {
            output[out_idx++] = ((vals[1] & 0x0F) << 4) | (vals[2] >> 2);
        }
        if (valid_chars >= 4 && out_idx < max_output) {
            output[out_idx++] = ((vals[2] & 0x03) << 6) | vals[3];
        }
    }

    return out_idx;
}

static void swap_endianness_chunks(uint8_t *data, size_t len, size_t word_size) {
    for (size_t i = 0; i < len; i += word_size) {
        size_t chunk_len = (i + word_size <= len) ? word_size : (len - i);
        /* Reverse the chunk in place */
        for (size_t j = 0; j < chunk_len / 2; j++) {
            uint8_t tmp = data[i + j];
            data[i + j] = data[i + chunk_len - 1 - j];
            data[i + chunk_len - 1 - j] = tmp;
        }
    }
}

/* Wordlist Loading */
/*------------------*/
static int load_wordlist(const char *path, char **words, size_t max_words) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: wordlist file not found: %s\n", path);
        return -1;
    }

    char line[MAX_WORD_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), f) && count < (int)max_words) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        words[count] = strdup(line);
        if (!words[count]) {
            fprintf(stderr, "Error: memory allocation failed\n");
            fclose(f);
            return -1;
        }
        count++;
    }

    fclose(f);
    return count;
}

static void free_wordlist(char **words, int count) {
    for (int i = 0; i < count; i++) {
        free(words[i]);
    }
}

/* Hash Parsing */
/*--------------*/
typedef struct {
    char subtype;
    int iter_exp;
    char iter_str[8];  /* Preserve original string like "00" */
    char salt_b64[32];
    char hash_b64[64];
} bcrypt_hash_t;

static int parse_bcrypt_hash(const char *hash_str, bcrypt_hash_t *parsed) {
    /* Expected format: $2a$05$SALT_22_CHARS_HASH_31_CHARS */
    if (hash_str[0] != '$') return -1;

    const char *p = hash_str + 1;

    /* Skip version (e.g., "2a", "2b", "2y") */
    const char *dollar2 = strchr(p, '$');
    if (!dollar2) return -1;

    /* Get subtype (second char of version, e.g., 'a' from '2a') */
    if (dollar2 - p >= 2) {
        parsed->subtype = p[1];
    } else {
        parsed->subtype = 'a';
    }

    p = dollar2 + 1;

    /* Parse iteration count */
    const char *dollar3 = strchr(p, '$');
    if (!dollar3) return -1;

    size_t iter_len = dollar3 - p;
    if (iter_len >= sizeof(parsed->iter_str)) return -1;
    strncpy(parsed->iter_str, p, iter_len);
    parsed->iter_str[iter_len] = '\0';
    parsed->iter_exp = atoi(parsed->iter_str);

    p = dollar3 + 1;

    /* Salt is first 22 chars, hash is next 31 chars */
    if (strlen(p) < 22 + 31) return -1;

    strncpy(parsed->salt_b64, p, 22);
    parsed->salt_b64[22] = '\0';

    strncpy(parsed->hash_b64, p + 22, 31);
    parsed->hash_b64[31] = '\0';

    return 0;
}

/* Help */
/*------*/
static void help(void) {
    printf("Cleanup2 Test - Bcrypt Hardware Test Utility\n"
           "usage: cleanup2_test [options]\n"
           "\n"
           "Options:\n"
           "  -h            Display this help message.\n"
           "  -d device_num Select the device (default = 0).\n"
           "  -w wordlist   Path to the wordlist file (one word per line).\n"
           "  -c hash       Hash string to crack.\n"
           "  -r            Send reset packet before starting test.\n");
    exit(1);
}

/* Main */
/*------*/
int main(int argc, char **argv) {
    int c;
    const char *wordlist_path = NULL;
    const char *hash_str = NULL;
    int do_reset = 0;

    /* Parameters */
    for (;;) {
        c = getopt(argc, argv, "hd:w:c:r");
        if (c == -1)
            break;
        switch (c) {
        case 'h':
            help();
            break;
        case 'd':
            litepcie_device_num = atoi(optarg);
            break;
        case 'w':
            wordlist_path = optarg;
            break;
        case 'c':
            hash_str = optarg;
            break;
        case 'r':
            do_reset = 1;
            break;
        default:
            exit(1);
        }
    }

    if (!wordlist_path || !hash_str) {
        fprintf(stderr, "Error: -w wordlist and -c hash are required\n");
        help();
    }

    /* Parse hash */
    printf("%s\n", hash_str);

    bcrypt_hash_t parsed;
    if (parse_bcrypt_hash(hash_str, &parsed) != 0) {
        fprintf(stderr, "Error: invalid bcrypt hash format\n");
        exit(1);
    }

    /* Split and print like Python - Python's split("$") includes empty first element */
    char *store[5];
    char hash_copy[256];
    strncpy(hash_copy, hash_str, sizeof(hash_copy) - 1);
    hash_copy[sizeof(hash_copy) - 1] = '\0';

    int store_count = 0;
    /* Python split("$") on "$2a$00$..." gives ['', '2a', '00', '...'] */
    /* Start with empty string since hash starts with $ */
    store[store_count++] = "";
    char *tok = strtok(hash_copy + 1, "$");  /* Skip first $ */
    while (tok && store_count < 5) {
        store[store_count++] = tok;
        tok = strtok(NULL, "$");
    }

    printf("[");
    for (int i = 0; i < store_count; i++) {
        printf("'%s'%s", store[i], (i < store_count - 1) ? ", " : "");
    }
    printf("]\n");

    printf("%c\n", parsed.subtype);
    printf("%s\n", parsed.iter_str);  /* Print as string to preserve leading zeros */
    printf("%s\n", parsed.salt_b64);
    printf("%s\n", parsed.hash_b64);

    /* Decode salt */
    uint8_t salt_decoded[32];
    size_t salt_len = custom_b64decode(parsed.salt_b64, salt_decoded, sizeof(salt_decoded));
    swap_endianness_chunks(salt_decoded, salt_len, 4);

    printf("b'");
    for (size_t i = 0; i < salt_len; i++)
        printf("\\x%02x", salt_decoded[i]);
    printf("'\n");

    /* Decode hash */
    uint8_t hash_decoded[32];
    size_t hash_len = custom_b64decode(parsed.hash_b64, hash_decoded, sizeof(hash_decoded));
    swap_endianness_chunks(hash_decoded, hash_len, 4);

    printf("b'");
    for (size_t i = 0; i < hash_len; i++)
        printf("\\x%02x", hash_decoded[i]);
    printf("'\n");

    /* Load wordlist */
    char *words[MAX_WORDS];
    int word_count = load_wordlist(wordlist_path, words, MAX_WORDS);
    if (word_count < 0) {
        exit(2);
    }

    /* Select device */
    snprintf(litepcie_device, sizeof(litepcie_device), "/dev/litepcie%d", litepcie_device_num);

    /* Open connection */
    int fd = litepcie_open_device();

    /* Optional: send reset packet to ensure clean FPGA state */
    if (do_reset) {
        send_reset(fd);
    }

    /* Drain any leftover packets from previous runs */
    printf("Draining output FIFO...\n");
    drain_output_fifo(fd);

    /* Build packets */
    uint32_t iter_count = 1U << parsed.iter_exp;

    /* Use first 16 bytes of salt */
    uint8_t salt16[16] = {0};
    size_t copy_len = salt_len < 16 ? salt_len : 16;
    memcpy(salt16, salt_decoded, copy_len);

    /* Get hash for comparison - decode fresh without endian swap for the comparison value */
    uint8_t hash_for_cmp[32];
    size_t hash_for_cmp_len = custom_b64decode(parsed.hash_b64, hash_for_cmp, sizeof(hash_for_cmp));
    uint32_t hashes[1];
    /* First 4 bytes as big-endian uint32 */
    hashes[0] = ((uint32_t)hash_for_cmp[0] << 24) |
                ((uint32_t)hash_for_cmp[1] << 16) |
                ((uint32_t)hash_for_cmp[2] << 8) |
                ((uint32_t)hash_for_cmp[3]);
    printf("[%u]\n", hashes[0]);

    /* Build CMP_CONFIG packet */
    uint8_t cmp_pl[128], cmp_hdr[10], pkt_cmp[256];
    size_t cmp_pl_len, pkt_cmp_len;
    build_cmp_config_payload_bcrypt(cmp_pl, &cmp_pl_len, iter_count, salt16, 'a', 1, hashes);
    build_header(cmp_hdr, PKT_TYPE_CMP_CONFIG, 0x0000, cmp_pl_len);
    add_checksums_around_payload(pkt_cmp, &pkt_cmp_len, cmp_hdr, 10, cmp_pl, cmp_pl_len);
    print_packet("CMP_CONFIG", pkt_cmp, pkt_cmp_len);

    /* Build WORD_LIST packet */
    uint8_t *wl_pl = malloc(MAX_WORDLIST_SIZE);
    uint8_t wl_hdr[10];
    uint8_t *pkt_wl = malloc(MAX_WORDLIST_SIZE + 32);
    size_t wl_pl_len, pkt_wl_len;
    if (!wl_pl || !pkt_wl) {
        fprintf(stderr, "Error: memory allocation failed\n");
        exit(1);
    }
    build_word_list_payload(wl_pl, &wl_pl_len, words, word_count);
    build_header(wl_hdr, PKT_TYPE_WORD_LIST, 0x0707, wl_pl_len);
    add_checksums_around_payload(pkt_wl, &pkt_wl_len, wl_hdr, 10, wl_pl, wl_pl_len);
    print_packet("WORD_LIST", pkt_wl, pkt_wl_len);

    /* Build WORD_GEN packet */
    uint8_t wg_pl[16], wg_hdr[10], pkt_wg[32];
    size_t wg_pl_len, pkt_wg_len;
    build_empty_word_gen_payload(wg_pl, &wg_pl_len);
    build_header(wg_hdr, PKT_TYPE_WORD_GEN, 0x3412, wg_pl_len);
    add_checksums_around_payload(pkt_wg, &pkt_wg_len, wg_hdr, 10, wg_pl, wg_pl_len);
    print_packet("WORD_GEN", pkt_wg, pkt_wg_len);

    /* Start recorder */
    start_recorder(fd);

    /* Stream packets */
    kick_streamer(fd, pkt_cmp, pkt_cmp_len);
    kick_streamer(fd, pkt_wg, pkt_wg_len);
    kick_streamer(fd, pkt_wl, pkt_wl_len);

    /* Read capture */
    uint32_t recorder_len = wait_recorder(fd);
    uint8_t *recorded_data = malloc(recorder_len + 64);
    if (!recorded_data) {
        fprintf(stderr, "Error: memory allocation failed\n");
        exit(1);
    }
    read_bytes(fd, RECORDER_MEM_BASE, recorded_data, recorder_len);

    printf("First 64 captured bytes:\n");
    size_t print_len = recorder_len < 64 ? recorder_len : 64;
    for (size_t i = 0; i < print_len; i++)
        printf("%02x ", recorded_data[i]);
    printf("\n");

    /* Read bcrypt status */
    uint32_t idle = 0xff, err = 0xff, ctrl = 0xff;
#ifdef CSR_BCRYPT_APP_STATUS_ADDR
    uint32_t app = litepcie_readl(fd, CSR_BCRYPT_APP_STATUS_ADDR);
    uint32_t pkt = litepcie_readl(fd, CSR_BCRYPT_PKT_COMM_STATUS_ADDR);
    ctrl = litepcie_readl(fd, CSR_BCRYPT_CTRL_ADDR);
    idle = litepcie_readl(fd, CSR_BCRYPT_IDLE_ADDR);
    err = litepcie_readl(fd, CSR_BCRYPT_ERROR_ADDR);
    printf("app_status=0x%02x pkt_comm_status=0x%02x bcrypt_ctrl=0x%02x bcrypt_idle=0x%02x bcrypt_error=0x%02x\n",
           app, pkt, ctrl, idle, err);
#endif

    printf("b'\\x%02x\\x%02x'\n", recorded_data[0], recorded_data[1]);

    if (recorder_len >= 2 && recorded_data[0] == 0x02 && recorded_data[1] == 0xd4) {
        printf("cracked\n");
        if (recorder_len >= 15) {
            printf("ID: %02x\n", recorded_data[14]);
            int word_id = recorded_data[14];
            if (word_id < word_count) {
                printf("%s:%s\n", hash_str, words[word_id]);
            }
        }
    }

    /* Drain any remaining packets */
    printf("Draining remaining packets...\n");
    drain_output_fifo(fd);

    /* Cleanup */
    litepcie_close_device(fd);
    free(wl_pl);
    free(pkt_wl);
    free(recorded_data);
    free_wordlist(words, word_count);

    printf("Test complete.\n");
    return 0;
}
