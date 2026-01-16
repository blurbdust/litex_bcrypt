#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include "liblitepcie.h"
#include "csr.h"
#include "mem.h"

/*
 * LiteX-Bcrypt Cleanup Test
 *
 * Port of cleanup_test.py to C, using the same LitePCIe communication
 * helpers and Wishbone access style as bcrypt_test.c.
 */

/* LitePCIe device handling --------------------------------------------------*/

static char litepcie_device[1024];
static int litepcie_device_num = 0;

static int litepcie_open_dev(void) {
    int fd = open(litepcie_device, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Could not init driver\n");
        exit(1);
    }
    return fd;
}

static void litepcie_close_dev(int fd) {
    close(fd);
}

/* Packet helpers ------------------------------------------------------------*/

#define PKT_VERSION         2
#define PKT_TYPE_WORD_LIST  0x01
#define PKT_TYPE_WORD_GEN   0x02
#define PKT_TYPE_CMP_CONFIG 0x03
#define PKT_TYPE_RESET      0x05

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
            w |= ((uint32_t)data[i + j]) << (8 * j);
        sum = (sum + w) & 0xFFFFFFFF;
    }
    return sum ^ 0xFFFFFFFF;
}

static void add_checksums(uint8_t *pkt, size_t *len,
                          const uint8_t *header, size_t hlen,
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

static void build_header(uint8_t *hdr,
                         uint8_t pkt_type,
                         uint16_t pkt_id,
                         uint32_t payload_len,
                         uint8_t version) {
    memset(hdr, 0, 10);
    hdr[0] = version;
    hdr[1] = pkt_type;
    le24(payload_len, hdr + 4);
    le16(pkt_id, hdr + 8);
}

static void build_cmp_config_payload_bcrypt(uint8_t *out, size_t *len,
                                            uint32_t iter_count,
                                            const uint8_t *salt16,
                                            uint8_t subtype,
                                            size_t nhashes,
                                            const uint32_t *hashes) {
    uint8_t *p = out;
    memcpy(p, salt16, 16);
    p += 16;
    *p++ = subtype;
    le32(iter_count, p);
    p += 4;
    le16((uint16_t)nhashes, p);
    p += 2;
    for (size_t i = 0; i < nhashes; i++) {
        le32(hashes[i], p);
        p += 4;
    }
    *p++ = 0xCC;
    *len = (size_t)(p - out);
}

static void build_word_list_payload(uint8_t *out, size_t *len,
                                    char **words, size_t nwords) {
    uint8_t *p = out;
    for (size_t i = 0; i < nwords; i++) {
        const char *w = words[i];
        while (*w) {
            *p++ = (uint8_t)*w++;
        }
        *p++ = 0x00;
    }
    *len = (size_t)(p - out);
}

static void build_empty_word_gen_payload(uint8_t *out, size_t *len) {
    uint8_t payload[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0xBB};
    memcpy(out, payload, sizeof(payload));
    *len = sizeof(payload);
}

static void print_packet(const char *name, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes):", name, len);
    for (size_t i = 0; i < len; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
}

/* Wishbone helpers ----------------------------------------------------------*/

static void write_bytes(int fd, uint32_t base, const uint8_t *data, size_t len) {
    uint8_t buf[4];
    for (size_t i = 0; i < len; i += 4) {
        size_t rem = (len - i > 4) ? 4 : (len - i);
        memset(buf, 0, 4);
        memcpy(buf, data + i, rem);
        uint32_t w = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
        litepcie_writel(fd, base + (uint32_t)i, w);
    }
}

static void read_bytes(int fd, uint32_t base, uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = litepcie_readl(fd, base + (uint32_t)i);
        size_t rem = (len - i > 4) ? 4 : (len - i);
        for (size_t j = 0; j < rem; j++) {
            data[i + j] = (uint8_t)((w >> (8 * j)) & 0xFF);
        }
    }
}

/* Streamer / Recorder control -----------------------------------------------*/

static void kick_streamer(int fd, const uint8_t *pkt_bytes, size_t pkt_len) {
    const uint32_t timeout = 10000000;
    uint32_t cnt = 0;

    printf("Writing %zu bytes into streamer_mem @ 0x%08x...\n",
           pkt_len, (unsigned)STREAMER_MEM_BASE);
    write_bytes(fd, STREAMER_MEM_BASE, pkt_bytes, pkt_len);
    litepcie_writel(fd, CSR_STREAMER_LENGTH_ADDR, pkt_len);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 0);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 1);
    while (!litepcie_readl(fd, CSR_STREAMER_DONE_ADDR)) {
        cnt++;
        if (cnt >= timeout) {
            fprintf(stderr, "streamer timeout\n");
            exit(1);
        }
    }
    printf("  \xe2\x86\x92 streamer done\n");
}

static void start_recorder(int fd) {
    printf("Starting recorder (captures until last packet)...\n");
    litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 0);
    litepcie_writel(fd, CSR_RECORDER_KICK_ADDR, 1);
}

static uint32_t wait_recorder(int fd) {
    const uint32_t timeout = 10000000;
    uint32_t cnt = 0;
    while (!litepcie_readl(fd, CSR_RECORDER_DONE_ADDR)) {
        cnt++;
        if (cnt >= timeout) {
            fprintf(stderr, "recorder timeout\n");
            exit(1);
        }
    }
    uint32_t recorder_len = litepcie_readl(fd, CSR_RECORDER_COUNT_ADDR);
    printf("Recorder captured %u bytes.\n", recorder_len);
    return recorder_len;
}

static void send_reset(int fd) {
    /* Send reset packet to clear FPGA state */
    const uint32_t timeout = 10000000;
    uint32_t cnt = 0;

    uint8_t reset_pl[] = {0xCC};  /* Minimal payload with magic byte */
    uint8_t hdr[10];
    build_header(hdr, PKT_TYPE_RESET, 0x0000, sizeof(reset_pl), PKT_VERSION);
    uint8_t pkt_reset[32];
    size_t pkt_reset_len = 0;
    add_checksums(pkt_reset, &pkt_reset_len, hdr, 10, reset_pl, sizeof(reset_pl));

    printf("Sending reset packet to clear FPGA state...\n");
    write_bytes(fd, STREAMER_MEM_BASE, pkt_reset, pkt_reset_len);
    litepcie_writel(fd, CSR_STREAMER_LENGTH_ADDR, pkt_reset_len);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 0);
    litepcie_writel(fd, CSR_STREAMER_KICK_ADDR, 1);
    while (!litepcie_readl(fd, CSR_STREAMER_DONE_ADDR)) {
        cnt++;
        if (cnt >= timeout) {
            fprintf(stderr, "reset streamer timeout\n");
            exit(1);
        }
    }
    printf("  \xe2\x86\x92 reset complete\n");
}

/* Base64 helpers (custom alphabet) ------------------------------------------*/

static void make_custom_to_std_table(char table[256]) {
    const char *custom_alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const char *std_alphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 256; i++) {
        table[i] = (char)i;
    }
    for (int i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)custom_alphabet[i];
        table[c] = std_alphabet[i];
    }
}

static uint8_t *base64_decode_std(const char *in, size_t *out_len) {
    static int8_t table[256];
    static int initialized = 0;
    if (!initialized) {
        for (int i = 0; i < 256; i++) table[i] = -1;
        for (int i = 'A'; i <= 'Z'; i++) table[i] = (int8_t)(i - 'A');
        for (int i = 'a'; i <= 'z'; i++) table[i] = (int8_t)(26 + i - 'a');
        for (int i = '0'; i <= '9'; i++) table[i] = (int8_t)(52 + i - '0');
        table[(unsigned char)'+'] = 62;
        table[(unsigned char)'/'] = 63;
        initialized = 1;
    }

    size_t in_len = strlen(in);
    if (in_len % 4 != 0) {
        /* Should be padded to multiple of 4 */
        fprintf(stderr, "base64 input length not multiple of 4\n");
        *out_len = 0;
        return NULL;
    }

    size_t max_out = (in_len / 4) * 3;
    uint8_t *out = (uint8_t *)malloc(max_out);
    if (!out) {
        fprintf(stderr, "Out of memory in base64_decode_std\n");
        *out_len = 0;
        return NULL;
    }

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        int8_t v[4];
        int pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                v[j] = 0;
                pad++;
            } else {
                v[j] = table[(unsigned char)c];
                if (v[j] < 0) {
                    fprintf(stderr, "Invalid base64 character '%c'\n", c);
                    free(out);
                    *out_len = 0;
                    return NULL;
                }
            }
        }

        uint32_t triple = ((uint32_t)v[0] << 18) |
                          ((uint32_t)v[1] << 12) |
                          ((uint32_t)v[2] << 6)  |
                          (uint32_t)v[3];

        if (pad == 0) {
            out[o++] = (uint8_t)((triple >> 16) & 0xFF);
            out[o++] = (uint8_t)((triple >> 8) & 0xFF);
            out[o++] = (uint8_t)(triple & 0xFF);
        } else if (pad == 1) {
            out[o++] = (uint8_t)((triple >> 16) & 0xFF);
            out[o++] = (uint8_t)((triple >> 8) & 0xFF);
        } else if (pad == 2) {
            out[o++] = (uint8_t)((triple >> 16) & 0xFF);
        }
    }

    *out_len = o;
    return out;
}

static uint8_t *custom_b64decode(const char trans_table[256],
                                 const char *s,
                                 size_t *out_len) {
    size_t in_len = strlen(s);
    /* translate */
    size_t buf_cap = in_len + 4;
    char *std = (char *)malloc(buf_cap + 1);
    if (!std) {
        fprintf(stderr, "Out of memory in custom_b64decode\n");
        *out_len = 0;
        return NULL;
    }
    size_t n = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)s[i];
        std[n++] = trans_table[c];
    }
    while (n % 4 != 0) {
        std[n++] = '=';
    }
    std[n] = '\0';

    uint8_t *decoded = base64_decode_std(std, out_len);
    free(std);
    return decoded;
}

/* Endianness helper ---------------------------------------------------------*/

static uint8_t *swap_endianness_chunks(const uint8_t *data, size_t len,
                                       size_t word_size) {
    uint8_t *out = (uint8_t *)malloc(len);
    if (!out) {
        fprintf(stderr, "Out of memory in swap_endianness_chunks\n");
        return NULL;
    }
    for (size_t i = 0; i < len; i += word_size) {
        size_t chunk_len = (len - i > word_size) ? word_size : (len - i);
        for (size_t j = 0; j < chunk_len; j++) {
            out[i + j] = data[i + chunk_len - 1 - j];
        }
    }
    return out;
}

/* Printing helpers ----------------------------------------------------------*/

static void print_bytes_repr(const uint8_t *data, size_t len) {
    putchar('b');
    putchar('\'');
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        if (c == '\\\\' || c == '\'') {
            putchar('\\');
            putchar(c);
        } else if (c >= 32 && c < 127 && c != '\\\\' && c != '\'') {
            putchar(c);
        } else {
            printf("\\\\x%02x", c);
        }
    }
    putchar('\'');
    putchar('\n');
}

/* Wordlist container --------------------------------------------------------*/

typedef struct {
    char **data;
    size_t count;
    size_t capacity;
} WordList;

static void wordlist_init(WordList *wl) {
    wl->data = NULL;
    wl->count = 0;
    wl->capacity = 0;
}

static void wordlist_push(WordList *wl, const char *line) {
    if (wl->count == wl->capacity) {
        size_t new_cap = wl->capacity ? wl->capacity * 2 : 16;
        char **new_data = (char **)realloc(wl->data, new_cap * sizeof(char *));
        if (!new_data) {
            fprintf(stderr, "Out of memory in wordlist_push\n");
            exit(1);
        }
        wl->data = new_data;
        wl->capacity = new_cap;
    }
    wl->data[wl->count] = strdup(line);
    if (!wl->data[wl->count]) {
        fprintf(stderr, "Out of memory duplicating word\n");
        exit(1);
    }
    wl->count++;
}

static void wordlist_free(WordList *wl) {
    for (size_t i = 0; i < wl->count; i++) {
        free(wl->data[i]);
    }
    free(wl->data);
    wl->data = NULL;
    wl->count = 0;
    wl->capacity = 0;
}

/* Cleanup test core ---------------------------------------------------------*/

static void cleanup_test(int fd, const char *wordlist_path, const char *hash_str) {
    WordList wl;
    wordlist_init(&wl);

    /* Read wordlist file */
    FILE *f = fopen(wordlist_path, "r");
    if (!f) {
        fprintf(stderr, "Error: wordlist file not found: %s\n", wordlist_path);
        exit(2);
    }

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    while ((linelen = getline(&line, &linecap, f)) != -1) {
        /* strip trailing newline only */
        if (linelen > 0 && line[linelen - 1] == '\n') {
            line[linelen - 1] = '\0';
        }
        wordlist_push(&wl, line);
    }
    free(line);
    fclose(f);

    /* After printing all words, print the hash exactly as provided */
    printf("%s\n", hash_str);

    /* Parse bcrypt hash: "$2a$10$<22salt><31hash>" */
    const char *h = hash_str;
    const char *p1 = strchr(h + 1, '$');
    const char *p2 = p1 ? strchr(p1 + 1, '$') : NULL;
    if (!p1 || !p2) {
        fprintf(stderr, "Invalid bcrypt hash format\n");
        wordlist_free(&wl);
        exit(1);
    }

    size_t type_len = (size_t)(p1 - (h + 1));
    size_t iter_len = (size_t)(p2 - (p1 + 1));
    size_t rest_len = strlen(p2 + 1);

    char type_str[16];
    char iter_str[16];
    char *rest_str = (char *)malloc(rest_len + 1);

    if (type_len >= sizeof(type_str)) type_len = sizeof(type_str) - 1;
    if (iter_len >= sizeof(iter_str)) iter_len = sizeof(iter_str) - 1;

    memcpy(type_str, h + 1, type_len);
    type_str[type_len] = '\0';

    memcpy(iter_str, p1 + 1, iter_len);
    iter_str[iter_len] = '\0';

    memcpy(rest_str, p2 + 1, rest_len);
    rest_str[rest_len] = '\0';

    /* store = ["", type_str, iter_str, rest_str] */
    printf("['', '%s', '%s', '%s']\n", type_str, iter_str, rest_str);

    char subtype = (type_str[0] != '\0' && type_str[1] != '\0') ? type_str[1] : '?';
    printf("%c\n", subtype);
    printf("%s\n", iter_str);

    /* salt = first 22 chars, hash = remainder */
    if (rest_len < 22) {
        fprintf(stderr, "Invalid bcrypt salt/hash portion\n");
        free(rest_str);
        wordlist_free(&wl);
        exit(1);
    }

    char salt[23];
    memcpy(salt, rest_str, 22);
    salt[22] = '\0';

    char *hash_part = strdup(rest_str + 22);
    if (!hash_part) {
        fprintf(stderr, "Out of memory for hash_part\n");
        free(rest_str);
        wordlist_free(&wl);
        exit(1);
    }

    printf("%s\n", salt);
    printf("%s\n", hash_part);

    /* Base64 decoding with custom alphabet */
    char trans_table[256];
    make_custom_to_std_table(trans_table);

    size_t salt_dec_len = 0;
    uint8_t *salt_dec = custom_b64decode(trans_table, salt, &salt_dec_len);
    if (!salt_dec) {
        free(rest_str);
        free(hash_part);
        wordlist_free(&wl);
        exit(1);
    }
    uint8_t *salt_swapped = swap_endianness_chunks(salt_dec, salt_dec_len, 4);
    if (!salt_swapped) {
        free(salt_dec);
        free(rest_str);
        free(hash_part);
        wordlist_free(&wl);
        exit(1);
    }
    print_bytes_repr(salt_swapped, salt_dec_len);

    size_t hash_dec_len = 0;
    uint8_t *hash_dec = custom_b64decode(trans_table, hash_part, &hash_dec_len);
    if (!hash_dec) {
        free(salt_dec);
        free(salt_swapped);
        free(rest_str);
        free(hash_part);
        wordlist_free(&wl);
        exit(1);
    }
    uint8_t *hash_swapped = swap_endianness_chunks(hash_dec, hash_dec_len, 4);
    if (!hash_swapped) {
        free(salt_dec);
        free(salt_swapped);
        free(hash_dec);
        free(rest_str);
        free(hash_part);
        wordlist_free(&wl);
        exit(1);
    }
    print_bytes_repr(hash_swapped, hash_dec_len);

    /* Build packets */
    uint16_t cmp_id = 0x0001;
    uint16_t wl_id  = 0x0707;
    uint16_t wg_id  = 0x3412;

    uint32_t iter_count = 1u << (uint32_t)atoi(iter_str);

    /* salt16 is swapped salt bytes (expect 16 bytes) */
    if (salt_dec_len < 16) {
        fprintf(stderr, "Decoded salt length < 16\n");
        free(salt_dec);
        free(salt_swapped);
        free(hash_dec);
        free(hash_swapped);
        free(rest_str);
        free(hash_part);
        wordlist_free(&wl);
        exit(1);
    }
    uint8_t salt16[16];
    memcpy(salt16, salt_swapped, 16);

    /* hashes = [int.from_bytes(custom_b64decode(hash)[:4], 'big')] */
    if (hash_dec_len < 4) {
        fprintf(stderr, "Decoded hash length < 4\n");
        free(salt_dec);
        free(salt_swapped);
        free(hash_dec);
        free(hash_swapped);
        free(rest_str);
        free(hash_part);
        wordlist_free(&wl);
        exit(1);
    }
    uint32_t h0 = ((uint32_t)hash_dec[0] << 24) |
                  ((uint32_t)hash_dec[1] << 16) |
                  ((uint32_t)hash_dec[2] << 8)  |
                  (uint32_t)hash_dec[3];
    uint32_t hashes[1];
    hashes[0] = h0;
    printf("[%u]\n", hashes[0]);

    uint8_t cmp_pl[128];
    size_t cmp_pl_len = 0;
    build_cmp_config_payload_bcrypt(cmp_pl, &cmp_pl_len,
                                    iter_count, salt16,
                                    (uint8_t)subtype,
                                    1, hashes);
    uint8_t hdr[10];
    build_header(hdr, PKT_TYPE_CMP_CONFIG, cmp_id, (uint32_t)cmp_pl_len, PKT_VERSION);
    uint8_t pkt_cmp[256];
    size_t pkt_cmp_len = 0;
    add_checksums(pkt_cmp, &pkt_cmp_len, hdr, 10, cmp_pl, cmp_pl_len);
    print_packet("CMP_CONFIG", pkt_cmp, pkt_cmp_len);

    uint8_t wl_pl[4096];
    size_t wl_pl_len = 0;
    build_word_list_payload(wl_pl, &wl_pl_len, wl.data, wl.count);
    uint8_t wl_hdr[10];
    build_header(wl_hdr, PKT_TYPE_WORD_LIST, wl_id, (uint32_t)wl_pl_len, PKT_VERSION);
    uint8_t pkt_wl[8192];
    size_t pkt_wl_len = 0;
    add_checksums(pkt_wl, &pkt_wl_len, wl_hdr, 10, wl_pl, wl_pl_len);
    print_packet("WORD_LIST", pkt_wl, pkt_wl_len);

    uint8_t wg_pl[32];
    size_t wg_pl_len = 0;
    build_empty_word_gen_payload(wg_pl, &wg_pl_len);
    uint8_t wg_hdr[10];
    build_header(wg_hdr, PKT_TYPE_WORD_GEN, wg_id, (uint32_t)wg_pl_len, PKT_VERSION);
    uint8_t pkt_wg[256];
    size_t pkt_wg_len = 0;
    add_checksums(pkt_wg, &pkt_wg_len, wg_hdr, 10, wg_pl, wg_pl_len);
    print_packet("WORD_GEN", pkt_wg, pkt_wg_len);

    /* Start recorder */
    start_recorder(fd);

    /* Stream packets: CMP, WORD_GEN, WORD_LIST */
    kick_streamer(fd, pkt_cmp, pkt_cmp_len);
    kick_streamer(fd, pkt_wg, pkt_wg_len);
    kick_streamer(fd, pkt_wl, pkt_wl_len);

    /* Read capture */
    uint32_t recorder_len = wait_recorder(fd);
    uint8_t *recorded_data = (uint8_t *)malloc(recorder_len);
    if (!recorded_data) {
        fprintf(stderr, "Out of memory for recorded_data\n");
        free(salt_dec);
        free(salt_swapped);
        free(hash_dec);
        free(hash_swapped);
        free(rest_str);
        free(hash_part);
        wordlist_free(&wl);
        exit(1);
    }
    read_bytes(fd, RECORDER_MEM_BASE, recorded_data, recorder_len);
    printf("First 64 captured bytes:\n");
    size_t to_print = (recorder_len < 64) ? recorder_len : 64;
    for (size_t i = 0; i < to_print; i++) {
        printf("%02x", recorded_data[i]);
        if (i + 1 < to_print) printf(" ");
    }
    printf("\n");

    /* Status registers */
    uint32_t app = 0xff;
    uint32_t pkt = 0xff;
    uint32_t ctrl = 0xff;
    uint32_t idle = 0xff;
    uint32_t err = 0xff;

    /* Attempt to read, if CSRs exist */
    app = litepcie_readl(fd, CSR_BCRYPT_APP_STATUS_ADDR);
    pkt = litepcie_readl(fd, CSR_BCRYPT_PKT_COMM_STATUS_ADDR);
#ifdef CSR_BCRYPT_CTRL_ADDR
    ctrl = litepcie_readl(fd, CSR_BCRYPT_CTRL_ADDR);
#endif
#ifdef CSR_BCRYPT_IDLE_ADDR
    idle = litepcie_readl(fd, CSR_BCRYPT_IDLE_ADDR);
#endif
#ifdef CSR_BCRYPT_ERROR_ADDR
    err = litepcie_readl(fd, CSR_BCRYPT_ERROR_ADDR);
#endif

    printf("app_status=0x%02x pkt_comm_status=0x%02x bcrypt_ctrl=0x%02x bcrypt_idle=0x%02x bcrypt_error=0x%02x\n",
           app & 0xFF, pkt & 0xFF, ctrl & 0xFF, idle & 0xFF, err & 0xFF);

    /* Print first two bytes as bytes repr */
    if (recorder_len >= 2) {
        print_bytes_repr(recorded_data, 2);
    } else {
        uint8_t tmp[2] = {0, 0};
        print_bytes_repr(tmp, 2);
    }

    if (recorder_len >= 2 && recorded_data[0] == 0x02 && recorded_data[1] == 0xd4) {
        printf("cracked\n");
        if (recorder_len > 14) {
            uint8_t id = recorded_data[14];
            printf("ID: %02x\n", id);
            if (id < wl.count) {
                printf("%s:%s\n", hash_str, wl.data[id]);
            }
        }
    }

    /* Cleanup */
    free(recorded_data);
    free(salt_dec);
    free(salt_swapped);
    free(hash_dec);
    free(hash_swapped);
    free(rest_str);
    free(hash_part);
    wordlist_free(&wl);

    printf("Test complete.\n");
}

/* Help ----------------------------------------------------------------------*/

static void help(void) {
    printf("Bcrypt Cleanup Test Utility\n"
           "usage: cleanup_test [options]\n"
           "\n"
           "Options:\n"
           "-h            Display this help message.\n"
           "-r            Send reset packet before test to clear FPGA state.\n"
           "-w wordlist   Path to wordlist file (one word per line).\n"
           "-c hash       Hash string to print after the words and use for config.\n");
    exit(1);
}

/* Main ----------------------------------------------------------------------*/

int main(int argc, char **argv) {
    int opt;
    const char *wordlist_path = NULL;
    const char *hash_str = NULL;
    int do_reset = 0;

    while ((opt = getopt(argc, argv, "hrw:c:")) != -1) {
        switch (opt) {
        case 'h':
            help();
            break;
        case 'r':
            do_reset = 1;
            break;
        case 'w':
            wordlist_path = optarg;
            break;
        case 'c':
            hash_str = optarg;
            break;
        default:
            help();
            break;
        }
    }

    if (!wordlist_path || !hash_str) {
        help();
    }

    /* Select device (default 0, same style as bcrypt_test.c) */
    litepcie_device_num = 0;
    snprintf(litepcie_device, sizeof(litepcie_device),
             "/dev/litepcie%d", litepcie_device_num);

    int fd = litepcie_open_dev();

    if (do_reset) {
        send_reset(fd);
    }

    cleanup_test(fd, wordlist_path, hash_str);
    litepcie_close_dev(fd);
    return 0;
}

