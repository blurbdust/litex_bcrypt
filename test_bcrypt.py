#!/usr/bin/env python3
#
# This file is part of LiteX-Bcrypt.
#
# test_bcrypt.py — Bcrypt Basic Test
#
# Initializes the Bcrypt accelerator once with CMP_CONFIG, then runs multiple
# password hashing operations (WORD_LIST + WORD_GEN) and reports performance.
#
import time

from litex import RemoteClient

# Packet helpers -----------------------------------------------------------------------------------

PKT_VERSION         = 2
PKT_TYPE_WORD_LIST  = 0x01
PKT_TYPE_WORD_GEN   = 0x02
PKT_TYPE_CMP_CONFIG = 0x03

def le16(x): return [x & 0xFF, (x >> 8) & 0xFF]
def le24(x): return [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF]
def le32(x): return [(x >> (8*i)) & 0xFF for i in range(4)]

def build_header(pkt_type, pkt_id, payload_len, version=PKT_VERSION):
    return [version, pkt_type, 0x00, 0x00, *le24(payload_len), 0x00, *le16(pkt_id)]

def _csum32_le(bs):
    s = 0
    for i in range(0, len(bs), 4):
        w = bs[i:i+4] + [0]*(4 - len(bs[i:i+4]))
        s = (s + (w[0] | (w[1] << 8) | (w[2] << 16) | (w[3] << 24))) & 0xFFFFFFFF
    s ^= 0xFFFFFFFF
    return [s & 0xFF, (s >> 8) & 0xFF, (s >> 16) & 0xFF, (s >> 24) & 0xFF]

def add_checksums_around_payload(header_bytes, payload_bytes):
    return header_bytes + _csum32_le(header_bytes) + payload_bytes + _csum32_le(payload_bytes)

def build_cmp_config_payload_bcrypt(iter_count, salt16_bytes, subtype=b"b", hashes=None):
    assert len(salt16_bytes) == 16
    hashes = hashes or []
    p = list(salt16_bytes)
    p += [subtype[0]]
    p += le32(iter_count)
    p += le16(len(hashes))
    for h in hashes:
        p += le32(h & 0x7FFFFFFF)
    p += [0xCC]
    return p

def build_word_list_payload(words):
    p = []
    for w in words:
        p += [ord(c) for c in w] + [0x00]
    return p

def build_word_gen_payload():
    return [0x00, 0x01, 0x00, 0x00, 0x00, 0xBB]

# Wishbone helpers ---------------------------------------------------------------------------------

def write_bytes(bus, base, data_bytes):
    buf = list(data_bytes)
    if len(buf) & 3:
        buf += [0] * (4 - (len(buf) & 3))
    for i in range(0, len(buf), 4):
        w = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
        bus.write(base + i, w)

def read_bytes(bus, base, length):
    data = bytearray()
    words = (length + 3)//4
    for i in range(words):
        w = bus.read(base + 4*i)
        data.extend([w & 0xFF, (w>>8)&0xFF, (w>>16)&0xFF, (w>>24)&0xFF])
    return bytes(data[:length])

# Streamer / Recorder control ----------------------------------------------------------------------

STREAMER_MEM_BASE = 0x00040000

def kick_streamer(bus, pkt_bytes, timeout=10_000_000):
    write_bytes(bus, STREAMER_MEM_BASE, pkt_bytes)
    bus.regs.streamer_length.write(len(pkt_bytes))
    bus.regs.streamer_kick.write(0)
    bus.regs.streamer_kick.write(1)
    cnt = 0
    while not bus.regs.streamer_done.read():
        cnt += 1
        if cnt >= timeout:
            raise RuntimeError("streamer timeout")

def start_recorder(bus):
    bus.regs.recorder_kick.write(0)
    bus.regs.recorder_kick.write(1)

def wait_recorder(bus, timeout=10_000_000):
    cnt = 0
    while not bus.regs.recorder_done.read():
        cnt += 1
        if cnt >= timeout:
            raise RuntimeError("recorder timeout")
    return bus.regs.recorder_count.read()

# Main ---------------------------------------------------------------------------------------------

def main():
    bus = RemoteClient()
    bus.open()

    # Build packets.
    cmp_id, wl_id, wg_id = 0x0001, 0x0002, 0x0003
    iter_count = 5
    salt16 = bytes(range(0x10))
    hashes = [0]

    cmp_pl = build_cmp_config_payload_bcrypt(iter_count, salt16, b"b", hashes)
    cmp_hdr = build_header(PKT_TYPE_CMP_CONFIG, cmp_id, len(cmp_pl))
    pkt_cmp = add_checksums_around_payload(cmp_hdr, cmp_pl)

    wl_pl = build_word_list_payload(["pass"])
    wl_hdr = build_header(PKT_TYPE_WORD_LIST, wl_id, len(wl_pl))
    pkt_wl = add_checksums_around_payload(wl_hdr, wl_pl)

    wg_pl = build_word_gen_payload()
    wg_hdr = build_header(PKT_TYPE_WORD_GEN, wg_id, len(wg_pl))
    pkt_wg = add_checksums_around_payload(wg_hdr, wg_pl)

    # Initialize core (no response expected).
    print("\033[1m[> Initializing Bcrypt core...\033[0m")
    kick_streamer(bus, pkt_cmp)

    # Run performance test.
    runs = 10
    total_time = 0.0
    total_hashes = 0

    print(f"\n\033[1m[> Running {runs} iterations (1 password per run)...\033[0m")
    print(f"{'Run':>3} {'Out':>4} {'Time(s)':>8} {'H/s':>10} {'Hash'}")
    print("-" * 55)

    for run in range(runs):
        start_time = time.time()

        start_recorder(bus)
        kick_streamer(bus, pkt_wl)
        kick_streamer(bus, pkt_wg)
        out_len = wait_recorder(bus)
        result = read_bytes(bus, 0x00080000, out_len)

        elapsed = time.time() - start_time
        hps = 1.0 / elapsed if elapsed > 0 else 0

        total_time += elapsed
        total_hashes += 1

        hash_hex = ''.join(f'{b:02x}' for b in result)
        print(f"{run+1:>3} {out_len:>4} {elapsed:>8.3f} {hps:>10.0f} {hash_hex}")

    # Final statistics.
    avg_hps = total_hashes / total_time
    print("-" * 55)
    print(f"Total: {total_hashes} hashes in {total_time:.3f} s → {avg_hps:,.0f} H/s")

    # Optional: read status.
    try:
        app = bus.regs.bcrypt_app_status.read()
        pkt = bus.regs.bcrypt_pkt_comm_status.read()
        print(f"\033[1m[> app_status=0x{app:02x} pkt_comm_status=0x{pkt:02x}\033[0m")
    except Exception:
        pass

    bus.close()
    print("\033[1m[> Test complete.\033[0m")

if __name__ == "__main__":
    main()