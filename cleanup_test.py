#!/usr/bin/env python3

#
# This file is part of LiteX-Bcrypt.
#
# test_bcrypt.py — Test Bcrypt Sim
# Demonstrates LiteX Bcrypt Proof-of-Concept (PoC) for flexible hardware acceleration.
#
# High-level:
# - Constructs and checksums application-level packets.
# - Streams packets via AXI8Streamer from streamer_mem @ 0x40100000.
# - Captures Bcrypt output into recorder_mem @ 0x40200000 using AXI8Recorder.
#

import argparse
import sys
from pathlib import Path
import base64

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

def build_cmp_config_payload_bcrypt(iter_count, salt16_bytes, subtype=b"a", hashes=None):
    assert len(salt16_bytes) == 16
    hashes = hashes or []
    p = list(salt16_bytes)
    p += [subtype[0]]
    p += le32(iter_count)
    p += le16(len(hashes))
    for h in hashes:
        p += le32(h)
    p += [0xCC]
    return p

def build_word_list_payload(words):
    p = []
    for w in words:
        p += [ord(c) for c in w] + [0x00]
    return p

def build_empty_word_gen_payload():
    return [0x00, 0x00, 0x00, 0x00, 0x00, 0xBB]

def build_word_gen_payload():
    return [0x00, 0x01, 0x00, 0x00, 0x00, 0xBB]

# Debug: Print packet
def print_packet(name, data):
    print(f"{name} ({len(data)} bytes): {' '.join(f'{b:02x}' for b in data)}")

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
RECORDER_MEM_BASE = 0x00080000

def kick_streamer(bus, pkt_bytes, timeout=10_000_000):
    """Write packet to streamer_mem and trigger streaming."""
    print(f"Writing {len(pkt_bytes)} bytes into streamer_mem @ 0x{STREAMER_MEM_BASE:08x}...")
    write_bytes(bus, STREAMER_MEM_BASE, pkt_bytes)
    bus.regs.streamer_length.write(len(pkt_bytes))
    bus.regs.streamer_kick.write(0)
    bus.regs.streamer_kick.write(1)
    cnt = 0
    while not bus.regs.streamer_done.read():
        cnt += 1
        if cnt >= timeout:
            raise RuntimeError("streamer timeout")
    print("  → streamer done")

def start_recorder(bus):
    """Start capture (records until .last)."""
    print("Starting recorder (captures until last packet)...")
    bus.regs.recorder_kick.write(0)
    bus.regs.recorder_kick.write(1)

def wait_recorder(bus, timeout=10_000_000):
    cnt = 0
    while not bus.regs.recorder_done.read():
        cnt += 1
        if cnt >= timeout:
            raise RuntimeError("recorder timeout")
    recorder_len = bus.regs.recorder_count.read()
    print(f"Recorder captured {recorder_len} bytes.")
    return recorder_len


def custom_b64decode(trans_table, s) -> bytes:
    """Decode string using the ./A-Za-z0-9 custom Base64 alphabet."""
    # Translate to standard Base64 alphabet
    std_b64 = s.translate(trans_table)
    # Pad with '=' if needed
    while len(std_b64) % 4:
        std_b64 += '='
    # Decode using standard base64
    return base64.b64decode(std_b64)

def swap_endianness_chunks(data: bytes, word_size: int = 4) -> bytes:
    """
    Swap endianness for fixed-size chunks of data.
    The last chunk (if incomplete) is reversed as-is, without padding or errors.

    Args:
        data (bytes): Input binary data.
        word_size (int): Chunk size in bytes (default: 4).

    Returns:
        bytes: Data with each chunk's endianness reversed.
    """
    swapped = []
    for i in range(0, len(data), word_size):
        chunk = data[i:i + word_size]
        swapped.append(chunk[::-1])
    return b''.join(swapped)


# Main ---------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Print each line from a wordlist file, then print a hash."
    )
    parser.add_argument("-w", "--wordlist", required=True,
                        help="Path to the wordlist file (one word per line).")
    parser.add_argument("-c", "--hash", required=True,
                        help="Hash string to print after the words.")
    args = parser.parse_args()

    wordlist_path = Path(args.wordlist)
    wordlist_ = []

    if not wordlist_path.is_file():
        print(f"Error: wordlist file not found: {wordlist_path}", file=sys.stderr)
        sys.exit(2)

    try:
        with wordlist_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # remove trailing newline only (preserve other whitespace)
                wordlist_.append(line.rstrip("\n"))
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    # After printing all words, print the hash exactly as provided
    print(args.hash)

    store = args.hash.split("$")
    subtype = store[1][1]
    iter = store[2]
    salt = store[3][:22]
    hash = store[3][22:]
    print(store)
    print(subtype)
    print(iter)
    print(salt)
    print(hash)

    custom_alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    std_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    trans_table = str.maketrans(custom_alphabet, std_alphabet)

    decoded_bytes = swap_endianness_chunks(custom_b64decode(trans_table, salt), 4)
    print(decoded_bytes)

    decoded_bytes = swap_endianness_chunks(custom_b64decode(trans_table, hash), 4)
    print(decoded_bytes)

    bus = RemoteClient()
    bus.open()

    # Build packets.
    cmp_id, wl_id, wg_id = 0x0001, 0x0002, 0x0003
    iter_count = 32
#    salt16     = bytes(range(0x10))
#    salt16     = bytes([0x10,0x04,0x41,0x10,0x41,0x10,0x04,0x41,0x04,0x41,0x10,0x04,0x10,0x04,0x41,0x10])
    salt16     = swap_endianness_chunks(custom_b64decode(trans_table, salt), 4)
#    hashes = [0x5c84350b]
    hashes = [int.from_bytes(custom_b64decode(trans_table, hash)[:4], byteorder='big')]
    print(hashes)

    cmp_pl  = build_cmp_config_payload_bcrypt(iter_count, salt16, b"a", hashes)
    cmp_hdr = build_header(PKT_TYPE_CMP_CONFIG, 0x0000, len(cmp_pl))
    pkt_cmp = add_checksums_around_payload(cmp_hdr, cmp_pl)
    print_packet("CMP_CONFIG", pkt_cmp)

#    wl_pl  = build_word_list_payload(["pass", "U*U*"])
#    wl_pl  = build_word_list_payload(["U*U*"])
    wl_pl  = build_word_list_payload(wordlist_)
    wl_hdr = build_header(PKT_TYPE_WORD_LIST, 0x0707, len(wl_pl))
    pkt_wl = add_checksums_around_payload(wl_hdr, wl_pl)
    print_packet("WORD_LIST", pkt_wl)

    wg_pl  = build_empty_word_gen_payload()
    wg_hdr = build_header(PKT_TYPE_WORD_GEN, 0x3412, len(wg_pl))
    pkt_wg = add_checksums_around_payload(wg_hdr, wg_pl)
    print_packet("WORD_GEN", pkt_wg)

    # Start recorder.
    start_recorder(bus)

    # Stream packets.
    kick_streamer(bus, pkt_cmp)
    kick_streamer(bus, pkt_wg)
    kick_streamer(bus, pkt_wl)

    # Read capture.
    recorder_len = wait_recorder(bus)
    recorded_data = read_bytes(bus, RECORDER_MEM_BASE, recorder_len)
    print("First 64 captured bytes:")
    print(" ".join(f"{b:02x}" for b in recorded_data[:64]))

    idle = 0xff
    err = 0xff
    ctrl = 0xff
    # Optional: read bcrypt status.
    try:
        app = bus.regs.bcrypt_app_status.read()
        pkt = bus.regs.bcrypt_pkt_comm_status.read()
        ctrl = bus.regs.bcrypt_ctrl.read()
        idle = bus.regs.bcrypt_idle.read()
        err = bus.regs.bcrypt_error.read()
        print(f"app_status=0x{app:02x} pkt_comm_status=0x{pkt:02x} bcrypt_ctrl=0x{ctrl:02x} bcrypt_idle=0x{idle:02x} bcrypt_error=0x{err:02x}")
    except Exception:
        pass

    print(recorded_data[0:2])

    if recorded_data[0:2] == b"\x02\xd4":
        print("cracked")
        print(f"ID: {recorded_data[14]:02x}")
        print(args.hash + ":" + wordlist_[recorded_data[14]])

    bus.close()
    print("Test complete.")

if __name__ == "__main__":
    main()
