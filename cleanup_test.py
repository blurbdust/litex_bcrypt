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
PKT_TYPE_RESET      = 0x05

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

def send_reset(bus):
    """Send reset packet to clear FPGA state."""
    reset_pl = [0xCC]  # Minimal payload with magic byte
    reset_hdr = build_header(PKT_TYPE_RESET, 0x0000, len(reset_pl))
    pkt_reset = add_checksums_around_payload(reset_hdr, reset_pl)
    print("Sending reset packet to clear FPGA state...")
    write_bytes(bus, STREAMER_MEM_BASE, pkt_reset)
    bus.regs.streamer_length.write(len(pkt_reset))
    bus.regs.streamer_kick.write(0)
    bus.regs.streamer_kick.write(1)
    cnt = 0
    while not bus.regs.streamer_done.read():
        cnt += 1
        if cnt >= 10_000_000:
            raise RuntimeError("reset streamer timeout")
    print("  → reset complete")


def drain_output_fifo(bus, short_timeout=5_000, max_packets=10):
    """Drain any leftover packets from the output FIFO.

    After a successful match, the FPGA outputs both CMP_RESULT and PACKET_DONE.
    If the recorder only captures the first packet, the second remains in the
    FIFO and will be captured on the next run, causing alternating behavior.

    This function repeatedly starts the recorder with a short timeout until
    no more data is captured.

    Args:
        bus: RemoteClient connection
        short_timeout: iterations to wait before assuming FIFO is empty (default 5000)
        max_packets: maximum packets to drain to prevent infinite loop (default 10)

    Returns:
        Total bytes drained
    """
    total_drained = 0
    packets_drained = 0

    while packets_drained < max_packets:
        # Start recorder
        bus.regs.recorder_kick.write(0)
        bus.regs.recorder_kick.write(1)

        # Wait with short timeout
        cnt = 0
        while not bus.regs.recorder_done.read():
            cnt += 1
            if cnt >= short_timeout:
                # Timeout - no more data pending
                if total_drained > 0:
                    print(f"  → drained {packets_drained} packet(s), {total_drained} bytes total")
                else:
                    print("  → FIFO empty (nothing to drain)")
                return total_drained

        # Check how much was captured
        captured = bus.regs.recorder_count.read()
        if captured == 0:
            # No data captured
            if total_drained > 0:
                print(f"  → drained {packets_drained} packet(s), {total_drained} bytes total")
            else:
                print("  → FIFO empty (nothing to drain)")
            return total_drained

        # Data was captured - read and display it
        packets_drained += 1
        total_drained += captured

        discarded = read_bytes(bus, RECORDER_MEM_BASE, captured)
        pkt_type = discarded[1] if len(discarded) > 1 else 0

        # Parse and display packet contents
        if pkt_type == 0xd2 and len(discarded) >= 18:
            # PACKET_DONE: version(1) + type(1) + checksum(2) + len(4) + pkt_id(2) + checksum(4) + num_processed(4)
            pkt_id = int.from_bytes(discarded[8:10], 'little')
            num_processed = int.from_bytes(discarded[14:18], 'little')
            print(f"  [drain] PACKET_DONE (0xd2): pkt_id=0x{pkt_id:04x}, num_processed={num_processed}")
        elif pkt_type == 0xd4 and len(discarded) >= 22:
            # CMP_RESULT: includes hash_num and result
            pkt_id = int.from_bytes(discarded[8:10], 'little')
            # Payload starts at offset 14: word_id(2) + gen_id(4) + hash_num(2) + result...
            hash_num = int.from_bytes(discarded[20:22], 'little') if len(discarded) >= 22 else 0
            print(f"  [drain] CMP_RESULT (0xd4): pkt_id=0x{pkt_id:04x}, hash_num={hash_num} (MATCH FOUND)")
        elif pkt_type == 0xd3:
            # RESULT (raw, no comparison)
            pkt_id = int.from_bytes(discarded[8:10], 'little') if len(discarded) >= 10 else 0
            print(f"  [drain] RESULT (0xd3): pkt_id=0x{pkt_id:04x}")
        else:
            print(f"  [drain] packet type 0x{pkt_type:02x}, {captured} bytes")
            print(f"          raw: {' '.join(f'{b:02x}' for b in discarded[:min(32, len(discarded))])}")

    print(f"  → drained {packets_drained} packet(s), {total_drained} bytes total (hit max)")
    return total_drained


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
    parser.add_argument("-r", "--reset", action="store_true",
                        help="Send reset packet before starting test (ensures clean FPGA state).")
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

    # Optional: send reset packet to ensure clean FPGA state
    if args.reset:
        send_reset(bus)

    # Drain any leftover packets from previous runs
    print("Draining output FIFO...")
    drain_output_fifo(bus)

    # Build packets.
    cmp_id, wl_id, wg_id = 0x0001, 0x0002, 0x0003
    iter_count = 2**int(iter)
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

    # Drain any remaining packets (e.g., PACKET_DONE after CMP_RESULT)
    print("Draining remaining packets...")
    drain_output_fifo(bus)

    bus.close()
    print("Test complete.")

if __name__ == "__main__":
    main()
