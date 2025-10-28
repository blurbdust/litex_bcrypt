#!/usr/bin/env python3
# test_bcrypt.py — works with simplified bcrypt_sim.py (no base/size/start CSRs)
from litex import RemoteClient

# -------------------------------------------------------------------------
# Packet helpers (unchanged)
# -------------------------------------------------------------------------
PKT_VERSION = 2
PKT_TYPE_WORD_LIST = 0x01
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

# -------------------------------------------------------------------------
# Wishbone helpers
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# NEW: Streamer / Recorder control (matches csr.csv)
# -------------------------------------------------------------------------
MEM_BASE = 0x40100000
REC_BASE = 0x40200000

def kick_streamer(bus, pkt_bytes, timeout=10_000_000):
    """Write packet at offset 0, then kick."""
    print(f"Writing {len(pkt_bytes)} bytes into SRAM @ 0x{MEM_BASE:08x}...")
    write_bytes(bus, MEM_BASE, pkt_bytes)

    bus.regs.streamer_length.write(len(pkt_bytes))  # ← NEW
    bus.regs.streamer_kick.write(0)
    bus.regs.streamer_kick.write(1)

    cnt = 0
    while not bus.regs.streamer_done.read():
        cnt += 1
        if cnt >= timeout:
            raise RuntimeError("streamer timeout")
    print("  → streamer done")

def start_recorder(bus):
    """Start capture once (captures all packets until last .last)"""
    print("Starting recorder (captures until last packet)...")
    bus.regs.recorder_kick.write(0)
    bus.regs.recorder_kick.write(1)

def wait_recorder(bus, timeout=10_000_000):
    cnt = 0
    while not bus.regs.recorder_done.read():
        cnt += 1
        if cnt >= timeout:
            raise RuntimeError("recorder timeout")
    cap_len = bus.regs.recorder_count.read()
    print(f"Recorder captured {cap_len} bytes.")
    return cap_len

# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------
def main():
    bus = RemoteClient()
    bus.open()

    # Build packets
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

    # Start recorder first
    start_recorder(bus)

    # Stream packets one by one
    print(pkt_cmp)
    kick_streamer(bus, pkt_cmp)
    print(pkt_wl)
    kick_streamer(bus, pkt_wl)
    print(pkt_wg)
    kick_streamer(bus, pkt_wg)

    # Wait and read capture
    cap_len = wait_recorder(bus)
    cap = read_bytes(bus, REC_BASE, cap_len)
    print("First 64 captured bytes:")
    print(" ".join(f"{b:02x}" for b in cap[:64]))

    # Optional: read bcrypt status
    try:
        app = bus.regs.bcrypt_app_status.read()
        pkt = bus.regs.bcrypt_pkt_comm_status.read()
        print(f"app_status=0x{app:02x} pkt_comm_status=0x{pkt:02x}")
    except Exception:
        pass

    bus.close()
    print("Test complete.")

if __name__ == "__main__":
    main()