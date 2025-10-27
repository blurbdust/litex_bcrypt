#!/usr/bin/env python3
# test_bcrypt.py — Send packets (with checksums) to Bcrypt Sim over Etherbone.

from litex import RemoteClient

# Packet types / version ---------------------------------------------------------------------------

PKT_VERSION = 2
PKT_TYPE_WORD_LIST   = 0x01
PKT_TYPE_WORD_GEN    = 0x02
PKT_TYPE_CMP_CONFIG  = 0x03

# Helpers ------------------------------------------------------------------------------------------

def le16(x):  return [x & 0xFF, (x >> 8) & 0xFF]
def le24(x):  return [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF]
def le32(x):  return [(x >> (8*i)) & 0xFF for i in range(4)]

def build_header(pkt_type, pkt_id, payload_len, version=PKT_VERSION):
    # [ver][type][res0(lo)][res0(hi)][len0][len1][len2][res1][id0][id1]
    return [version, pkt_type, 0x00, 0x00, *le24(payload_len), 0x00, *le16(pkt_id)]

def _csum32_le(bs):
    """32-bit little-endian sum over 32-bit LE words (pad to 4), then XOR with 0xFFFFFFFF."""
    s = 0
    for i in range(0, len(bs), 4):
        w = bs[i:i+4] + [0]*(4 - (len(bs[i:i+4]) % 4))
        s = (s + (w[0] | (w[1] << 8) | (w[2] << 16) | (w[3] << 24))) & 0xFFFFFFFF
    s ^= 0xFFFFFFFF
    return [s & 0xFF, (s >> 8) & 0xFF, (s >> 16) & 0xFF, (s >> 24) & 0xFF]

def add_checksums_around_payload(header_bytes, payload_bytes):
    """Emit: header, csum(header), payload, csum(payload)."""
    return header_bytes + _csum32_le(header_bytes) + payload_bytes + _csum32_le(payload_bytes)

def build_cmp_config_payload_bcrypt(iter_count, salt16_bytes, subtype=b"b", hashes=None):
    assert isinstance(salt16_bytes, (bytes, bytearray)) and len(salt16_bytes) == 16
    assert subtype in (b"a", b"b", b"x", b"y")
    hashes = hashes or []
    p  = list(salt16_bytes)
    p += [subtype[0]]
    p += le32(iter_count)
    p += le16(len(hashes))
    for w in hashes:
        p += le32(w & 0x7FFFFFFF)
    p += [0xCC]  # magic
    return p

def build_word_list_payload(words):
    p = []
    for w in words:
        p += [ord(c) for c in w] + [0x00]  # NUL-terminated
    return p

def build_word_gen_payload():
    # num_ranges=0, num_generate=1 (LE32), magic=0xBB
    return [0x00, 0x01, 0x00, 0x00, 0x00, 0xBB]

# WB helpers ---------------------------------------------------------------------------------------

def write_bytes(bus, base, data_bytes):
    """Write byte array into a 32-bit WB region (little-endian), padding to 4."""
    buf = list(data_bytes)
    if len(buf) & 3:
        buf += [0] * (4 - (len(buf) & 3))
    for i in range(0, len(buf), 4):
        w = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
        bus.write(base + i, w)

def kick_stream(bus, base, size, busy_timeout=10_000_000):
    """Program (base,size), issue a 0->1 start edge, poll busy->0, then read 'done'."""
    bus.regs.streamer_base.write(base)
    bus.regs.streamer_size.write(size)
    bus.regs.streamer_start.write(0)     # ensure clean edge
    bus.regs.streamer_start.write(1)     # start

    # Poll busy with a simple timeout guard (prevents infinite loop if miswired)
    cnt = 0
    while bus.regs.streamer_busy.read():
        cnt += 1
        if cnt >= busy_timeout:
            raise RuntimeError("streamer busy timeout")

    _ = bus.regs.streamer_done.read()    # observe/clear pulse

# Main ---------------------------------------------------------------------------------------------

def main():
    bus = RemoteClient()
    bus.open()

    MEM_BASE = 0x4010_0000

    # Build packets (WITH checksums).
    cmp_id, wl_id, wg_id = 0x0001, 0x0002, 0x0003
    iter_count = 5
    salt16     = bytes(range(0x10))
    hashes     = [0]

    cmp_pl   = build_cmp_config_payload_bcrypt(iter_count, salt16, b"b", hashes)
    cmp_hdr  = build_header(PKT_TYPE_CMP_CONFIG, cmp_id, len(cmp_pl))
    pkt_cmp  = add_checksums_around_payload(cmp_hdr, cmp_pl)

    wl_pl    = build_word_list_payload(["pass"])
    wl_hdr   = build_header(PKT_TYPE_WORD_LIST, wl_id, len(wl_pl))
    pkt_wl   = add_checksums_around_payload(wl_hdr, wl_pl)

    wg_pl    = build_word_gen_payload()
    wg_hdr   = build_header(PKT_TYPE_WORD_GEN, wg_id, len(wg_pl))
    pkt_wg   = add_checksums_around_payload(wg_hdr, wg_pl)

    # Layout (contiguous in SRAM).
    off_cmp = 0
    len_cmp = len(pkt_cmp)
    off_wl  = off_cmp + len_cmp
    len_wl  = len(pkt_wl)
    off_wg  = off_wl  + len_wl
    len_wg  = len(pkt_wg)

    all_bytes = pkt_cmp + pkt_wl + pkt_wg

    # Write + kick.
    print(f"Writing {len(all_bytes)} bytes into SRAM @ 0x{MEM_BASE:08x}...")
    write_bytes(bus, MEM_BASE, all_bytes)

    print("Sending CMP_CONFIG...")
    kick_stream(bus, MEM_BASE + off_cmp, len_cmp)

    print("Sending WORD_LIST...")
    kick_stream(bus, MEM_BASE + off_wl,  len_wl)

    print("Sending WORD_GEN...")
    kick_stream(bus, MEM_BASE + off_wg,  len_wg)

    # (Optional) read wrapper status if exposed as CSRs.
    try:
        app  = bus.regs.bcrypt_app_status.read()
        pkt  = bus.regs.bcrypt_pkt_comm_status.read()
        print(f"app_status=0x{app:02x}  pkt_comm_status=0x{pkt:02x}")
    except Exception:
        pass

    print("Done.")
    bus.close()

if __name__ == "__main__":
    main()
