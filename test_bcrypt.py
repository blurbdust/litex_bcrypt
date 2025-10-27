#!/usr/bin/env python3
# test_bcrypt.py — Send packets (with checksums) to Bcrypt Sim over Etherbone
# and capture AXI-M output with the recorder into SRAM.

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

# WB helpers (write/read) --------------------------------------------------------------------------

def write_bytes(bus, base, data_bytes):
    """Write byte array into a 32-bit WB region (little-endian), padding to 4."""
    buf = list(data_bytes)
    if len(buf) & 3:
        buf += [0] * (4 - (len(buf) & 3))
    for i in range(0, len(buf), 4):
        w = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16) | (buf[i+3] << 24)
        bus.write(base + i, w)

def read_bytes(bus, base, length):
    """Read byte array from a 32-bit WB region."""
    data = bytearray()
    words = (length + 3)//4
    for i in range(words):
        w = bus.read(base + 4*i)
        data.extend([w & 0xFF, (w>>8)&0xFF, (w>>16)&0xFF, (w>>24)&0xFF])
    return bytes(data[:length])

# Streamer control ---------------------------------------------------------------------------------

def kick_stream(bus, base, size, busy_timeout=10_000_000):
    """Program (base,size), issue a 0->1 start edge, poll busy->0, then read 'done'."""
    bus.regs.streamer_base.write(base)
    bus.regs.streamer_size.write(size)
    bus.regs.streamer_start.write(0)     # clean edge
    bus.regs.streamer_start.write(1)     # start
    cnt = 0
    while bus.regs.streamer_busy.read():
        cnt += 1
        if cnt >= busy_timeout:
            raise RuntimeError("streamer busy timeout")
    _ = bus.regs.streamer_done.read()    # observe/clear pulse

# Recorder control ---------------------------------------------------------------------------------

def arm_recorder(bus, base, max_bytes, stop_on_last=True):
    bus.regs.rec_base.write(base)
    bus.regs.rec_size.write(max_bytes)
    bus.regs.rec_stop_on_last.write(1 if stop_on_last else 0)
    bus.regs.rec_start.write(0)
    bus.regs.rec_start.write(1)

def wait_recorder_done(bus, busy_timeout=10_000_000):
    cnt = 0
    while bus.regs.rec_busy.read():
        cnt += 1
        if cnt >= busy_timeout:
            raise RuntimeError("recorder busy timeout")
    _ = bus.regs.rec_done.read()
    return bus.regs.rec_count.read()

# Main ---------------------------------------------------------------------------------------------

def main():
    bus = RemoteClient()
    bus.open()

    # Regions from sim.
    MEM_BASE = 0x4010_0000  # streamer input SRAM (WB)
    REC_BASE = 0x4020_0000  # recorder output SRAM (WB)

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

    # Layout (contiguous in input SRAM).
    off_cmp = 0
    len_cmp = len(pkt_cmp)
    off_wl  = off_cmp + len_cmp
    len_wl  = len(pkt_wl)
    off_wg  = off_wl  + len_wl
    len_wg  = len(pkt_wg)

    all_bytes = pkt_cmp + pkt_wl + pkt_wg

    # Write input SRAM.
    print(f"Writing {len(all_bytes)} bytes into SRAM @ 0x{MEM_BASE:08x}...")
    write_bytes(bus, MEM_BASE, all_bytes)

    # Arm recorder BEFORE sending input (capture from first byte).
    REC_LIMIT = 4096
    arm_recorder(bus, base=REC_BASE, max_bytes=REC_LIMIT, stop_on_last=True)

    # Send 3 packets via streamer.
    print("Sending CMP_CONFIG...")
    kick_stream(bus, MEM_BASE + off_cmp, len_cmp)

    print("Sending WORD_LIST...")
    kick_stream(bus, MEM_BASE + off_wl,  len_wl)

    print("Sending WORD_GEN...")
    kick_stream(bus, MEM_BASE + off_wg,  len_wg)

    # Wait for recorder to finish; read back capture.
    cap_len = wait_recorder_done(bus)
    print(f"Recorder captured {cap_len} bytes.")
    cap = read_bytes(bus, REC_BASE, cap_len)
    print("AXI-M capture (first 64 bytes):",
          " ".join(f"{b:02x}" for b in cap[:64]))

    # Optional: read wrapper status CSRs (if exposed).
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
