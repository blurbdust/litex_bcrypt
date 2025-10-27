#!/usr/bin/env python3

# SPDX-License-Identifier: BSD-2-Clause
#
# sim_axis8_packets.py — Packet-level LiteX/Migen simulation for BcryptCoreAXIS8.
#
# This drives the 8-bit AXI-Stream IN with three "high-level" packets:
#   1) CMP_CONFIG (type=0x03): iter_count + salt + cmp_data[5]
#   2) WORD_LIST  (type=0x01): a single word "pass\0"
#   3) WORD_GEN   (type=0x02): minimal config to consume 1 word from WORD_LIST
#
# Notes
# -----
# * Header format assumed (adjust to match your repo's `inpkt_header`):
#     [ver:8][type:8][id:16-LE][len:16-LE] [payload...]
#   With SIMULATION=1 on the wrapper, checksum is disabled.
# * Payload encodings for cmp_config/word_list/word_gen may need tweaks to your exact RTL.
#   The structure below follows the comments in bcrypt_data.v and typical repo defaults.
#
import argparse
from migen import *
from litex.gen import *
from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator import verilator_build_args, verilator_build_argdict
from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder import Builder
from litex.soc.interconnect import stream
from litex.gen import LiteXModule

WRAPPER_SV = "bcrypt_axis8_wrap.sv"
LITEX_MOD  = "litex_bcrypt_axis8.py"

PKT_VERSION = 2  # Adjust to match `PKT_COMM_VERSION` in your repo
PKT_TYPE_WORD_LIST   = 0x01
PKT_TYPE_WORD_GEN    = 0x02
PKT_TYPE_CMP_CONFIG  = 0x03

def le16(x):  return [x & 0xFF, (x >> 8) & 0xFF]
def le24(x):  return [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF]
def le32(x):  return [(x >> (8*i)) & 0xFF for i in range(4)]

# RTL header: 10 bytes total
# [ver][type][res0(lo)][res0(hi)][len0][len1][len2][res1][id0][id1]
def build_header(pkt_type, pkt_id, payload_len, version=PKT_VERSION):
    hdr  = []
    hdr += [version, pkt_type]
    hdr += [0x00, 0x00]              # reserved0
    hdr += le24(payload_len)         # 3-byte length (LE)
    hdr += [0x00]                    # reserved1
    hdr += le16(pkt_id)
    return hdr

# Even with DISABLE_CHECKSUM=1 the FSM still consumes a 32-bit checksum
# right after the header and another 32-bit checksum after the payload.
def add_checksums_around_payload(header, payload):
    chk = [0x00, 0x00, 0x00, 0x00]   # dummy checksum words
    return header + chk + payload + chk

def build_cmp_config_payload_bcrypt(iter_count, salt16_bytes, subtype=b"b", hashes=None):
    assert isinstance(salt16_bytes, (bytes, bytearray)) and len(salt16_bytes) == 16
    assert subtype in (b"a", b"b", b"x", b"y")
    if hashes is None:
        hashes = []

    payload  = list(salt16_bytes)          # 16 bytes salt
    payload += [subtype[0]]                # 1 byte subtype
    payload += le32(iter_count)            # 4 bytes LE
    payload += le16(len(hashes))           # 2 bytes LE
    for w in hashes:
        payload += le32(w & 0x7FFFFFFF)    # 4 bytes each (LE)
    payload += [0xCC]                      # magic
    return payload

def add_checksums_around_payload(header_bytes, payload_bytes):
    # 32-bit little-endian sum of 32-bit little-endian words (pad with zeros)
    def csum(bs):
        s = 0
        for i in range(0, len(bs), 4):
            w = bs[i:i+4] + [0]*(4 - (len(bs[i:i+4])%4))
            s = (s + (w[0] | (w[1]<<8) | (w[2]<<16) | (w[3]<<24))) & 0xFFFFFFFF
        s ^= 0xFFFFFFFF
        return [s & 0xFF, (s>>8)&0xFF, (s>>16)&0xFF, (s>>24)&0xFF]

    return header_bytes + csum(header_bytes) + payload_bytes + csum(payload_bytes)

def build_word_list_payload(words):
    p = []
    for w in words:
        p += [ord(c) for c in w] + [0x00]  # NUL-terminated entries
    return p

def build_word_gen_payload():
    # num_ranges = 0x00
    # num_generate = 1 (LE 32-bit)
    # magic = 0xBB
    return [0x00, 0x01, 0x00, 0x00, 0x00, 0xBB]

class ByteStreamer(LiteXModule):
    def __init__(self, data):
        self.source = stream.Endpoint([('data', 8)])
        self.start  = Signal(reset=0)   # external “request”
        self.done   = Signal(reset=0)

        n = len(data)
        mem = Array([Signal(8, reset=d) for d in data])
        idx = Signal(max=n+1)
        running   = Signal(reset=0)
        start_d   = Signal()            # registered start
        start_p   = Signal()            # 1-cycle pulse on rising edge

        # present data/last
        self.comb += [
            self.source.data.eq(mem[idx]),
            self.source.last.eq(idx == (n-1)),
            start_p.eq(self.start & ~start_d),
        ]

        self.sync += [
            start_d.eq(self.start),
            self.done.eq(0),

            If(start_p & ~running,         # only react to rising edge
                running.eq(1),
                idx.eq(0)
            ).Elif(running,
                self.source.valid.eq(1),
                If(self.source.valid & self.source.ready,
                    If(idx == (n-1),
                        self.source.valid.eq(0),
                        self.done.eq(1),
                        running.eq(0)
                    ).Else(
                        idx.eq(idx + 1)
                    )
                )
            ).Else(
                self.source.valid.eq(0)
            )
        ]


class WordCollector(LiteXModule):
    def __init__(self, nwords=8):
        self.sink  = stream.Endpoint([('data', 8)])
        self.done  = Signal()
        self.words = [Signal(32) for _ in range(nwords)]

        cur = Signal(32)
        byte_pos = Signal(2)   # 0..3
        idx = Signal(max=nwords)
        capturing = Signal(reset=1)

        self.sync += [
            self.done.eq(0),
            If(capturing,
                If(self.sink.valid & self.sink.ready,
                    cur.eq(cur | (self.sink.data << (8*byte_pos))),
                    byte_pos.eq(byte_pos + 1),
                    If(byte_pos == 3,
                        Case(idx, {i: self.words[i].eq(cur | (self.sink.data << 24)) for i in range(nwords)}),
                        idx.eq(idx + 1),
                        byte_pos.eq(0),
                        cur.eq(0),
                        If(idx == (nwords - 1),
                            capturing.eq(0),
                            self.done.eq(1)
                        )
                    )
                )
            )
        ]
        self.comb += self.sink.ready.eq(1)

_io = [("sys_clk", 0, Pins(1)), ("sys_rst", 0, Pins(1))]

class Platform(SimPlatform):
    def __init__(self): SimPlatform.__init__(self, "SIM", _io)

class SimSoC(SoCMini):
    def __init__(self):
        platform     = Platform()
        self.comb += platform.trace.eq(1)
        sys_clk_freq = int(50e6)
        SoCMini.__init__(self, platform, sys_clk_freq)
        self.crg = CRG(platform.request("sys_clk"))

        # Import integration
        import importlib.util, sys as _sys
        spec = importlib.util.spec_from_file_location("litex_bcrypt_axis8", LITEX_MOD)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _sys.modules["litex_bcrypt_axis8"] = mod
        BcryptCoreAXIS8 = mod.BcryptCoreAXIS8

        self.platform.add_source(WRAPPER_SV)
        # Force SIMULATION=1 by defining the parameter at instantiation
        self.bcrypt = bcrypt = BcryptCoreAXIS8(self.platform,
            num_proxies     = 2,
            proxies_n_cores = [4,4],     # 4 real cores per proxy
            proxies_dummy   = [0,0],
            proxies_bitmap  = [0,0]
        )
        self.bcrypt.add_sources()

        # ---------------- Packets ----------------
        cmp_id  = 0x0001
        wl_id   = 0x0002
        wg_id   = 0x0003

        iter_count = 5
        salt16     = bytes(range(0x10))
        hashes     = [0]  # at least one

        cmp_pl  = build_cmp_config_payload_bcrypt(iter_count, salt16, subtype=b"b", hashes=[0])
        cmp_hdr = build_header(PKT_TYPE_CMP_CONFIG, 0x0001, len(cmp_pl))
        pkt_cmp = add_checksums_around_payload(cmp_hdr, cmp_pl)

        wl_pl   = build_word_list_payload(["pass"])
        wl_hdr  = build_header(PKT_TYPE_WORD_LIST, 0x0002, len(wl_pl))
        pkt_wl  = add_checksums_around_payload(wl_hdr, wl_pl)

        wg_pl   = build_word_gen_payload()
        wg_hdr  = build_header(PKT_TYPE_WORD_GEN, 0x0003, len(wg_pl))
        pkt_wg  = add_checksums_around_payload(wg_hdr, wg_pl)

        # (Optional) quick dumps
        def dump_bytes(lbl, bb, n=64):
            print(lbl, "len=", len(bb))
            print(" ".join(f"{b:02x}" for b in bb[:n]))
        dump_bytes("PKT_CMP", pkt_cmp)
        dump_bytes("PKT_WL ", pkt_wl)
        dump_bytes("PKT_WG ", pkt_wg)

        #exit()

        # Streamers + collector
        self.tx_cmp = tx_cmp = ByteStreamer(pkt_cmp)
        self.tx_wl  = tx_wl  = ByteStreamer(pkt_wl)
        self.tx_wg  = tx_wg  = ByteStreamer(pkt_wg)
        self.rx     = rx     = WordCollector(nwords=8)

        # CSRs: mode_cmp=1
        #self.comb += bcrypt._ctrl.storage.eq(0b001)

        # AXIS connections
        self.comb += [
            bcrypt.sink.valid.eq(tx_cmp.source.valid | tx_wl.source.valid | tx_wg.source.valid),
            bcrypt.sink.data.eq(
                Mux(tx_cmp.source.valid, tx_cmp.source.data,
                Mux(tx_wl .source.valid, tx_wl .source.data, tx_wg.source.data))
            ),
            bcrypt.sink.last.eq(
                Mux(tx_cmp.source.valid, tx_cmp.source.last,
                Mux(tx_wl .source.valid, tx_wl .source.last, tx_wg.source.last))
            ),
            tx_cmp.source.ready.eq(bcrypt.sink.ready & tx_cmp.source.valid),
            tx_wl .source.ready.eq(bcrypt.sink.ready & ~tx_cmp.source.valid & tx_wl.source.valid),
            tx_wg .source.ready.eq(bcrypt.sink.ready & ~tx_cmp.source.valid & ~tx_wl.source.valid & tx_wg.source.valid),

            rx.sink.valid.eq(bcrypt.source.valid),
            rx.sink.data .eq(bcrypt.source.data),
            rx.sink.last .eq(bcrypt.source.last),
            bcrypt.source.ready.eq(1),
        ]

        # Sequencer
        self.fsm = fsm = FSM(reset_state="SEND_CMP")
        fsm.act("SEND_CMP",
            tx_cmp.start.eq(1),
            If(tx_cmp.done, NextState("SEND_WL"))
        )
        fsm.act("SEND_WL",
            tx_wl.start.eq(1),
            If(tx_wl.done, NextState("SEND_WG"))
        )
        fsm.act("SEND_WG",
            tx_wg.start.eq(1),
            If(tx_wg.done, NextState("WAIT_RX"))
        )
        fsm.act("WAIT_RX",
            If(rx.done, NextState("DONE"))
        )
        fsm.act("DONE")

def main():
    parser = argparse.ArgumentParser()
    verilator_build_args(parser)
    args = parser.parse_args()
    build_kwargs = verilator_build_argdict(args)

    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(25e6))

    soc = SimSoC()
    builder = Builder(soc, csr_csv="csr.csv", compile_software=False)
    builder.build(sim_config=sim_config, **build_kwargs)

if __name__ == "__main__":
    main()
