#!/usr/bin/env python3

# bcrypt_sim.py — Bcrypt Sim
# Bcrypt core wrapped in LiteX.
#
# High-level:
# - Streams three packets into the wrapper: CMP_CONFIG → WORD_LIST → WORD_GEN.
# - AXI egress is always-ready (no RX collector).
# - Compact helpers, clean wiring, simple sequencer.

import argparse

from migen import *
from litex.gen import *

from litex.build.generic_platform import *
from litex.build.sim              import SimPlatform
from litex.build.sim.config       import SimConfig
from litex.build.sim.verilator    import verilator_build_args, verilator_build_argdict

from litex.soc.integration.soc_core import SoCMini
from litex.soc.integration.builder  import Builder
from litex.soc.interconnect         import stream

# IOs ----------------------------------------------------------------------------------------------

_io = [
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),
]

# Platform -----------------------------------------------------------------------------------------

class Platform(SimPlatform):
    def __init__(self):
        SimPlatform.__init__(self, "SIM", _io)

# Packet helpers -----------------------------------------------------------------------------------

PKT_VERSION = 2
PKT_TYPE_WORD_LIST   = 0x01
PKT_TYPE_WORD_GEN    = 0x02
PKT_TYPE_CMP_CONFIG  = 0x03

def le16(x):  return [x & 0xFF, (x >> 8) & 0xFF]
def le24(x):  return [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF]
def le32(x):  return [(x >> (8*i)) & 0xFF for i in range(4)]

def build_header(pkt_type, pkt_id, payload_len, version=PKT_VERSION):
    # [ver][type][res0(lo)][res0(hi)][len0][len1][len2][res1][id0][id1]
    return [version, pkt_type, 0x00, 0x00, *le24(payload_len), 0x00, *le16(pkt_id)]

def _csum32_le(bs):
    s = 0
    for i in range(0, len(bs), 4):
        w = bs[i:i+4] + [0]*(4 - (len(bs[i:i+4])%4))
        s = (s + (w[0] | (w[1]<<8) | (w[2]<<16) | (w[3]<<24))) & 0xFFFFFFFF
    s ^= 0xFFFFFFFF
    return [s & 0xFF, (s>>8)&0xFF, (s>>16)&0xFF, (s>>24)&0xFF]

def add_checksums_around_payload(header_bytes, payload_bytes):
    return header_bytes + _csum32_le(header_bytes) + payload_bytes + _csum32_le(payload_bytes)

def build_cmp_config_payload_bcrypt(iter_count, salt16_bytes, subtype=b"b", hashes=None):
    assert len(salt16_bytes) == 16
    hashes = hashes or []
    p  = list(salt16_bytes)
    p += [subtype[0]]
    p += le32(iter_count)
    p += le16(len(hashes))
    for w in hashes: p += le32(w & 0x7FFFFFFF)
    p += [0xCC]  # magic
    return p

def build_word_list_payload(words):
    p = []
    for w in words: p += [ord(c) for c in w] + [0x00]
    return p

def build_word_gen_payload():
    # num_ranges=0, num_generate=1, magic=0xBB
    return [0x00, 0x01, 0x00, 0x00, 0x00, 0xBB]

# Simple AXIS8 byte streamer -----------------------------------------------------------------------

class ByteStreamer(LiteXModule):
    """Stream a byte list once per start pulse."""
    def __init__(self, data):
        self.source = stream.Endpoint([("data", 8)])
        self.start  = Signal(reset=0)
        self.done   = Signal(reset=0)

        n       = len(data)
        mem     = Array([Signal(8, reset=d) for d in data])
        idx     = Signal(max=n+1)
        running = Signal(reset=0)
        start_d = Signal()
        start_p = Signal()

        self.comb += [
            self.source.data.eq(mem[idx]),
            self.source.last.eq(idx == (n-1)),
            start_p.eq(self.start & ~start_d),
        ]

        self.sync += [
            start_d.eq(self.start),
            self.done.eq(0),

            If(start_p & ~running,
                running.eq(1), idx.eq(0)
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

# Simulation SoC -----------------------------------------------------------------------------------

class SimSoC(SoCMini):
    def __init__(self):
        platform     = Platform()
        self.comb += platform.trace.eq(1)
        sys_clk_freq = int(50e6)

        SoCMini.__init__(self, platform, sys_clk_freq)

        self.crg = CRG(platform.request("sys_clk"))

        from gateware.bcrypt_wrapper import BcryptWrapper
        self.bcrypt = bcrypt = BcryptWrapper(self.platform,
            num_proxies     = 2,
            proxies_n_cores = [4, 4],
            proxies_dummy   = [0, 0],
            proxies_bitmap  = [0, 0],
        )
        self.platform.add_source("gateware/bcrypt_axis_8b.sv")
        self.bcrypt.add_sources()

        # Packets ---------------------------------------------------------------------------------
        cmp_id, wl_id, wg_id = 0x0001, 0x0002, 0x0003
        iter_count = 5
        salt16     = bytes(range(0x10))
        hashes     = [0]

        cmp_pl  = build_cmp_config_payload_bcrypt(iter_count, salt16, b"b", hashes)
        pkt_cmp = add_checksums_around_payload(build_header(PKT_TYPE_CMP_CONFIG, cmp_id, len(cmp_pl)), cmp_pl)

        wl_pl   = build_word_list_payload(["pass"])
        pkt_wl  = add_checksums_around_payload(build_header(PKT_TYPE_WORD_LIST, wl_id, len(wl_pl)), wl_pl)

        wg_pl   = build_word_gen_payload()
        pkt_wg  = add_checksums_around_payload(build_header(PKT_TYPE_WORD_GEN, wg_id, len(wg_pl)), wg_pl)

        # Preview (optional)
        def dump(lbl, bb, n=32):
            print(lbl, "len=", len(bb))
            print(" ".join(f"{b:02x}" for b in bb[:n]))
        dump("PKT_CMP", pkt_cmp); dump("PKT_WL ", pkt_wl); dump("PKT_WG ", pkt_wg)

        # Streamers ------------------------------------------------------------------------------
        self.tx_cmp = tx_cmp = ByteStreamer(pkt_cmp)
        self.tx_wl  = tx_wl  = ByteStreamer(pkt_wl)
        self.tx_wg  = tx_wg  = ByteStreamer(pkt_wg)

        # AXIS wiring — IN to wrapper; OUT kept ready=1 ------------------------------------------
        self.comb += [
            # IN
            bcrypt.sink.valid.eq(tx_cmp.source.valid | tx_wl.source.valid | tx_wg.source.valid),
            bcrypt.sink.data .eq(
                Mux(tx_cmp.source.valid, tx_cmp.source.data,
                Mux(tx_wl .source.valid, tx_wl .source.data, tx_wg.source.data))
            ),
            bcrypt.sink.last .eq(
                Mux(tx_cmp.source.valid, tx_cmp.source.last,
                Mux(tx_wl .source.valid, tx_wl .source.last, tx_wg.source.last))
            ),
            tx_cmp.source.ready.eq(bcrypt.sink.ready & tx_cmp.source.valid),
            tx_wl .source.ready.eq(bcrypt.sink.ready & ~tx_cmp.source.valid & tx_wl.source.valid),
            tx_wg .source.ready.eq(bcrypt.sink.ready & ~tx_cmp.source.valid & ~tx_wl.source.valid & tx_wg.source.valid),

            # OUT (tie ready high; no collector)
            bcrypt.source.ready.eq(1),
        ]

        # AXIS In Sequencer ------------------------------------------------------------------------
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
            If(tx_wg.done, NextState("DONE"))
        )
        fsm.act("DONE")

        # AXIS Out Display -------------------------------------------------------------------------
        out_byte_idx = Signal(8)
        self.sync += [
            If(bcrypt.source.valid & bcrypt.source.ready,
                Display("AXIS.OUT byte=0x%02x last=%d", bcrypt.source.data, bcrypt.source.last),
                If(bcrypt.source.last,
                    Display("AXIS.OUT <END>")
                ),
                out_byte_idx.eq(out_byte_idx + 1)
            )
        ]

# Build / Main -------------------------------------------------------------------------------------

def sim_args(parser):
    verilator_build_args(parser)

def main():
    parser = argparse.ArgumentParser(description="Bcrypt Sim — Bcrypt core wrapped in LiteX (AXIS8).")
    sim_args(parser)
    args = parser.parse_args()
    verilator_kwargs = verilator_build_argdict(args)

    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(25e6))

    soc = SimSoC()
    builder = Builder(soc, csr_csv="csr.csv", compile_software=False)
    builder.build(sim_config=sim_config, **verilator_kwargs)

if __name__ == "__main__":
    main()
